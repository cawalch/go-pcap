//go:build linux

package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const LinkTypeUnknown LinkType = 0xffff

// PACKET_AUXDATA from linux/if_packet.h is absent from syscall on linux/386.
const packetAuxdata = 8

// LiveCapture reads live packets from an OS network interface using standard
// library AF_PACKET syscalls on Linux.
type LiveCapture struct {
	statsMu   sync.Mutex // serializes Stats accumulation and closed state
	stats     LiveStats
	closed    bool
	file      *os.File
	ifaceName string
	linkType  LinkType
	snapLen   uint32
	timeout   time.Duration
	buf       []byte
	oob       []byte
	pktIndex  int
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

// OpenLive opens a live packet capture handle on ifaceName using an AF_PACKET
// raw socket and standard library syscalls without cgo or libpcap.
func OpenLive(ifaceName string, opts LiveOptions) (*LiveCapture, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("%w: empty interface name", ErrInvalidHeader)
	}
	normOpts, err := opts.normalize()
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	proto := int(htons(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	if normOpts.Promiscuous {
		// Linux packet_mreq contains the interface index, membership type,
		// address length, and eight address bytes in native byte order.
		var membership [16]byte
		binary.NativeEndian.PutUint32(membership[:4], uint32(iface.Index))
		binary.NativeEndian.PutUint16(membership[4:6], syscall.PACKET_MR_PROMISC)
		if err := syscall.SetsockoptString(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, string(membership[:])); err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("PACKET_ADD_MEMBERSHIP: %w", err)
		}
	}

	if normOpts.BufferSize > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, normOpts.BufferSize)
	}

	var oob []byte
	if len(normOpts.BPFFilter) > 0 {
		// A filter can shorten the packet before recvmsg sees it. AUXDATA
		// supplies the length recorded before filtering in tpacket_auxdata.
		if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetAuxdata, 1); err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("PACKET_AUXDATA: %w", err)
		}
		oob = make([]byte, syscall.CmsgSpace(20))
		insns := make([]syscall.SockFilter, len(normOpts.BPFFilter))
		for i, insn := range normOpts.BPFFilter {
			insns[i] = syscall.SockFilter{
				Code: insn.Code,
				Jt:   insn.JT,
				Jf:   insn.JF,
				K:    insn.K,
			}
		}
		fprog := syscall.SockFprog{
			Len:    uint16(len(insns)),
			Filter: &insns[0],
		}
		err := attachLinuxBPFFilter(fd, &fprog)
		runtime.KeepAlive(insns)
		if err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("setsockopt SO_ATTACH_FILTER: %w", err)
		}
	}

	return &LiveCapture{
		file:      os.NewFile(uintptr(fd), ifaceName),
		ifaceName: ifaceName,
		linkType:  LinkTypeEthernet,
		snapLen:   normOpts.SnapLen,
		timeout:   normOpts.Timeout,
		buf:       make([]byte, normOpts.SnapLen),
		oob:       oob,
	}, nil
}

// InterfaceName returns the bound network interface name.
func (lc *LiveCapture) InterfaceName() string {
	if lc == nil {
		return ""
	}
	return lc.ifaceName
}

// LinkType returns the link-layer encapsulation type reported by the interface.
func (lc *LiveCapture) LinkType() LinkType {
	if lc == nil {
		return LinkTypeUnknown
	}
	return lc.linkType
}

// SnapLen returns the configured snapshot length.
func (lc *LiveCapture) SnapLen() uint32 {
	if lc == nil {
		return 0
	}
	return lc.snapLen
}

// ReadPacket reads the next live packet from the AF_PACKET socket.
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	if lc == nil || lc.file == nil || len(lc.buf) == 0 {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	if lc.timeout > 0 {
		if err := lc.file.SetReadDeadline(time.Now().Add(lc.timeout)); err != nil {
			return PacketRecord{}, nil, err
		}
	}
	raw, err := lc.file.SyscallConn()
	if err != nil {
		return PacketRecord{}, nil, err
	}
	var n, controlLen int
	var recvErr error
	err = raw.Read(func(fd uintptr) bool {
		for {
			n, controlLen, _, _, recvErr = syscall.Recvmsg(int(fd), lc.buf, lc.oob, syscall.MSG_TRUNC)
			if recvErr != syscall.EINTR {
				return recvErr != syscall.EAGAIN
			}
		}
	})
	if err != nil {
		return PacketRecord{}, nil, err
	}
	if recvErr != nil {
		return PacketRecord{}, nil, recvErr
	}
	wireLen := uint32(n)
	if controlLen > 0 {
		messages, err := syscall.ParseSocketControlMessage(lc.oob[:controlLen])
		if err != nil {
			return PacketRecord{}, nil, err
		}
		for _, msg := range messages {
			if msg.Header.Level == syscall.SOL_PACKET && msg.Header.Type == packetAuxdata && len(msg.Data) >= 8 {
				wireLen = binary.NativeEndian.Uint32(msg.Data[4:8])
				break
			}
		}
	}
	capLen := uint32(n)
	if capLen > lc.snapLen {
		capLen = lc.snapLen
	}
	rec := PacketRecord{
		Index:         lc.pktIndex,
		LinkType:      lc.linkType,
		TimestampNs:   time.Now().UnixNano(),
		CaptureLen:    capLen,
		OriginalLen:   wireLen,
		PayloadOffset: 0,
		PayloadLength: int64(capLen),
	}
	lc.pktIndex++
	return rec, lc.buf[:capLen], nil
}

func (lc *LiveCapture) statsDelta(fd int) (LiveStats, error) {
	// PACKET_STATISTICS returns two native uint32 counters and resets them.
	var counters [2]uint32
	size := uint32(8)
	if errno := getPacketStatistics(fd, &counters, &size); errno != 0 {
		return LiveStats{}, errno
	}
	if size != 8 {
		return LiveStats{}, fmt.Errorf("PACKET_STATISTICS: unexpected size %d", size)
	}
	return LiveStats{PacketsReceived: uint64(counters[0]), PacketsDropped: uint64(counters[1])}, nil
}
