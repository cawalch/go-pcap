//go:build linux

package pcap

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const LinkTypeUnknown LinkType = 0xffff

const (
	packetAuxdata     = 8  // PACKET_AUXDATA is absent from syscall on linux/386.
	packetAuxdataSize = 20 // sizeof(struct tpacket_auxdata)
	soTimestampNSNew  = 64 // SO_TIMESTAMPNS_NEW from asm-generic/socket.h.
)

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

	// A zero protocol starts reception only after Bind, with timestamps enabled.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := enableLinuxReceiveTimestamp(fd); err != nil {
		_ = syscall.Close(fd)
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

	controlSize := syscall.CmsgSpace(16) // Two 64-bit fields in the time64 ABI.
	if len(normOpts.BPFFilter) > 0 {
		// A filter can shorten the packet before recvmsg sees it. AUXDATA
		// supplies the length recorded before filtering in tpacket_auxdata.
		if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetAuxdata, 1); err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("PACKET_AUXDATA: %w", err)
		}
		controlSize += syscall.CmsgSpace(packetAuxdataSize)
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
		oob:       make([]byte, controlSize),
	}, nil
}

func enableLinuxReceiveTimestamp(fd int) error {
	// Request the time64 ABI even on 32-bit systems to avoid 2038 rollover.
	for _, option := range [...]int{soTimestampNSNew, syscall.SO_TIMESTAMPNS} {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, option, 1)
		switch err {
		case nil:
			return nil
		case syscall.ENOPROTOOPT, syscall.EOPNOTSUPP:
			continue
		default:
			return fmt.Errorf("setsockopt receive timestamp (option %d): %w", option, err)
		}
	}
	return nil
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

// ReadPacket reads the next live packet from the AF_PACKET socket. It uses the
// kernel software receive timestamp when available and the wall clock at read
// time when the kernel supplies no usable timestamp.
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
	var timestampNs int64
	var hasTimestamp bool
	if controlLen > 0 {
		messages, err := syscall.ParseSocketControlMessage(lc.oob[:controlLen])
		if err != nil {
			return PacketRecord{}, nil, err
		}
		for _, msg := range messages {
			switch {
			case msg.Header.Level == syscall.SOL_PACKET && msg.Header.Type == packetAuxdata && len(msg.Data) >= 8:
				wireLen = binary.NativeEndian.Uint32(msg.Data[4:8])
			case msg.Header.Level == syscall.SOL_SOCKET && (msg.Header.Type == soTimestampNSNew || msg.Header.Type == syscall.SCM_TIMESTAMPNS):
				timestampNs, hasTimestamp = linuxReceiveTimestamp(msg.Header.Type, msg.Data)
			}
		}
	}
	if !hasTimestamp {
		timestampNs = time.Now().UnixNano()
	}
	capLen := uint32(n)
	if capLen > lc.snapLen {
		capLen = lc.snapLen
	}
	rec := PacketRecord{
		Index:         lc.pktIndex,
		LinkType:      lc.linkType,
		TimestampNs:   timestampNs,
		CaptureLen:    capLen,
		OriginalLen:   wireLen,
		PayloadOffset: 0,
		PayloadLength: int64(capLen),
	}
	lc.pktIndex++
	return rec, lc.buf[:capLen], nil
}

func linuxReceiveTimestamp(kind int32, data []byte) (int64, bool) {
	const nanosPerSecond = int64(time.Second)
	var sec, nsec int64
	switch {
	case (kind == soTimestampNSNew || strconv.IntSize == 64) && len(data) == 16:
		sec = int64(binary.NativeEndian.Uint64(data[:8]))
		nsec = int64(binary.NativeEndian.Uint64(data[8:16]))
	case kind == syscall.SCM_TIMESTAMPNS && strconv.IntSize == 32 && len(data) == 8:
		sec = int64(int32(binary.NativeEndian.Uint32(data[:4])))
		nsec = int64(int32(binary.NativeEndian.Uint32(data[4:8])))
	default:
		return 0, false
	}
	if sec < 0 || nsec < 0 || nsec >= nanosPerSecond || sec > (math.MaxInt64-nsec)/nanosPerSecond {
		return 0, false
	}
	return sec*nanosPerSecond + nsec, true
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
