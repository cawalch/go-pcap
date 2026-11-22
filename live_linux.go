//go:build linux

package pcap

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const LinkTypeUnknown LinkType = 0xffff

// LiveCapture reads live packets from an OS network interface using standard
// library AF_PACKET syscalls on Linux.
type LiveCapture struct {
	fd        int
	ifaceName string
	linkType  LinkType
	snapLen   uint32
	buf       []byte
	pktIndex  int
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
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
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
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

	if normOpts.Timeout > 0 {
		tv := syscall.NsecToTimeval(normOpts.Timeout.Nanoseconds())
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	}

	if len(normOpts.BPFFilter) > 0 {
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
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			uintptr(syscall.SOL_SOCKET),
			uintptr(syscall.SO_ATTACH_FILTER),
			uintptr(unsafe.Pointer(&fprog)),
			unsafe.Sizeof(fprog),
			0,
		)
		if errno != 0 {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("setsockopt SO_ATTACH_FILTER: %w", errno)
		}
	}

	return &LiveCapture{
		fd:        fd,
		ifaceName: ifaceName,
		linkType:  LinkTypeEthernet,
		snapLen:   normOpts.SnapLen,
		buf:       make([]byte, normOpts.SnapLen),
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
	if lc == nil || lc.fd < 0 {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	n, _, err := syscall.Recvfrom(lc.fd, lc.buf, 0)
	if err != nil {
		return PacketRecord{}, nil, err
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
		OriginalLen:   uint32(n),
		PayloadOffset: 0,
		PayloadLength: int64(capLen),
	}
	lc.pktIndex++
	return rec, lc.buf[:capLen], nil
}

// Close closes the underlying AF_PACKET socket descriptor.
func (lc *LiveCapture) Close() error {
	if lc == nil || lc.fd < 0 {
		return nil
	}
	fd := lc.fd
	lc.fd = -1
	return syscall.Close(fd)
}
