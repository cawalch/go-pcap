//go:build windows

package pcap

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	LinkTypeUnknown LinkType = 0xffff
	sioRcvAll       uint32   = 0x98000001
	rcvallOn        uint32   = 1
)

// LiveCapture reads live IPv4 packets from a Windows network interface using
// standard-library raw sockets and SIO_RCVALL without Npcap or cgo.
type LiveCapture struct {
	conn      net.Conn
	ifaceName string
	linkType  LinkType
	snapLen   uint32
	timeout   time.Duration
	filter    []BPFInstruction
	buf       []byte
	pktIndex  int
}

// OpenLive opens a live IPv4 packet capture handle on ifaceName using a Windows
// raw socket and SIO_RCVALL.
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
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var bindIP [4]byte
	foundIPv4 := false
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			copy(bindIP[:], ip4)
			foundIPv4 = true
			break
		}
	}
	if !foundIPv4 {
		return nil, fmt.Errorf("%w: interface %s has no IPv4 address for SIO_RCVALL", ErrInvalidHeader, ifaceName)
	}

	// Protocol zero is IPPROTO_IP, as required by SIO_RCVALL.
	conn, err := net.ListenIP("ip4:0", &net.IPAddr{IP: bindIP[:]})
	if err != nil {
		return nil, err
	}
	if normOpts.Promiscuous {
		raw, err := conn.SyscallConn()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		var ioctlErr error
		err = raw.Control(func(fd uintptr) {
			inVal := rcvallOn
			var bytesRet uint32
			ioctlErr = syscall.WSAIoctl(syscall.Handle(fd), sioRcvAll,
				(*byte)(unsafe.Pointer(&inVal)), uint32(unsafe.Sizeof(inVal)),
				nil, 0, &bytesRet, nil, 0)
		})
		if err != nil || ioctlErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("WSAIoctl SIO_RCVALL: %w", errors.Join(err, ioctlErr))
		}
	}
	return &LiveCapture{
		conn:      conn,
		ifaceName: ifaceName,
		linkType:  LinkTypeIPv4,
		snapLen:   normOpts.SnapLen,
		timeout:   normOpts.Timeout,
		filter:    normOpts.BPFFilter,
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

// LinkType returns the link-layer encapsulation type ([LinkTypeIPv4]).
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

// ReadPacket reads the next live IPv4 packet from the Windows raw socket,
// evaluating any configured BPF filter in userspace via [EvalBPF].
// It timestamps accepted packets with the wall clock at read time.
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	if lc == nil || lc.conn == nil {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	if lc.timeout > 0 {
		if err := lc.conn.SetReadDeadline(time.Now().Add(lc.timeout)); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return PacketRecord{}, nil, ErrInvalidHeader
			}
			return PacketRecord{}, nil, err
		}
	}
	for {
		// IPConn.Read preserves the IPv4 header and coordinates with Close.
		n, err := lc.conn.Read(lc.buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return PacketRecord{}, nil, ErrInvalidHeader
			}
			return PacketRecord{}, nil, err
		}
		if n == 0 {
			continue
		}
		pkt := lc.buf[:n]
		capLen := uint32(n)
		if len(lc.filter) > 0 {
			snap, ok := EvalBPF(lc.filter, pkt)
			if !ok || snap == 0 {
				continue
			}
			if snap < capLen {
				capLen = snap
			}
		}
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
}

// Close closes the underlying Windows raw socket and unblocks ReadPacket.
func (lc *LiveCapture) Close() error {
	if lc == nil || lc.conn == nil {
		return nil
	}
	err := lc.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Stats returns [ErrLiveCaptureUnsupported] because this backend lacks capture counters.
func (lc *LiveCapture) Stats() (LiveStats, error) {
	return LiveStats{}, ErrLiveCaptureUnsupported
}
