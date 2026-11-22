//go:build windows

package pcap

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	LinkTypeUnknown LinkType = 0xffff
	sioRcvAll       uint32   = 0x98000001
	rcvallOn        uint32   = 1
)

var procCancelIoEx = syscall.NewLazyDLL("kernel32.dll").NewProc("CancelIoEx")

// LiveCapture reads live IPv4 packets from a Windows network interface using
// standard-library raw sockets and SIO_RCVALL without Npcap or cgo.
type LiveCapture struct {
	mu        sync.Mutex
	fd        syscall.Handle
	closed    bool
	refs      int
	ifaceName string
	linkType  LinkType
	snapLen   uint32
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

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: bindIP}); err != nil {
		_ = syscall.Closesocket(fd)
		return nil, err
	}

	if normOpts.Promiscuous {
		inVal := rcvallOn
		var bytesRet uint32
		err := syscall.WSAIoctl(
			fd,
			sioRcvAll,
			(*byte)(unsafe.Pointer(&inVal)),
			uint32(unsafe.Sizeof(inVal)),
			nil,
			0,
			&bytesRet,
			nil,
			0,
		)
		if err != nil {
			_ = syscall.Closesocket(fd)
			return nil, fmt.Errorf("WSAIoctl SIO_RCVALL: %w", err)
		}
	}

	return &LiveCapture{
		fd:        fd,
		ifaceName: ifaceName,
		linkType:  LinkTypeIPv4,
		snapLen:   normOpts.SnapLen,
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

func (lc *LiveCapture) acquireFD() (syscall.Handle, bool) {
	if lc == nil {
		return syscall.InvalidHandle, false
	}
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.closed || lc.fd == syscall.InvalidHandle || lc.buf == nil {
		return syscall.InvalidHandle, false
	}
	lc.refs++
	return lc.fd, true
}

func (lc *LiveCapture) releaseFD() {
	lc.mu.Lock()
	lc.refs--
	var closeHandle syscall.Handle
	if lc.closed && lc.refs == 0 && lc.fd != syscall.InvalidHandle {
		closeHandle = lc.fd
		lc.fd = syscall.InvalidHandle
	}
	lc.mu.Unlock()
	if closeHandle != 0 {
		_ = syscall.Closesocket(closeHandle)
	}
}

func (lc *LiveCapture) isClosed() bool {
	lc.mu.Lock()
	closed := lc.closed
	lc.mu.Unlock()
	return closed
}

// ReadPacket reads the next live IPv4 packet from the Windows raw socket,
// evaluating any configured BPF filter in userspace via [EvalBPF].
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	fd, ok := lc.acquireFD()
	if !ok {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	defer lc.releaseFD()
	if len(lc.buf) == 0 {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	wsaBuf := syscall.WSABuf{
		Len: uint32(len(lc.buf)),
		Buf: &lc.buf[0],
	}
	for {
		if lc.isClosed() {
			return PacketRecord{}, nil, ErrInvalidHeader
		}
		var n, flags uint32
		if err := syscall.WSARecv(fd, &wsaBuf, 1, &n, &flags, nil, nil); err != nil {
			return PacketRecord{}, nil, err
		}
		if n == 0 {
			continue
		}
		pkt := lc.buf[:n]
		capLen := n
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
			OriginalLen:   n,
			PayloadOffset: 0,
			PayloadLength: int64(capLen),
		}
		lc.pktIndex++
		return rec, lc.buf[:capLen], nil
	}
}

// Close closes the underlying Windows raw socket handle and cancels any
// blocked ReadPacket call while keeping the handle valid across cancellation
// and active reads.
func (lc *LiveCapture) Close() error {
	if lc == nil {
		return nil
	}
	lc.mu.Lock()
	if lc.closed || lc.fd == syscall.InvalidHandle || lc.buf == nil {
		lc.mu.Unlock()
		return nil
	}
	lc.closed = true
	fd := lc.fd
	if lc.refs == 0 {
		lc.fd = syscall.InvalidHandle
		lc.mu.Unlock()
		return syscall.Closesocket(fd)
	}
	// Hold a reference across CancelIoEx so the last reader cannot close fd before cancellation runs.
	lc.refs++
	lc.mu.Unlock()
	_, _, _ = procCancelIoEx.Call(uintptr(fd), 0)
	lc.releaseFD()
	return nil
}

// Stats returns [ErrLiveCaptureUnsupported] because this backend lacks capture counters.
func (lc *LiveCapture) Stats() (LiveStats, error) {
	return LiveStats{}, ErrLiveCaptureUnsupported
}
