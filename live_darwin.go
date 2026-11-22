//go:build darwin

package pcap

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// LiveCapture reads live packets from an OS network interface using standard
// library syscalls (/dev/bpf* on macOS).
type LiveCapture struct {
	statsMu   sync.Mutex // serializes Stats and Close
	stats     LiveStats
	fd        int
	ifaceName string
	linkType  LinkType
	snapLen   uint32
	buf       []byte
	queued    []PacketRecord
	queueIdx  int
	pktIndex  int
}

type bpfIfreq struct {
	Name [syscall.IFNAMSIZ]byte
	Pad  [16]byte
}

// OpenLive opens a live packet capture handle on ifaceName using /dev/bpf* and
// standard library syscalls without cgo or libpcap.
func OpenLive(ifaceName string, opts LiveOptions) (*LiveCapture, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("%w: empty interface name", ErrInvalidHeader)
	}
	if len(ifaceName) >= syscall.IFNAMSIZ {
		return nil, fmt.Errorf("%w: interface name %q exceeds %d bytes", ErrInvalidHeader, ifaceName, syscall.IFNAMSIZ-1)
	}
	normOpts, err := opts.normalize()
	if err != nil {
		return nil, err
	}

	fd := -1
	var openErr error
	for i := range 256 {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, openErr = syscall.Open(dev, syscall.O_RDONLY, 0)
		if openErr == nil {
			break
		}
		if openErr != syscall.EBUSY {
			break
		}
	}
	if fd < 0 {
		return nil, fmt.Errorf("opening /dev/bpf device: %w", openErr)
	}

	bufLen := uint32(normOpts.BufferSize)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSBLEN, uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl BIOCSBLEN: %w", errno)
	}

	var ifr bpfIfreq
	copy(ifr.Name[:], ifaceName)
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSETIF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl BIOCSETIF(%s): %w", ifaceName, errno)
	}

	if normOpts.Immediate {
		imm := uint32(1)
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCIMMEDIATE, uintptr(unsafe.Pointer(&imm)))
		if errno != 0 {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("ioctl BIOCIMMEDIATE: %w", errno)
		}
	}

	if normOpts.Promiscuous {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCPROMISC, 0)
		if errno != 0 {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("ioctl BIOCPROMISC: %w", errno)
		}
	}

	if normOpts.Timeout > 0 {
		tv := syscall.NsecToTimeval(normOpts.Timeout.Nanoseconds())
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSRTIMEOUT, uintptr(unsafe.Pointer(&tv)))
		if errno != 0 {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("ioctl BIOCSRTIMEOUT: %w", errno)
		}
	}

	if len(normOpts.BPFFilter) > 0 {
		insns := make([]syscall.BpfInsn, len(normOpts.BPFFilter))
		for i, insn := range normOpts.BPFFilter {
			insns[i] = syscall.BpfInsn{
				Code: insn.Code,
				Jt:   insn.JT,
				Jf:   insn.JF,
				K:    insn.K,
			}
		}
		prog := syscall.BpfProgram{
			Len:   uint32(len(insns)),
			Insns: &insns[0],
		}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSETF, uintptr(unsafe.Pointer(&prog)))
		runtime.KeepAlive(insns)
		if errno != 0 {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("ioctl BIOCSETF: %w", errno)
		}
	}

	var actualBufLen uint32
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGBLEN, uintptr(unsafe.Pointer(&actualBufLen)))
	if errno != 0 || actualBufLen == 0 {
		actualBufLen = bufLen
	}

	var dlt uint32
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCGDLT, uintptr(unsafe.Pointer(&dlt)))
	if errno != 0 {
		dlt = uint32(LinkTypeEthernet)
	}

	return &LiveCapture{
		fd:        fd,
		ifaceName: ifaceName,
		linkType:  LinkType(dlt & 0xffff),
		snapLen:   normOpts.SnapLen,
		buf:       make([]byte, actualBufLen),
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

const LinkTypeUnknown LinkType = 0xffff

// SnapLen returns the configured snapshot length.
func (lc *LiveCapture) SnapLen() uint32 {
	if lc == nil {
		return 0
	}
	return lc.snapLen
}

// ReadPacket reads the next live packet from the kernel BPF buffer. The returned
// byte slice aliases the LiveCapture's internal read buffer and remains valid
// until the next call to ReadPacket.
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	fd, ok := lc.snapshotFD()
	if !ok {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	for lc.queueIdx >= len(lc.queued) {
		n, err := syscall.Read(fd, lc.buf)
		if err != nil {
			return PacketRecord{}, nil, err
		}
		if n == 0 {
			fd, ok = lc.snapshotFD()
			if !ok {
				return PacketRecord{}, nil, ErrInvalidHeader
			}
			continue
		}
		records, err := ParseBPFBuffer(lc.buf[:n], lc.linkType)
		if err != nil {
			return PacketRecord{}, nil, err
		}
		lc.queued = records
		lc.queueIdx = 0
	}

	rec := lc.queued[lc.queueIdx]
	lc.queueIdx++
	rec.Index = lc.pktIndex
	lc.pktIndex++
	if uint32(rec.PayloadLength) > lc.snapLen {
		rec.PayloadLength = int64(lc.snapLen)
		rec.CaptureLen = lc.snapLen
	}
	payload := lc.buf[rec.PayloadOffset : rec.PayloadOffset+rec.PayloadLength]
	return rec, payload, nil
}

func (lc *LiveCapture) statsDelta() (LiveStats, error) {
	var raw syscall.BpfStat
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(lc.fd), syscall.BIOCGSTATS, uintptr(unsafe.Pointer(&raw)))
	if errno != 0 {
		return LiveStats{}, errno
	}
	// BPF returns cumulative 32-bit counters. Subtract modulo 2^32.
	return LiveStats{
		PacketsReceived: uint64(raw.Recv - uint32(lc.stats.PacketsReceived)),
		PacketsDropped:  uint64(raw.Drop - uint32(lc.stats.PacketsDropped)),
	}, nil
}
