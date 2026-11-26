//go:build linux

package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	packetVersion           = 10 // PACKET_VERSION is absent from syscall on some architectures.
	tpacketV3               = 2
	tpacketUser             = 1 // TP_STATUS_USER
	tpacketV3Alignment      = 8
	tpacketBlockHeaderSize  = 48 // sizeof(struct tpacket_block_desc)
	tpacketPacketHeaderSize = 68 // TPACKET3_HDRLEN includes sockaddr_ll.
	tpacketMaxMACOffset     = 96 // TPACKET_ALIGN(TPACKET3_HDRLEN + 16) with no link header.
	linuxRingDefaultBlocks  = 32
	linuxRingDefaultMemory  = 4 << 20
)

type linuxPacketRing struct {
	data      []byte
	blockSize int
	block     int
	offset    uint32
	end       uint32
	remaining uint32
}

// LiveCapture reads live packets from an OS network interface using standard
// library AF_PACKET syscalls on Linux. A LiveCapture must not be copied after opening.
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
	readMu    sync.Mutex // serializes reads and protects the mapping from Close
	ring      linuxPacketRing
	unmap     runtime.Cleanup
	pktIndex  int
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

// OpenLive opens a live packet capture handle on ifaceName using an AF_PACKET
// raw socket and standard library syscalls without cgo or libpcap. It accepts
// Ethernet, Linux loopback, and Metricom interfaces. An unsupported interface hardware
// type returns an error wrapping [ErrUnsupportedDataLink].
func OpenLive(ifaceName string, opts LiveOptions) (*LiveCapture, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("%w: empty interface name", ErrInvalidHeader)
	}
	normOpts, err := opts.normalize()
	if err != nil {
		return nil, err
	}
	links, err := readLinuxLiveLinks()
	if err != nil {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Err: err}
	}
	var iface linuxLiveLink
	for _, link := range links {
		if link.device.Name == ifaceName {
			iface = link
			break
		}
	}
	if iface.device.Index == 0 {
		return nil, &net.OpError{Op: "route", Net: "ip+net", Err: errors.New("no such network interface")}
	}

	// Install the filter and ring before binding makes the socket receive packets.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			_ = syscall.Close(fd)
		}
	}()

	linkType, err := linuxARPHRDLinkType(iface.hardwareType)
	if err != nil {
		return nil, fmt.Errorf("live interface %q: %w", ifaceName, err)
	}

	if normOpts.Promiscuous {
		// Linux packet_mreq contains the interface index, membership type,
		// address length, and eight address bytes in native byte order.
		var membership [16]byte
		binary.NativeEndian.PutUint32(membership[:4], uint32(iface.device.Index))
		binary.NativeEndian.PutUint16(membership[4:6], syscall.PACKET_MR_PROMISC)
		if err := syscall.SetsockoptString(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, string(membership[:])); err != nil {
			return nil, fmt.Errorf("PACKET_ADD_MEMBERSHIP: %w", err)
		}
	}

	filter := normOpts.BPFFilter
	if len(filter) == 0 {
		// Keep only the requested bytes in the ring. The kernel still
		// records the original length in each packet header.
		filter = []BPFInstruction{{Code: bpfClassRET | bpfSrcK, K: normOpts.SnapLen}}
	}
	insns := make([]syscall.SockFilter, len(filter))
	for i, insn := range filter {
		if insn.Code == bpfClassRET|bpfSrcK {
			// Apply the snapshot limit before the kernel copies a packet
			// into the ring. A zero return still rejects the packet.
			insn.K = min(insn.K, normOpts.SnapLen)
		}
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
	err = attachLinuxBPFFilter(fd, &fprog)
	runtime.KeepAlive(insns)
	if err != nil {
		return nil, fmt.Errorf("setsockopt SO_ATTACH_FILTER: %w", err)
	}

	ring, err := openLinuxPacketRing(fd, normOpts, opts.BufferSize <= 0)
	if err != nil {
		return nil, err
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.device.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Munmap(ring.data)
		return nil, err
	}

	lc := &LiveCapture{
		file:      os.NewFile(uintptr(fd), ifaceName),
		ifaceName: ifaceName,
		linkType:  linkType,
		snapLen:   normOpts.SnapLen,
		timeout:   normOpts.Timeout,
		buf:       make([]byte, normOpts.SnapLen),
		ring:      ring,
	}
	lc.unmap = runtime.AddCleanup(lc, func(data []byte) { _ = syscall.Munmap(data) }, ring.data)
	opened = true
	return lc, nil
}

func linuxRingBlockSize(opts LiveOptions, pageSize int) int {
	// Leave room for the largest supported link-layer offset, alignment
	// padding, and the block header before the first packet.
	minBlockSize := max(pageSize, int(opts.SnapLen)+tpacketBlockHeaderSize+tpacketMaxMACOffset+tpacketV3Alignment)
	targetBlockSize := max(minBlockSize, min(opts.BufferSize/4, 64<<10))
	return 1 << bits.Len(uint(targetBlockSize-1))
}

func openLinuxPacketRing(fd int, opts LiveOptions, defaultBuffer bool) (linuxPacketRing, error) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetVersion, tpacketV3); err != nil {
		return linuxPacketRing{}, fmt.Errorf("PACKET_VERSION: %w", err)
	}

	// V3 packs variable-size records into blocks. Size each block to hold
	// at least one full snapshot and keep at least two blocks so the kernel
	// can keep capturing while userspace owns a block. The live option
	// limits bound the total mapping to 64 MiB, including block padding.
	pageSize := os.Getpagesize()
	blockSize := linuxRingBlockSize(opts, pageSize)
	blockCount := max(2, opts.BufferSize/blockSize)
	if defaultBuffer {
		// A partially filled block still occupies a ring slot. Give the
		// default ring more slots to retain sparse traffic between reads.
		memoryLimitedBlocks := (linuxRingDefaultMemory - int(opts.SnapLen)) / blockSize
		blockCount = max(blockCount, min(linuxRingDefaultBlocks, memoryLimitedBlocks))
	}
	// tpacket_req3 needs a valid frame size and frame count even though
	// V3 receive records use variable lengths.
	frameSize := pageSize
	retire := 8 * time.Millisecond
	if opts.Immediate {
		retire = time.Millisecond
	} else if opts.Timeout > 0 {
		retire = max(time.Millisecond, min(retire, opts.Timeout/4))
	}
	var req [28]byte
	binary.NativeEndian.PutUint32(req[0:4], uint32(blockSize))
	binary.NativeEndian.PutUint32(req[4:8], uint32(blockCount))
	binary.NativeEndian.PutUint32(req[8:12], uint32(frameSize))
	binary.NativeEndian.PutUint32(req[12:16], uint32(blockSize/frameSize*blockCount))
	binary.NativeEndian.PutUint32(req[16:20], uint32(retire/time.Millisecond))
	if err := syscall.SetsockoptString(fd, syscall.SOL_PACKET, syscall.PACKET_RX_RING, string(req[:])); err != nil {
		return linuxPacketRing{}, fmt.Errorf("PACKET_RX_RING: %w", err)
	}
	data, err := syscall.Mmap(fd, 0, blockSize*blockCount, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return linuxPacketRing{}, fmt.Errorf("mmap PACKET_RX_RING: %w", err)
	}
	return linuxPacketRing{data: data, blockSize: blockSize}, nil
}

// ReadPacket reads the next live packet with the kernel capture timestamp.
// The returned bytes alias the capture buffer and are valid until the next call.
func (lc *LiveCapture) ReadPacket() (PacketRecord, []byte, error) {
	if lc == nil || lc.file == nil || len(lc.buf) == 0 {
		return PacketRecord{}, nil, ErrInvalidHeader
	}
	lc.readMu.Lock()
	defer lc.readMu.Unlock()
	if lc.timeout > 0 {
		if err := lc.file.SetReadDeadline(time.Now().Add(lc.timeout)); err != nil {
			return PacketRecord{}, nil, err
		}
	}
	raw, err := lc.file.SyscallConn()
	if err != nil {
		return PacketRecord{}, nil, err
	}
	var rec PacketRecord
	var packetErr error
	err = raw.Read(func(uintptr) bool {
		var ready bool
		rec, ready, packetErr = lc.ring.read(lc.buf)
		return ready || packetErr != nil
	})
	if err != nil {
		return PacketRecord{}, nil, err
	}
	if packetErr != nil {
		return PacketRecord{}, nil, packetErr
	}
	rec.Index = lc.pktIndex
	rec.LinkType = lc.linkType
	lc.pktIndex++
	return rec, lc.buf[:rec.CaptureLen], nil
}

func (r *linuxPacketRing) read(buf []byte) (PacketRecord, bool, error) {
	for range len(r.data) / r.blockSize {
		block := r.data[r.block : r.block+r.blockSize]
		status := (*uint32)(unsafe.Pointer(&block[8]))
		if r.remaining == 0 {
			// Acquire ownership before reading headers shared with the kernel.
			if atomic.LoadUint32(status)&tpacketUser == 0 {
				return PacketRecord{}, false, nil
			}
			r.remaining = binary.NativeEndian.Uint32(block[12:16])
			if r.remaining == 0 {
				// The kernel can retire an empty block when the incoming
				// packet needs all the space in a fresh block.
				r.release(status)
				continue
			}
			r.offset = binary.NativeEndian.Uint32(block[16:20])
			r.end = binary.NativeEndian.Uint32(block[20:24])
			if r.offset < tpacketBlockHeaderSize || r.offset%tpacketV3Alignment != 0 ||
				r.end > uint32(len(block)) || r.offset > r.end ||
				r.remaining > (r.end-r.offset)/tpacketPacketHeaderSize {
				r.release(status)
				return PacketRecord{}, false, fmt.Errorf("%w: AF_PACKET block header", ErrInvalidPacket)
			}
		}

		rec, err := r.readPacket(block, buf)
		if err != nil || r.remaining == 0 {
			r.release(status)
		}
		return rec, err == nil, err
	}
	return PacketRecord{}, false, nil
}

func (r *linuxPacketRing) release(status *uint32) {
	// The kernel may reuse this block after the status changes.
	atomic.StoreUint32(status, 0)
	r.remaining = 0
	r.block += r.blockSize
	if r.block == len(r.data) {
		r.block = 0
	}
}

func (r *linuxPacketRing) readPacket(block, buf []byte) (PacketRecord, error) {
	packet := block[r.offset:r.end]
	next := binary.NativeEndian.Uint32(packet[0:4])
	sec := binary.NativeEndian.Uint32(packet[4:8])
	nsec := binary.NativeEndian.Uint32(packet[8:12])
	captured := binary.NativeEndian.Uint32(packet[12:16])
	original := binary.NativeEndian.Uint32(packet[16:20])
	mac := uint32(binary.NativeEndian.Uint16(packet[24:26]))
	limit := uint32(len(packet))
	if r.remaining > 1 {
		if next%tpacketV3Alignment != 0 || next < tpacketPacketHeaderSize || next > limit-tpacketPacketHeaderSize {
			return PacketRecord{}, fmt.Errorf("%w: AF_PACKET next packet offset", ErrInvalidPacket)
		}
		limit = next
	} else if next != 0 {
		return PacketRecord{}, fmt.Errorf("%w: AF_PACKET last packet offset", ErrInvalidPacket)
	}
	if mac < tpacketPacketHeaderSize || mac > limit || captured > limit-mac || captured > original || nsec >= uint32(time.Second) {
		return PacketRecord{}, fmt.Errorf("%w: AF_PACKET packet header", ErrInvalidPacket)
	}

	captured = min(captured, uint32(len(buf)))
	copy(buf, packet[mac:mac+captured])
	r.offset += next
	r.remaining--
	return PacketRecord{
		TimestampNs:   int64(sec)*int64(time.Second) + int64(nsec),
		CaptureLen:    captured,
		OriginalLen:   original,
		PayloadLength: int64(captured),
	}, nil
}

// Close closes the capture descriptor, unblocks any concurrent ReadPacket call,
// and releases the receive ring.
func (lc *LiveCapture) Close() error {
	if lc == nil || lc.file == nil {
		return nil
	}
	lc.statsMu.Lock()
	defer lc.statsMu.Unlock()
	if lc.closed {
		return nil
	}
	lc.closed = true

	closeErr := lc.file.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	lc.readMu.Lock()
	defer lc.readMu.Unlock()
	lc.unmap.Stop()
	return errors.Join(closeErr, syscall.Munmap(lc.ring.data))
}

func (lc *LiveCapture) statsDelta(fd int) (LiveStats, error) {
	// V3 has a third counter for ring freezes, which the API does not expose.
	var counters [3]uint32
	size := uint32(12)
	if errno := getPacketStatistics(fd, &counters, &size); errno != 0 {
		return LiveStats{}, errno
	}
	if size != 12 {
		return LiveStats{}, fmt.Errorf("PACKET_STATISTICS: unexpected size %d", size)
	}
	return LiveStats{PacketsReceived: uint64(counters[0]), PacketsDropped: uint64(counters[1])}, nil
}
