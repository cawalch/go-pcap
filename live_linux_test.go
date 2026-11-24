//go:build linux

package pcap

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestLiveLinuxRingBlockSize(t *testing.T) {
	// An IP-only interface can place the snapshot 96 bytes into the
	// packet record, rather than the earlier offset used for Ethernet.
	const pageSize = 4096
	opts := LiveOptions{SnapLen: 3964, BufferSize: pageSize}
	if got := linuxRingBlockSize(opts, pageSize); got != 2*pageSize {
		t.Fatalf("block size = %d, want %d for an IP-only snapshot", got, 2*pageSize)
	}
}

func TestLiveLinuxRingPacketBounds(t *testing.T) {
	const futureSec = 2_200_000_000 // Beyond the signed 32-bit seconds range.
	const frameOffset = tpacketBlockHeaderSize
	const frameSize = 80
	block := make([]byte, frameOffset+frameSize*2)
	binary.NativeEndian.PutUint32(block[8:12], tpacketUser)
	binary.NativeEndian.PutUint32(block[12:16], 2)
	binary.NativeEndian.PutUint32(block[16:20], frameOffset)
	binary.NativeEndian.PutUint32(block[20:24], uint32(len(block)))

	for i := range 2 {
		packet := block[frameOffset+i*frameSize:]
		binary.NativeEndian.PutUint32(packet[4:8], futureSec)
		binary.NativeEndian.PutUint32(packet[8:12], 123_456_789)
		binary.NativeEndian.PutUint32(packet[12:16], 4)
		binary.NativeEndian.PutUint32(packet[16:20], 8)
		binary.NativeEndian.PutUint16(packet[24:26], tpacketPacketHeaderSize)
	}
	binary.NativeEndian.PutUint32(block[frameOffset:], frameSize)
	binary.NativeEndian.PutUint32(block[frameOffset+frameSize+12:], frameSize)
	ring := linuxPacketRing{data: block, blockSize: len(block)}

	rec, ready, err := ring.read(make([]byte, 3))
	if err != nil || !ready || rec.CaptureLen != 3 || rec.OriginalLen != 8 || rec.TimestampNs != futureSec*int64(time.Second)+123_456_789 {
		t.Fatalf("first packet = (%+v, %v, %v)", rec, ready, err)
	}
	if _, _, err := ring.read(make([]byte, 3)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("out-of-bounds packet error = %v, want ErrInvalidPacket", err)
	}
	if _, ready, err := ring.read(make([]byte, 3)); ready || err != nil {
		t.Fatalf("released block ready=%v, error=%v", ready, err)
	}
}

func TestLiveLinuxQueuedTimestamp(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	addr := receiver.LocalAddr().(*net.UDPAddr)
	filter := BPFFilterUDPPort(uint16(addr.Port))
	filter[len(filter)-2].K = 64
	lc, err := OpenLive("lo", LiveOptions{SnapLen: 96, BPFFilter: filter, Timeout: 2 * time.Second})
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("live capture permissions: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var payload [200]byte
	sent := time.Now()
	if _, err := receiver.WriteToUDP(payload[:], addr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.ReadFromUDP(payload[:]); err != nil {
		t.Fatal(err)
	}
	delivered := time.Now()
	time.Sleep(250 * time.Millisecond)
	read := time.Now()
	rec, packet, err := lc.ReadPacket()
	if err != nil || rec.OriginalLen != 242 || rec.CaptureLen != 64 || len(packet) != 64 {
		t.Fatalf("queued packet = (%+v, %d bytes, %v)", rec, len(packet), err)
	}
	if rec.TimestampNs < sent.UnixNano() || rec.TimestampNs > delivered.UnixNano() {
		t.Fatalf("packet timestamp outside send–delivery window: timestamp minus delivery %v, timestamp minus delayed read %v", time.Duration(rec.TimestampNs-delivered.UnixNano()), time.Duration(rec.TimestampNs-read.UnixNano()))
	}
	t.Logf("timestamp minus delivery %v, timestamp minus delayed read %v", time.Duration(rec.TimestampNs-delivered.UnixNano()), time.Duration(rec.TimestampNs-read.UnixNano()))
}

func TestLiveLinuxRingTimeout(t *testing.T) {
	lc, err := OpenLive("lo", LiveOptions{
		Timeout:   20 * time.Millisecond,
		BPFFilter: []BPFInstruction{{Code: bpfClassRET | bpfSrcK}},
	})
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("live capture permissions: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()
	if _, _, err := lc.ReadPacket(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("empty ring read error = %v, want deadline exceeded", err)
	}
}

func TestLiveCaptureConcurrentCloseUnblocksReadPacket(t *testing.T) {
	lc, err := OpenLive("lo", LiveOptions{
		BPFFilter: []BPFInstruction{{Code: bpfClassRET | bpfSrcK}},
	})
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("live capture permissions: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()

	done := make(chan error, 1)
	go func() {
		_, _, err := lc.ReadPacket()
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := lc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := lc.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("Stats() after Close() error = %v, want ErrInvalidHeader", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadPacket() succeeded after concurrent Close()")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket() remained blocked after concurrent Close()")
	}
}

func TestLiveLinuxTruncatedWireLength(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	addr := receiver.LocalAddr().(*net.UDPAddr)
	for _, test := range []struct {
		snapLen    uint32
		filterCap  uint32
		bufferSize int
		payloadLen uint32
		returnA    bool
	}{
		{64, 32, DefaultLiveBufferSize, 200, false},
		{64, 96, DefaultLiveBufferSize, 200, false},
		{64, MaxSnapLen, 4096, 10_000, true},
		{MaxSnapLen, MaxSnapLen, DefaultLiveBufferSize, 65_507, false},
	} {
		filter := BPFFilterUDPPort(uint16(addr.Port))
		accept := len(filter) - 2
		if test.returnA {
			// Return the snapshot via the accumulator after jumping over
			// the reject instruction. This leaves the other jumps intact.
			filter[accept] = BPFInstruction{Code: bpfClassJMP | bpfOpJA, K: 1}
			filter = append(filter,
				BPFInstruction{Code: bpfClassLD | bpfSizeW | bpfModeIMM, K: test.filterCap},
				BPFInstruction{Code: bpfClassRET | bpfRetA},
			)
		} else {
			filter[accept].K = test.filterCap
		}
		lc, err := OpenLive("lo", LiveOptions{
			Promiscuous: true, SnapLen: test.snapLen, BufferSize: test.bufferSize,
			BPFFilter: filter, Timeout: 2 * time.Second,
		})
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("live capture permissions: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lc.Close() }()
		if _, err := receiver.WriteToUDP(make([]byte, test.payloadLen), addr); err != nil {
			t.Fatal(err)
		}
		rec, p, err := lc.ReadPacket()
		wireLen := 42 + test.payloadLen
		if err != nil || rec.OriginalLen != wireLen || rec.CaptureLen != min(test.snapLen, test.filterCap, wireLen) || len(p) != int(rec.CaptureLen) {
			t.Fatalf("snaplen %d filter snapshot %d: rec=%+v len=%d err=%v", test.snapLen, test.filterCap, rec, len(p), err)
		}
		if err := lc.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveLinuxDefaultRingQueuesSmallPackets(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	addr := receiver.LocalAddr().(*net.UDPAddr)
	lc, err := OpenLive("lo", LiveOptions{
		BPFFilter: BPFFilterUDPPort(uint16(addr.Port)),
		Timeout:   2 * time.Second,
	})
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("live capture permissions: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()

	const total, sparse = 32, 8
	for i := range total {
		if _, err := receiver.WriteToUDP([]byte{byte(i)}, addr); err != nil {
			t.Fatal(err)
		}
		if i < sparse {
			// Let the kernel publish a partial block between sparse sends.
			time.Sleep(12 * time.Millisecond)
		}
	}
	var seen [total]bool
	count := 0
	for i := range 2 * total {
		rec, packet, err := lc.ReadPacket()
		if err != nil || rec.Index != i || rec.CaptureLen != 43 || len(packet) != 43 || packet[42] >= total {
			t.Fatalf("packet %d = (%+v, %d bytes, %v), received %d of %d sends", i, rec, len(packet), err, count, total)
		}
		if !seen[packet[42]] {
			seen[packet[42]] = true
			count++
			if count == total {
				return
			}
		}
	}
	t.Fatalf("received %d of %d sends", count, total)
}
