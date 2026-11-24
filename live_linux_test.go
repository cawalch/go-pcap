//go:build linux

package pcap

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestLiveLinuxReceiveTimestamp(t *testing.T) {
	const futureSec = 2_200_000_000 // Beyond the signed 32-bit seconds range.
	time64 := make([]byte, 16)
	binary.NativeEndian.PutUint64(time64, futureSec)
	binary.NativeEndian.PutUint64(time64[8:], 123_456_789)
	if got, ok := linuxReceiveTimestamp(soTimestampNSNew, time64); !ok || got != futureSec*int64(time.Second)+123_456_789 {
		t.Fatalf("time64 timestamp = (%d, %v)", got, ok)
	}
	if _, ok := linuxReceiveTimestamp(soTimestampNSNew, time64[:8]); ok {
		t.Fatal("accepted a truncated time64 timestamp")
	}

	const legacySec = 1_900_000_000
	legacy := make([]byte, 2*(strconv.IntSize/8))
	if strconv.IntSize == 32 {
		binary.NativeEndian.PutUint32(legacy, legacySec)
		binary.NativeEndian.PutUint32(legacy[4:], 987_654_321)
	} else {
		binary.NativeEndian.PutUint64(legacy, legacySec)
		binary.NativeEndian.PutUint64(legacy[8:], 987_654_321)
	}
	if got, ok := linuxReceiveTimestamp(syscall.SCM_TIMESTAMPNS, legacy); !ok || got != legacySec*int64(time.Second)+987_654_321 {
		t.Fatalf("legacy timestamp = (%d, %v)", got, ok)
	}

	binary.NativeEndian.PutUint64(time64[8:], uint64(time.Second))
	if _, ok := linuxReceiveTimestamp(soTimestampNSNew, time64); ok {
		t.Fatal("accepted an invalid nanosecond field")
	}
	binary.NativeEndian.PutUint64(time64, math.MaxInt64)
	binary.NativeEndian.PutUint64(time64[8:], 1)
	if _, ok := linuxReceiveTimestamp(soTimestampNSNew, time64); ok {
		t.Fatal("accepted an overflowing timestamp")
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
	// Linux can enable software timestamping asynchronously the first time a
	// socket requests it. Allow that work to complete before sending the packet.
	time.Sleep(50 * time.Millisecond)
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

func TestLiveLinuxReadTimeFallback(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()
	lc := &LiveCapture{
		file: os.NewFile(uintptr(fds[0]), "capture-fallback"),
		buf:  make([]byte, 64), snapLen: 64, timeout: time.Second,
		oob: make([]byte, syscall.CmsgSpace(16)),
	}
	defer func() { _ = lc.Close() }()
	if _, err := syscall.Write(fds[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
	read := time.Now().UnixNano()
	rec, _, err := lc.ReadPacket()
	if err != nil || rec.TimestampNs < read || rec.TimestampNs > time.Now().UnixNano() {
		t.Fatalf("wall clock timestamp = %d, read started at %d, err = %v", rec.TimestampNs, read, err)
	}
}

func TestLiveLinuxTruncatedWireLength(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	addr := receiver.LocalAddr().(*net.UDPAddr)
	for _, filterCap := range []uint32{32, 96} {
		filter := BPFFilterUDPPort(uint16(addr.Port))
		filter[len(filter)-2].K = filterCap
		lc, err := OpenLive("lo", LiveOptions{Promiscuous: true, SnapLen: 64, BPFFilter: filter, Timeout: 2 * time.Second})
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("live capture permissions: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lc.Close() }()
		if _, err := receiver.WriteToUDP(make([]byte, 200), addr); err != nil {
			t.Fatal(err)
		}
		rec, p, err := lc.ReadPacket()
		if err != nil || rec.OriginalLen != 242 || rec.CaptureLen != min(64, filterCap) || len(p) != int(rec.CaptureLen) {
			t.Fatalf("filter snapshot %d: rec=%+v len=%d err=%v", filterCap, rec, len(p), err)
		}
		if err := lc.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
