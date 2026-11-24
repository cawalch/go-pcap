//go:build linux || darwin

package pcap

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestLiveStatsInvalidHandle(t *testing.T) {
	for _, lc := range []*LiveCapture{nil, {}} {
		if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("Stats() error = %v, want ErrInvalidHeader", err)
		}
	}
}

func TestLiveCaptureConcurrentCloseUnblocksReadPacket(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(pair[1]) }()
	if err := syscall.SetNonblock(pair[0], true); err != nil {
		_ = syscall.Close(pair[0])
		t.Fatal(err)
	}
	r := os.NewFile(uintptr(pair[0]), "capture-socket")

	lc := &LiveCapture{
		file:     r,
		linkType: LinkTypeEthernet,
		snapLen:  DefaultLiveSnapLen,
		buf:      make([]byte, 4096),
	}

	done := make(chan error, 1)
	go func() {
		_, _, readErr := lc.ReadPacket()
		done <- readErr
	}()

	time.Sleep(10 * time.Millisecond)
	if err := lc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// Second Close is idempotent.
	if err := lc.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	// Stats after Close must return ErrInvalidHeader.
	if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("Stats() after Close() error = %v, want ErrInvalidHeader", err)
	}

	select {
	case readErr := <-done:
		if readErr == nil {
			t.Fatal("ReadPacket() succeeded after concurrent Close(), want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket() remained blocked after concurrent Close()")
	}
}

func TestLiveStatsLoopback(t *testing.T) {
	iface := "lo"
	if runtime.GOOS == "darwin" {
		iface = "lo0"
	}
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	addr := receiver.LocalAddr().(*net.UDPAddr)
	lc, err := OpenLive(iface, LiveOptions{})
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("live capture permissions: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()
	before, err := lc.Stats()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := sender.Write([]byte("stats")); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [5]byte
	if _, _, err := receiver.ReadFromUDP(buf[:]); err != nil {
		t.Fatal(err)
	}
	after, err := lc.Stats()
	if err != nil || after.PacketsReceived <= before.PacketsReceived {
		t.Fatalf("after loopback packet: %+v, %v (before %+v)", after, err, before)
	}
	again, err := lc.Stats()
	if err != nil || again.PacketsReceived < after.PacketsReceived || again.PacketsDropped < after.PacketsDropped {
		t.Fatalf("second poll: %+v, %v (previous %+v)", again, err, after)
	}
	if err := lc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("closed Stats: %v", err)
	}
}
