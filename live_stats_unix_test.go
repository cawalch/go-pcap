//go:build linux || darwin

package pcap

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestLiveStatsInvalidHandle(t *testing.T) {
	for _, lc := range []*LiveCapture{nil, {}, {fd: -1}} {
		if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("Stats() error = %v, want ErrInvalidHeader", err)
		}
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
