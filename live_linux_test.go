//go:build linux

package pcap

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

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
