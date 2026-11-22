package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBeaconStatsAndCaptureBeacons(t *testing.T) {
	ts := []int64{
		10_000_000_000,
		20_000_000_000,
		30_000_000_000,
		40_000_000_000,
		50_000_000_000,
	}
	sizes := []uint64{64, 64, 64, 64, 64}
	stats := ComputeBeaconStats(ts, sizes, 320, 320)
	if stats.MedianIntervalNs != 10_000_000_000 || stats.MADIntervalNs != 0 || stats.BeaconScore < 0.99 {
		t.Fatalf("BeaconStats = %+v, want high periodicity and uniformity", stats)
	}
	if stats.ProducerConsumerRatio != 0 {
		t.Fatalf("PCR = %v, want 0", stats.ProducerConsumerRatio)
	}

	var frames [][]byte
	for range 5 {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 1}, 50000, 443, 1, 1, TCPFlagPSH|TCPFlagACK, bytes.Repeat([]byte{'A'}, 64)))
	}
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	beacons, err := cap.Beacons(rawPCAP)
	if err != nil || len(beacons) != 1 || beacons[0].Stats.BeaconScore < 0.95 {
		t.Fatalf("cap.Beacons() = (%+v, %v)", beacons, err)
	}
}
