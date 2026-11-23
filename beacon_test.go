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

	// Zero-interval timestamps must yield BeaconScore == 0, and large PCR totals must not wrap uint64.
	zeroInt := ComputeBeaconStats([]int64{100, 100, 100, 100}, []uint64{64, 64, 64, 64}, ^uint64(0)-10, ^uint64(0)-10)
	if zeroInt.BeaconScore != 0 {
		t.Fatalf("zero-interval BeaconScore = %v, want 0", zeroInt.BeaconScore)
	}
	if zeroInt.ProducerConsumerRatio != 0 {
		t.Fatalf("large-byte PCR = %v, want 0", zeroInt.ProducerConsumerRatio)
	}

	// Bare TCP control packets (SYN, bare ACK) must not skew Beacon sample counts.
	var ackFrames [][]byte
	ackFrames = append(ackFrames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 2}, 50001, 443, 1, 0, TCPFlagSYN, nil))
	for range 10 {
		ackFrames = append(ackFrames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 2}, 50001, 443, 2, 1, TCPFlagACK, nil))
	}
	ackFrames = append(ackFrames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 2}, 50001, 443, 2, 1, TCPFlagPSH|TCPFlagACK, []byte("hello")))
	ackPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, ackFrames)
	ackCap, err := New(ackPCAP)
	if err != nil {
		t.Fatal(err)
	}
	ackBeacons, err := ackCap.Beacons(ackPCAP)
	if err != nil || len(ackBeacons) != 1 || ackBeacons[0].Stats.SampleCount != 1 {
		t.Fatalf("ackBeacons = (%+v, %v), want SampleCount=1", ackBeacons, err)
	}
}

func TestBeacons3TupleAndExclusions(t *testing.T) {
	// 6 rotating-SrcPort callbacks spaced 5s apart, plus 6 fast DNS :53 queries spaced 100ms apart.
	var frames [][]byte
	var timestamps []int64
	baseTS := int64(100_000_000_000)
	for i := range 6 {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 10}, [4]byte{203, 0, 113, 50}, uint16(40000+i), 443, 1, 1, TCPFlagPSH|TCPFlagACK, bytes.Repeat([]byte{'B'}, 64)))
		timestamps = append(timestamps, baseTS+int64(i)*5_000_000_000)

		frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 10}, [4]byte{8, 8, 8, 8}, uint16(50000+i), 53, bytes.Repeat([]byte{'D'}, 32)))
		timestamps = append(timestamps, baseTS+int64(i)*100_000_000)
	}
	// This flow starts with a resolver reply, so port 53 is the source.
	frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 8}, 53, 40001, []byte{1}))
	timestamps = append(timestamps, baseTS)

	var buf bytes.Buffer
	pw, err := NewPCAPWriter(&buf, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	for i := range frames {
		if err := pw.WritePacket(timestamps[i], frames[i]); err != nil {
			t.Fatal(err)
		}
	}
	rawPCAP := buf.Bytes()
	c, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Default 5-tuple Beacons sees 1 sample per flow, so BeaconScore == 0.
	b5, err := c.Beacons(rawPCAP)
	if err != nil {
		t.Fatalf("Beacons() error = %v", err)
	}
	for _, b := range b5 {
		if b.Stats.BeaconScore != 0 {
			t.Fatalf("expected 0 5-tuple BeaconScore for rotating SrcPort, got %+v", b)
		}
	}

	// 3-tuple mode detects the 443 callback and excludes port 53 by default.
	b3, err := c.BeaconsWithOptions(rawPCAP, BeaconOptions{GroupBy3Tuple: true})
	if err != nil {
		t.Fatalf("BeaconsWithOptions() error = %v", err)
	}
	if len(b3) != 1 || b3[0].DstPort != 443 || b3[0].SrcPort != 0 || b3[0].Stats.SampleCount != 6 || b3[0].Stats.BeaconScore < 0.95 {
		t.Fatalf("b3 = %+v, want 1 beacon on port 443 with score >= 0.95", b3)
	}

	// With IncludeDNSPort=true and default 1s MinIntervalNs, port 53 (100ms) is still zero-scored.
	b3DNS, err := c.BeaconsWithOptions(rawPCAP, BeaconOptions{GroupBy3Tuple: true, IncludeDNSPort: true})
	if err != nil || len(b3DNS) != 3 {
		t.Fatalf("BeaconsWithOptions(IncludeDNSPort) = (%+v, %v)", b3DNS, err)
	}
	for _, b := range b3DNS {
		if b.DstPort == 53 && b.Stats.BeaconScore != 0 {
			t.Fatalf("expected port 53 100ms interval to be zeroed by MinIntervalNs, got %+v", b.Stats)
		}
	}
}
