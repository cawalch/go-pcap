package pcap

import (
	"math"
	"net/netip"
	"slices"
)

// BeaconStats contains statistical timing regularity, payload size uniformity,
// and directional Producer-Consumer Ratio (PCR) metrics for C2 beacon and data
// exfiltration triage.
type BeaconStats struct {
	SampleCount           int
	MedianIntervalNs      int64
	MADIntervalNs         int64
	JitterRatio           float64
	PeriodicityScore      float64
	MedianPayloadBytes    uint64
	MADPayloadBytes       uint64
	PayloadUniformity     float64
	ProducerConsumerRatio float64
	BeaconScore           float64
}

// FlowBeacon pairs a 5-tuple flow index with its computed [BeaconStats].
type FlowBeacon struct {
	FlowIndex int
	Protocol  uint8
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Stats     BeaconStats
}

// ComputeBeaconStats computes C2 beacon timing periodicity, payload size
// uniformity, and directional Producer-Consumer Ratio (PCR) from client packet
// timestamps (in nanoseconds), client payload byte sizes, and total client/server
// byte counts.
//
// It requires at least 4 timestamps (3 inter-arrival intervals) to compute a
// non-zero PeriodicityScore and BeaconScore.
func ComputeBeaconStats(timestampsNs []int64, payloadBytes []uint64, clientBytes, serverBytes uint64) BeaconStats {
	out := BeaconStats{
		SampleCount:           len(timestampsNs),
		ProducerConsumerRatio: computePCR(clientBytes, serverBytes),
	}
	if len(timestampsNs) < 4 {
		return out
	}

	sortedTS := slices.Clone(timestampsNs)
	slices.Sort(sortedTS)
	// Each delta replaces a timestamp whose last use is in this iteration.
	intervals := sortedTS[:0]
	for i := 1; i < len(sortedTS); i++ {
		delta := sortedTS[i] - sortedTS[i-1]
		if delta >= 0 {
			intervals = append(intervals, delta)
		}
	}
	if len(intervals) < 3 {
		return out
	}
	slices.Sort(intervals)

	medInterval := median(intervals)
	out.MedianIntervalNs = medInterval

	q1 := float64(intervals[len(intervals)/4])
	q3 := float64(intervals[3*len(intervals)/4])
	madInterval := medianAbsoluteDeviation(intervals, medInterval)
	out.MADIntervalNs = madInterval

	if medInterval > 0 {
		out.JitterRatio = float64(madInterval) / float64(medInterval)
		// Regularity score: 1.0 when MAD == 0, decaying smoothly as jitter increases.
		regScore := max(0.0, 1.0-out.JitterRatio)

		// Bowley quartile skewness symmetry score (1.0 - |skew|).
		q2 := float64(medInterval)
		symScore := 1.0
		if q3 > q1 {
			bowley := (q1 + q3 - 2*q2) / (q3 - q1)
			symScore = max(0.0, 1.0-math.Abs(bowley))
		}
		out.PeriodicityScore = 0.7*regScore + 0.3*symScore
	}

	if len(payloadBytes) > 0 {
		sortedSizes := slices.Clone(payloadBytes)
		slices.Sort(sortedSizes)
		medSize := median(sortedSizes)
		out.MedianPayloadBytes = medSize

		madSize := medianAbsoluteDeviation(sortedSizes, medSize)
		out.MADPayloadBytes = madSize
		if medSize > 0 {
			out.PayloadUniformity = max(0.0, 1.0-float64(madSize)/float64(medSize))
		} else if madSize == 0 {
			out.PayloadUniformity = 1.0
		}
	}

	if medInterval > 0 {
		out.BeaconScore = 0.65*out.PeriodicityScore + 0.35*out.PayloadUniformity
	}
	return out
}

func computePCR(clientBytes, serverBytes uint64) float64 {
	total := float64(clientBytes) + float64(serverBytes)
	if total == 0 {
		return 0
	}
	return (float64(clientBytes) - float64(serverBytes)) / total
}

// median returns the median of a sorted, nonempty slice of nonnegative samples.
func median[T int64 | uint64](sorted []T) T {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return sorted[n/2-1] + (sorted[n/2]-sorted[n/2-1])/2
}

// medianAbsoluteDeviation reuses the caller's scratch slice.
func medianAbsoluteDeviation[T int64 | uint64](samples []T, center T) T {
	for i, sample := range samples {
		if sample >= center {
			samples[i] = sample - center
		} else {
			samples[i] = center - sample
		}
	}
	slices.Sort(samples)
	return median(samples)
}

// BeaconOptions configures beacon aggregation in [Capture.BeaconsWithOptions].
type BeaconOptions struct {
	// GroupBy3Tuple aggregates flow-start callbacks by (Protocol, SrcAddr,
	// DstAddr, DstPort) instead of 5-tuple, catching beacons that open a new
	// source port per callback. FlowIndex is set to the first flow's index and
	// SrcPort is set to 0 in 3-tuple results.
	GroupBy3Tuple bool
	// MinIntervalNs ignores 3-tuple beacon candidates whose median inter-arrival
	// interval is below this threshold by zeroing PeriodicityScore and
	// BeaconScore. When GroupBy3Tuple is true and MinIntervalNs is 0, a default
	// of 1 second (1_000_000_000 ns) is used. Set a negative value to disable.
	MinIntervalNs int64
	// IncludeDNSPort includes port 53 traffic when GroupBy3Tuple is true.
	// By default, port 53 is excluded in 3-tuple mode to avoid DNS polling FPs.
	IncludeDNSPort bool
}

// Beacons computes C2 beacon periodicity, payload size uniformity, and
// directional Producer-Consumer Ratio (PCR) metrics for every IPv4/IPv6 flow in
// the capture.
func (c *Capture) Beacons(data []byte) ([]FlowBeacon, error) {
	return c.BeaconsWithOptions(data, BeaconOptions{})
}

// BeaconsWithOptions computes C2 beacon metrics according to opts. When
// opts.GroupBy3Tuple is false, it behaves identically to [Capture.Beacons].
func (c *Capture) BeaconsWithOptions(data []byte, opts BeaconOptions) ([]FlowBeacon, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}

	type flowAccum struct {
		flowIndex   int
		proto       uint8
		srcAddr     netip.Addr
		dstAddr     netip.Addr
		srcPort     uint16
		dstPort     uint16
		firstTS     int64
		timestamps  []int64
		sizes       []uint64
		clientBytes uint64
		serverBytes uint64
	}

	r := SafeReader{data: data, size: int64(len(data))}
	var table flowIndexTable
	var flows []flowAccum

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		idx, exists, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if !exists {
			flows = append(flows, flowAccum{
				flowIndex: idx,
				proto:     frame.IPProtocol,
				srcAddr:   frame.SrcAddr,
				dstAddr:   frame.DstAddr,
				srcPort:   frame.SrcPort,
				dstPort:   frame.DstPort,
				firstTS:   pkt.TimestampNs,
			})
		} else if pkt.TimestampNs < flows[idx].firstTS {
			flows[idx].firstTS = pkt.TimestampNs
		}

		fa := &flows[idx]
		if frame.SrcAddr == fa.srcAddr && frame.SrcPort == fa.srcPort {
			fa.clientBytes += uint64(frame.PayloadLength)
			if !opts.GroupBy3Tuple && (frame.IPProtocol != IPProtoTCP || frame.PayloadLength > 0) {
				fa.timestamps = append(fa.timestamps, pkt.TimestampNs)
				fa.sizes = append(fa.sizes, uint64(frame.PayloadLength))
			}
		} else {
			fa.serverBytes += uint64(frame.PayloadLength)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if !opts.GroupBy3Tuple {
		out := make([]FlowBeacon, len(flows))
		for i := range flows {
			fa := &flows[i]
			out[i] = FlowBeacon{
				FlowIndex: fa.flowIndex,
				Protocol:  fa.proto,
				SrcAddr:   fa.srcAddr,
				DstAddr:   fa.dstAddr,
				SrcPort:   fa.srcPort,
				DstPort:   fa.dstPort,
				Stats:     ComputeBeaconStats(fa.timestamps, fa.sizes, fa.clientBytes, fa.serverBytes),
			}
		}
		return out, nil
	}

	type tuple3Key struct {
		proto   uint8
		srcAddr netip.Addr
		dstAddr netip.Addr
		dstPort uint16
	}
	type tuple3Accum struct {
		firstFlowIndex int
		key            tuple3Key
		timestamps     []int64
		sizes          []uint64
		clientBytes    uint64
		serverBytes    uint64
	}

	indexByTuple3 := make(map[tuple3Key]int)
	var groups []tuple3Accum
	for i := range flows {
		fa := &flows[i]
		if !opts.IncludeDNSPort && (fa.srcPort == 53 || fa.dstPort == 53) {
			continue
		}
		tk := tuple3Key{
			proto:   fa.proto,
			srcAddr: fa.srcAddr,
			dstAddr: fa.dstAddr,
			dstPort: fa.dstPort,
		}
		gIdx, exists := indexByTuple3[tk]
		if !exists {
			gIdx = len(groups)
			indexByTuple3[tk] = gIdx
			groups = append(groups, tuple3Accum{
				firstFlowIndex: fa.flowIndex,
				key:            tk,
			})
		}
		g := &groups[gIdx]
		g.timestamps = append(g.timestamps, fa.firstTS)
		g.sizes = append(g.sizes, fa.clientBytes)
		g.clientBytes += fa.clientBytes
		g.serverBytes += fa.serverBytes
	}

	minInt := opts.MinIntervalNs
	if minInt == 0 {
		minInt = 1_000_000_000
	}

	out := make([]FlowBeacon, len(groups))
	for i := range groups {
		g := &groups[i]
		stats := ComputeBeaconStats(g.timestamps, g.sizes, g.clientBytes, g.serverBytes)
		if minInt > 0 && stats.MedianIntervalNs < minInt {
			stats.PeriodicityScore = 0
			stats.BeaconScore = 0
		}
		out[i] = FlowBeacon{
			FlowIndex: g.firstFlowIndex,
			Protocol:  g.key.proto,
			SrcAddr:   g.key.srcAddr,
			DstAddr:   g.key.dstAddr,
			SrcPort:   0,
			DstPort:   g.key.dstPort,
			Stats:     stats,
		}
	}
	return out, nil
}
