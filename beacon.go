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
	intervals := make([]int64, 0, len(sortedTS)-1)
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

	medInterval := medianInt64(intervals)
	out.MedianIntervalNs = medInterval

	deviations := make([]int64, len(intervals))
	for i, v := range intervals {
		d := v - medInterval
		if d < 0 {
			d = -d
		}
		deviations[i] = d
	}
	slices.Sort(deviations)
	madInterval := medianInt64(deviations)
	out.MADIntervalNs = madInterval

	if medInterval > 0 {
		out.JitterRatio = float64(madInterval) / float64(medInterval)
		// Regularity score: 1.0 when MAD == 0, decaying smoothly as jitter increases.
		regScore := max(0.0, 1.0-out.JitterRatio)

		// Bowley quartile skewness symmetry score (1.0 - |skew|).
		q1 := float64(intervals[len(intervals)/4])
		q2 := float64(medInterval)
		q3 := float64(intervals[(3*len(intervals))/4])
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
		medSize := medianUint64(sortedSizes)
		out.MedianPayloadBytes = medSize

		sizeDevs := make([]uint64, len(sortedSizes))
		for i, s := range sortedSizes {
			if s >= medSize {
				sizeDevs[i] = s - medSize
			} else {
				sizeDevs[i] = medSize - s
			}
		}
		slices.Sort(sizeDevs)
		madSize := medianUint64(sizeDevs)
		out.MADPayloadBytes = madSize
		if medSize > 0 {
			out.PayloadUniformity = max(0.0, 1.0-float64(madSize)/float64(medSize))
		} else if madSize == 0 {
			out.PayloadUniformity = 1.0
		}
	}

	out.BeaconScore = 0.65*out.PeriodicityScore + 0.35*out.PayloadUniformity
	return out
}

func computePCR(clientBytes, serverBytes uint64) float64 {
	total := clientBytes + serverBytes
	if total == 0 {
		return 0
	}
	return (float64(clientBytes) - float64(serverBytes)) / float64(total)
}

func medianInt64(sorted []int64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return sorted[n/2-1] + (sorted[n/2]-sorted[n/2-1])/2
}

func medianUint64(sorted []uint64) uint64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return sorted[n/2-1] + (sorted[n/2]-sorted[n/2-1])/2
}

// Beacons computes C2 beacon periodicity, payload size uniformity, and
// directional Producer-Consumer Ratio (PCR) metrics for every IPv4/IPv6 flow in
// the capture.
func (c *Capture) Beacons(data []byte) ([]FlowBeacon, error) {
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
			})
		}

		fa := &flows[idx]
		if frame.SrcAddr == fa.srcAddr && frame.SrcPort == fa.srcPort {
			fa.clientBytes += uint64(frame.PayloadLength)
			fa.timestamps = append(fa.timestamps, pkt.TimestampNs)
			fa.sizes = append(fa.sizes, uint64(frame.PayloadLength))
		} else {
			fa.serverBytes += uint64(frame.PayloadLength)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

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
