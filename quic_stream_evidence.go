package pcap

import (
	"container/heap"
	"sort"
)

type quicObservedRange struct{ start, end int }
type quicObservedRangeHeap []quicObservedRange

func (h quicObservedRangeHeap) Len() int           { return len(h) }
func (h quicObservedRangeHeap) Less(i, j int) bool { return h[i].start < h[j].start }
func (h quicObservedRangeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *quicObservedRangeHeap) Push(v any)        { *h = append(*h, v.(quicObservedRange)) }
func (h *quicObservedRangeHeap) Pop() any {
	a := *h
	last := a[len(a)-1]
	*h = a[:len(a)-1]
	return last
}

type quicStreamContribution struct{ packet, start, end int }
type quicStreamProgress struct{ step, end int }

type quicLocatedStream struct {
	stream        QUICStream
	progress      []quicStreamProgress
	waiting       quicObservedRangeHeap
	contributions []quicStreamContribution
	packets       []int
	shared        bool
	// Encoded STREAM and RESET_STREAM bytes for this stream in its latest
	// packet. Other streams or controls in the same packet imply sharing.
	lastWire, lastSize int
}

// Reassembly owns overlap/final-size validation. Track only stream ranges,
// their packets and when each contiguous prefix became available.
func (s *quicLocatedStream) observe(packet QUIC1RTTPacket, start, end, wire, step int) {
	if len(s.packets) == 0 || s.packets[len(s.packets)-1] != packet.PacketIndex {
		s.shared = s.shared || s.lastWire < s.lastSize || packet.UDPOffset > 0
		s.lastWire, s.lastSize = 0, len(packet.Payload)
		s.packets = append(s.packets, packet.PacketIndex)
	}
	s.lastWire += wire
	// FIN or reset can contribute an original packet without new bytes.
	if start == end {
		return
	}
	s.contributions = append(s.contributions, quicStreamContribution{packet.PacketIndex, start, end})
	prefix := 0
	if len(s.progress) > 0 {
		prefix = s.progress[len(s.progress)-1].end
	}
	if start > prefix {
		heap.Push(&s.waiting, quicObservedRange{start, end})
		return
	}
	if end <= prefix {
		return
	}
	for len(s.waiting) > 0 && s.waiting[0].start <= end {
		r := heap.Pop(&s.waiting).(quicObservedRange)
		end = max(end, r.end)
	}
	s.progress = append(s.progress, quicStreamProgress{step, end})
}

func (s *quicLocatedStream) arrival(end int) int {
	i := sort.Search(len(s.progress), func(i int) bool { return s.progress[i].end >= end })
	return s.progress[i].step
}
func (s *quicLocatedStream) prefixAt(step int) int {
	if s == nil {
		return 0
	}
	i := sort.Search(len(s.progress), func(i int) bool { return s.progress[i].step > step })
	if i == 0 {
		return 0
	}
	return s.progress[i-1].end
}

// locateQUICStreams accepts the capture-ordered packets for one direction of
// one keyed connection. Packet indices include repeated bytes and terminal
// frames. Contributions retain the original data ranges for narrower lookups.
func locateQUICStreams(packets []QUIC1RTTPacket) ([]quicLocatedStream, error) {
	if len(packets) > MaxQUICStreamPackets {
		return nil, ErrQUICLimit
	}
	payloads := make([][]byte, len(packets))
	for i := range packets {
		payloads[i] = packets[i].Payload
	}
	locations := make(map[uint64]*quicLocatedStream)
	step := 0
	streams, err := reassembleQUICStreams(payloads, func(i int, id uint64, start, end, wire int) {
		loc := locations[id]
		if loc == nil {
			loc = new(quicLocatedStream)
			locations[id] = loc
		}
		step++
		loc.observe(packets[i], start, end, wire, step)
	})
	if err != nil {
		return nil, err
	}
	out := make([]quicLocatedStream, 0, len(streams))
	for _, stream := range streams {
		s := locations[stream.ID]
		s.stream = stream
		s.shared = s.shared || s.lastWire < s.lastSize
		s.waiting = nil
		out = append(out, *s)
	}
	return out, nil
}
