package pcap

import (
	"bytes"
	"sort"
)

// A prefix walk resolves flow indices and TCP openings before choosing which
// large payloads to fetch. Offsets refer to the original stable capture.
type tlsStreamReader struct {
	budget  scanReadBudget
	size    int64
	keyed   bool
	sources map[*byte]*tlsRecordSource // keyed by start of the inner TLS stream
	pending map[int][]tlsSegmentRead   // keyed by TCP opening
}

type tlsSegmentRead struct {
	direction, segment int
	offset             int64
	length             int
}

func (r *tlsStreamReader) walk(c *Capture, collect func(PacketRecord, Frame, []byte) error) error {
	if c.PacketCount == 0 {
		return nil
	}
	return c.walkFlowPrefixes(&r.budget, func(pkt PacketRecord, f Frame, frame []byte) error {
		start := int(f.PayloadOffset)
		prefix := frame[start:min(len(frame), start+int(f.PayloadLength))]
		return collect(pkt, f, prefix)
	})
}

func (r *tlsStreamReader) retain(opening, direction, segment int, pkt PacketRecord, f Frame, prefix []byte) []byte {
	if len(prefix) < int(f.PayloadLength) {
		if r.pending == nil {
			r.pending = make(map[int][]tlsSegmentRead)
		}
		r.pending[opening] = append(r.pending[opening], tlsSegmentRead{
			direction, segment, pkt.PayloadOffset + int64(f.PayloadOffset), int(f.PayloadLength),
		})
	}
	// The walk reuses its frame scratch. Keep the bytes it already read so
	// small packets need no subsequent I/O and large ones cost only a tail read.
	return bytes.Clone(prefix)
}

// A span identifies the packet that owns a contiguous range under the normal
// reassembler's overlap rules. Its prefix borrows the initial frame read.
type tlsReadSpan struct {
	end    int
	offset int64
	prefix []byte
}

type tlsReadDirection []tlsReadSpan

func (d tlsReadDirection) size() int {
	if len(d) == 0 {
		return 0
	}
	return d[len(d)-1].end
}

func (r *tlsStreamReader) plan(segments []TCPSegmentInput, refs []tlsSegmentRead, dir int, limit int64) (tlsReadDirection, int64, error) {
	if len(segments) == 0 || limit == 0 {
		return nil, 0, nil
	}
	var shortLengths [8]int
	var shortOffsets [8]int64
	lengths := shortLengths[:min(len(segments), len(shortLengths))]
	offsets := shortOffsets[:len(lengths)]
	if len(segments) > len(lengths) {
		lengths = make([]int, len(segments))
		offsets = make([]int64, len(segments))
	}
	for i := range segments {
		lengths[i] = len(segments[i].Payload)
	}
	for _, ref := range refs {
		if ref.direction == dir {
			lengths[ref.segment], offsets[ref.segment] = ref.length, ref.offset
		}
	}
	var spans tlsReadDirection
	var gapped bool
	_, used, err := assembleTCPRanges(segments, lengths, limit, func(i, end int, seq uint32, gap bool) {
		gapped = gapped || gap
		if gapped {
			return
		}
		seg := &segments[i]
		first := seg.Seq
		if seg.Flags&TCPFlagSYN != 0 {
			first++
		}
		skip := int(seq - first)
		prefix := seg.Payload[min(skip, len(seg.Payload)):]
		spans = append(spans, tlsReadSpan{end, offsets[i] + int64(skip), prefix})
	})
	return spans, used, err
}

// read resolves an interval of the contiguous prefix to disjoint packet
// ranges. Previously retained prefix bytes cost no additional scan I/O.
func (d tlsReadDirection) read(r *tlsStreamReader, dest []byte, start int) error {
	end := start + len(dest)
	i := sort.Search(len(d), func(i int) bool { return d[i].end > start })
	base := 0
	if i > 0 {
		base = d[i-1].end
	}
	for start < end {
		span := &d[i]
		lo, n := start-base, min(end, span.end)-start
		have := copy(dest[:n], span.prefix[min(lo, len(span.prefix)):])
		if have < n {
			if err := readExactAt(&r.budget, dest[have:n], span.offset+int64(lo+have), r.size); err != nil {
				return err
			}
		}
		start, base, dest, i = start+n, span.end, dest[n:], i+1
	}
	return nil
}

func (r *tlsStreamReader) opening(index int, st *flowSegments, budget *tcpFlowBudget, remaining *int64) ([]byte, []byte, error) {
	var dirs [2]tlsReadDirection
	var seeds [2][]byte
	var first [2][8]byte
	for dir, segments := range [2][]TCPSegmentInput{st.client, st.server} {
		side := tcpSide(st.canonical) ^ dir
		spans, used, err := r.plan(segments, r.pending[index], dir, min(*remaining, MaxFlowStreamBytes-budget.bytes[side]))
		if err != nil {
			return nil, nil, err
		}
		// Gaps stop TLS inspection. Every distinct retained sequence byte
		// still counts against this tuple and the capture, including beyond gaps.
		budget.bytes[side] += used
		*remaining -= used
		dirs[dir] = spans
		seeds[dir] = first[dir][:min(len(first[dir]), spans.size())]
		if err := spans.read(r, seeds[dir], 0); err != nil {
			return nil, nil, err
		}
	}
	var inner [2]int
	for dir, seed := range seeds {
		if len(seed) == 0 || seed[0] != 5 && !bytes.HasPrefix(seed, []byte("CONNECT ")) {
			continue
		}
		// Both supported negotiations fit the CONNECT parser's 4096-byte
		// envelope. Let the existing proxy parser decide success and orientation.
		for i, d := range dirs {
			n := min(d.size(), 4096)
			if len(seeds[i]) < n {
				seed := make([]byte, n)
				have := copy(seed, seeds[i])
				if err := d.read(r, seed[have:], have); err != nil {
					return nil, nil, err
				}
				seeds[i] = seed
			}
		}
		peer := 1 - dir
		cl, sv, _, _, _, ok := UnwrapProxyStream(seeds[dir], seeds[peer])
		if ok {
			inner[dir], inner[peer] = len(seeds[dir])-len(cl), len(seeds[peer])-len(sv)
			break
		}
	}
	var data [2][]byte
	for i, d := range dirs {
		b, err := d.handshake(r, seeds[i], inner[i])
		if err != nil {
			return nil, nil, err
		}
		data[i] = b
	}
	return data[0], data[1], nil
}

// Allocate the same logical prefix the byte parser sees. Only its seed is
// initialized here. The record parser fills inspected ranges on demand.
func (d tlsReadDirection) handshake(r *tlsStreamReader, seed []byte, inner int) ([]byte, error) {
	n := d.size()
	if n-inner < 6 {
		return seed, nil
	}
	if len(seed)-inner < 6 {
		start := len(seed)
		seed = append(seed, make([]byte, inner+6-start)...)
		if err := d.read(r, seed[start:], start); err != nil {
			return nil, err
		}
	}
	if !hasTLSHandshakeStart(seed[inner:]) {
		return seed, nil
	}
	if !r.keyed {
		n = min(n, inner+(MaxTLSHandshakeRecords+1)*(5+MaxTLSRecordBytes))
	}
	if len(seed) >= n {
		return seed[:n], nil
	}
	data := make([]byte, n)
	have := copy(data, seed)
	if r.sources == nil {
		r.sources = make(map[*byte]*tlsRecordSource)
	}
	r.sources[&data[inner]] = &tlsRecordSource{reader: r, dir: d, inner: inner, data: data[inner:], through: have - inner}
	return data, nil
}

// The plaintext parser visits ranges in increasing order. For a capture with
// embedded keys, remember the skipped intervals until the ClientHello random
// and selected suite establish which directions need actual ciphertext.
type tlsRecordSource struct {
	reader  *tlsStreamReader
	dir     tlsReadDirection
	inner   int
	data    []byte
	through int
	skipped [][2]int
	err     error
}

func (r *tlsStreamReader) source(data []byte) *tlsRecordSource {
	if r == nil || len(data) == 0 {
		return nil
	}
	return r.sources[&data[0]]
}

func (s *tlsRecordSource) fill(start, end int) error {
	if s == nil || end <= s.through {
		return nil
	}
	start = max(start, s.through)
	if s.reader.keyed && start > s.through {
		s.skipped = append(s.skipped, [2]int{s.through, start})
	}
	s.err = s.dir.read(s.reader, s.data[start:end], s.inner+start)
	s.through = end
	return s.err
}

// fillProtected materializes a range for a matched handshake secret, including
// ciphertext skipped by the earlier plaintext pass. Requests are monotonic.
func (s *tlsRecordSource) fillProtected(start, end int) error {
	for len(s.skipped) > 0 && start >= s.skipped[0][1] {
		s.skipped = s.skipped[1:]
	}
	for _, span := range s.skipped {
		lo, hi := max(start, span[0]), min(end, span[1])
		if lo < hi {
			if err := s.dir.read(s.reader, s.data[lo:hi], s.inner+lo); err != nil {
				s.err = err
				return err
			}
		}
		if end <= span[1] {
			break
		}
	}
	return s.fill(start, end)
}
