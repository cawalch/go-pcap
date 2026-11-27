package pcap

import "bytes"

// A prefix walk resolves flow indices and TCP openings before choosing which
// large payloads to fetch. Offsets refer to the original stable capture.
type tlsStreamReader struct {
	budget  scanReadBudget
	size    int64
	pending map[int][]tlsSegmentRead // keyed by TCP opening
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

func (r *tlsStreamReader) complete(opening int, st *flowSegments) error {
	reads := r.pending[opening]
	if len(reads) == 0 {
		return nil
	}
	directions := [2][]TCPSegmentInput{st.client, st.server}
	// A deep tunnel header can leave no transport bytes in the frame prefix.
	// Recover a byte for classification even on a previously empty segment.
	for _, ref := range reads {
		seg := &directions[ref.direction][ref.segment]
		if len(seg.Payload) == 0 {
			seg.Payload = make([]byte, 1)
			if err := readExactAt(&r.budget, seg.Payload, ref.offset, r.size); err != nil {
				return err
			}
		}
	}
	if !possibleTLSOpening(st.client) && !possibleTLSOpening(st.server) {
		st.client, st.server = nil, nil
		return nil
	}
	for _, ref := range reads {
		seg := &directions[ref.direction][ref.segment]
		have := len(seg.Payload)
		if err := r.budget.check(int64(ref.length - have)); err != nil {
			return err
		}
		data := make([]byte, ref.length)
		copy(data, seg.Payload)
		if err := readExactAt(&r.budget, data[have:], ref.offset+int64(have), r.size); err != nil {
			return err
		}
		seg.Payload = data
	}
	return nil
}

// Classify the first TCP sequence byte, which can arrive after later payload.
// TLS handshakes, CONNECT and SOCKS5 are the only accepted opening forms.
// Leave uncertain overlaps crossing a SYN to the ordinary reassembler.
func possibleTLSOpening(segments []TCPSegmentInput) bool {
	var base uint32
	anchored := false
	for i := range segments {
		if segments[i].Flags&TCPFlagSYN != 0 {
			base, anchored = segments[i].Seq+1, true
			break
		}
	}
	var first []byte
	var earliest int32
	for i := range segments {
		seg := &segments[i]
		if len(seg.Payload) == 0 {
			continue
		}
		seq := seg.Seq
		if seg.Flags&TCPFlagSYN != 0 {
			seq++
		}
		if !anchored && first == nil {
			base = seq
		}
		rel := int32(seq - base)
		if anchored && rel < 0 {
			return true
		}
		if first == nil || rel < earliest {
			earliest, first = rel, seg.Payload
		}
	}
	if first == nil || anchored && earliest != 0 {
		return false
	}
	switch first[0] {
	case TLSRecordHandshake, 'C', 5:
		return true
	}
	return false
}
