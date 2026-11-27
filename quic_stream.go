package pcap

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
)

// Directional limits for [ReassembleQUIC1RTTStreams].
const (
	MaxQUICStreamPackets    = 256
	MaxQUICStreamInputBytes = 8 << 20
	MaxQUICStreamFrames     = 16_384
	MaxQUICStreams          = 1024
	MaxQUICStreamBytes      = 4 << 20
)

// QUICStream holds the contiguous prefix of one sending direction of a QUIC
// stream. Data starts at offset zero and belongs to the caller. Gap indicates
// that an observed offset or final size extends beyond Data. Complete requires
// a FIN at the end of the prefix and no observed reset. Reset records an
// observed RESET_STREAM from this sender.
type QUICStream struct {
	ID       uint64
	Data     []byte
	Gap      bool
	Complete bool
	Reset    bool
}

// ReassembleQUIC1RTTStreams accepts complete authenticated 1-RTT payloads from
// [QUIC1RTTDecoder.Open] for one connection and one sender. Each slice element
// is one packet payload, in any order. Keep the two sending directions in
// separate calls, including for bidirectional stream IDs.
//
// Streams are returned in ascending ID order. Identical retransmissions
// contribute bytes once. Conflicting overlaps, inconsistent final sizes and
// malformed or unsupported frames return [ErrInvalidQUIC] with no output.
// Exceeding a directional limit or the ACK range cap returns [ErrQUICLimit].
func ReassembleQUIC1RTTStreams(packets [][]byte) ([]QUICStream, error) {
	return reassembleQUICStreams(packets, nil)
}

// observe receives each validated STREAM or RESET_STREAM frame in capture
// order, including its encoded size inside the authenticated packet.
func reassembleQUICStreams(packets [][]byte, observe func(packet int, stream uint64, start, end, wire int)) ([]QUICStream, error) {
	if len(packets) > MaxQUICStreamPackets {
		return nil, ErrQUICLimit
	}
	inputBytes := 0
	for _, packet := range packets {
		if len(packet) == 0 {
			return nil, ErrInvalidQUIC
		}
		if len(packet) > maxQUICUDPPayloadBytes || len(packet) > MaxQUICStreamInputBytes-inputBytes {
			return nil, ErrQUICLimit
		}
		inputBytes += len(packet)
	}
	frames := 0
	streams := make(map[uint64]*quicStreamInput)
	for packetIndex, packet := range packets {
		r := quicFrameReader{data: packet}
		for len(r.data) > 0 && r.err == nil {
			before := len(r.data)
			typ := r.data[0]
			r.data = r.data[1:]
			if typ != 0x04 && (typ < 0x08 || typ > 0x0f) {
				r.skip(typ)
				continue
			}
			frames++
			if frames > MaxQUICStreamFrames {
				return nil, ErrQUICLimit
			}
			id, offset, data, final, reset := r.streamFrame(typ)
			if r.err != nil {
				break
			}
			s := streams[id]
			if s == nil {
				if len(streams) == MaxQUICStreams {
					return nil, ErrQUICLimit
				}
				s = new(quicStreamInput)
				streams[id] = s
			}
			if err := s.add(offset, data, final, reset); err != nil {
				return nil, fmt.Errorf("QUIC stream %d: %w", id, err)
			}
			if observe != nil {
				observe(packetIndex, id, int(offset), int(offset)+len(data), before-len(r.data))
			}
		}
		if r.err != nil {
			return nil, r.err
		}
	}
	if len(streams) == 0 {
		return nil, nil
	}
	out := make([]QUICStream, 0, len(streams))
	for id, s := range streams {
		data, err := s.prefix()
		if err != nil {
			return nil, fmt.Errorf("QUIC stream %d: %w", id, err)
		}
		gap := uint64(len(data)) < s.end
		out = append(out, QUICStream{ID: id, Data: data, Gap: gap, Complete: s.hasFinal && !gap && !s.reset, Reset: s.reset})
	}
	slices.SortFunc(out, func(a, b QUICStream) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

type quicStreamChunk struct {
	offset uint64
	data   []byte
}

type quicStreamInput struct {
	chunks   []quicStreamChunk
	end      uint64 // highest observed end or the final size, once known
	hasFinal bool
	reset    bool
}

func (s *quicStreamInput) add(offset uint64, data []byte, final, reset bool) error {
	end := offset + uint64(len(data))
	if end >= quicPacketNumberLimit {
		return ErrInvalidQUIC
	}
	if end > MaxQUICStreamBytes {
		return ErrQUICLimit
	}
	if (s.hasFinal && (end > s.end || final && end != s.end)) || (final && end < s.end) {
		return fmt.Errorf("%w: inconsistent final size", ErrInvalidQUIC)
	}
	s.end = max(s.end, end)
	s.hasFinal = s.hasFinal || final
	s.reset = s.reset || reset
	if len(data) > 0 {
		s.chunks = append(s.chunks, quicStreamChunk{offset: offset, data: data})
	}
	return nil
}

func (s *quicStreamInput) prefix() ([]byte, error) {
	slices.SortFunc(s.chunks, func(a, b quicStreamChunk) int { return cmp.Compare(a.offset, b.offset) })
	var prefixLen uint64
	for _, c := range s.chunks {
		if c.offset > prefixLen {
			break
		}
		prefixLen = max(prefixLen, c.offset+uint64(len(c.data)))
	}
	var prefix, run []byte
	if prefixLen > 0 {
		run = make([]byte, 0, prefixLen)
	}
	var start, end uint64
	for _, c := range s.chunks {
		if c.offset > end {
			// Keep the prefix and check overlaps in later runs without allocating
			// space for the missing bytes between runs.
			if start == 0 {
				prefix, run = run, nil
			} else {
				run = run[:0]
			}
			start, end = c.offset, c.offset
		}
		overlap := min(end-c.offset, uint64(len(c.data)))
		at := c.offset - start
		if !bytes.Equal(run[at:at+overlap], c.data[:overlap]) {
			return nil, fmt.Errorf("%w: conflicting stream bytes at offset %d", ErrInvalidQUIC, c.offset)
		}
		run = append(run, c.data[overlap:]...)
		end = start + uint64(len(run))
	}
	if start == 0 {
		return run, nil
	}
	return prefix, nil
}

// quicFrameReader consumes bytes within one authenticated packet. Errors are
// sticky so a truncated field cannot be interpreted as part of another frame.
type quicFrameReader struct {
	data []byte
	err  error
}

func (r *quicFrameReader) varint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n, ok := ReadQUICVarint(r.data)
	if !ok {
		r.err = ErrInvalidQUIC
		return 0
	}
	r.data = r.data[n:]
	return v
}

func (r *quicFrameReader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.data)) {
		r.err = ErrInvalidQUIC
		return nil
	}
	data := r.data[:n]
	r.data = r.data[n:]
	return data
}

func (r *quicFrameReader) streamFrame(typ byte) (id, offset uint64, data []byte, final, reset bool) {
	id = r.varint()
	if typ == 0x04 { // RESET_STREAM carries the final size in place of data.
		r.varint() // Application error code.
		return id, r.varint(), nil, true, true
	}
	if typ&0x04 != 0 {
		offset = r.varint()
	}
	length := uint64(len(r.data))
	if typ&0x02 != 0 {
		length = r.varint()
	}
	return id, offset, r.take(length), typ&0x01 != 0, false
}

func (r *quicFrameReader) skipVarints(n int) {
	for i := 0; i < n && r.err == nil; i++ {
		r.varint()
	}
}

// Skip the RFC 9000 control frames and RFC 9221 DATAGRAM frames. The known
// frame types all require single-byte encodings.
func (r *quicFrameReader) skip(typ byte) {
	switch typ {
	case 0x00, 0x01, 0x1e: // PADDING, PING, HANDSHAKE_DONE.
	case 0x02, 0x03: // ACK and ACK_ECN.
		r.skipVarints(2)
		ranges := r.varint()
		if ranges > 256 {
			r.err = ErrQUICLimit
			return
		}
		r.skipVarints(1 + 2*int(ranges))
		if typ == 0x03 {
			r.skipVarints(3)
		}
	case 0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19:
		r.varint() // MAX_DATA, MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED, RETIRE_CONNECTION_ID.
	case 0x05, 0x11, 0x15: // STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED.
		r.skipVarints(2)
	case 0x06, 0x1d: // CRYPTO or CONNECTION_CLOSE with an application error.
		r.varint()
		r.take(r.varint())
	case 0x07, 0x31: // NEW_TOKEN or DATAGRAM with a length.
		r.take(r.varint())
	case 0x18: // NEW_CONNECTION_ID.
		r.newConnectionID()
	case 0x1a, 0x1b: // PATH_CHALLENGE, PATH_RESPONSE.
		r.take(8)
	case 0x1c: // CONNECTION_CLOSE with a transport error.
		r.skipVarints(2)
		r.take(r.varint())
	case 0x30: // DATAGRAM without a length consumes the rest of the packet.
		r.data = nil
	default:
		r.err = fmt.Errorf("%w: unsupported QUIC frame type byte %#x", ErrInvalidQUIC, typ)
	}
}
