package pcap

import (
	"errors"
	"fmt"
	"io"
)

// Directional QPACK resource limits for one connection. A table entry costs
// at least 32 bytes. Each queued section is decoded at most once.
const (
	MaxQPACKTableBytes      = 64 << 10
	MaxQPACKBlockedSections = 64
	MaxQPACKBlockedBytes    = 256 << 10
)

// QPACKSectionInput locates one complete compressed field section. Data starts
// at Offset in StreamID. EncoderOffset is the number of contiguous encoder
// stream bytes available at the section's arrival, including the stream type.
type QPACKSectionInput struct {
	StreamID      uint64
	Offset        int
	Data          []byte
	EncoderOffset int
}

// QPACKSectionState describes the outcome of decoding one field section.
type QPACKSectionState uint8

const (
	QPACKDecoded QPACKSectionState = iota + 1
	QPACKBlocked
	QPACKMalformed
	QPACKLimited
)

// QPACKFieldSection identifies the source range and decoded fields in wire
// order. Only QPACKDecoded has usable Headers. RequiredInsertCount is the
// absolute number of insertions required when the prefix could be decoded.
// EncoderOffset is the end of the contiguous encoder prefix in effect when
// a dynamic section decoded. It can include instructions for other sections.
// Static sections and sections without decoded fields have zero EncoderOffset.
type QPACKFieldSection struct {
	StreamID            uint64
	Offset, Length      int
	State               QPACKSectionState
	RequiredInsertCount uint64
	EncoderOffset       int
	Headers             []HTTPHeader
}

// DecodeQPACKSections decodes complete field sections from one sending
// direction of a known HTTP/3 connection in observed arrival order. Supply the
// sender's QPACK encoder stream and its peer's advertised maximum table
// capacity (zero by default). An empty encoder supplies no instructions.
// EncoderOffset must be nondecreasing. Blocked sections resume when the
// required insert arrives, before a later instruction can evict that entry.
//
// A gap leaves dependent sections blocked. Malformed and oversized field
// sections carry their own state. Invalid inputs or encoder instructions
// return [ErrInvalidHTTP3]; connection-wide input or encoder limits return
// [ErrHTTP3Limit]. On those errors the function returns no rows.
func DecodeQPACKSections(encoder QUICStream, maxTableCapacity uint64, sections []QPACKSectionInput) ([]QPACKFieldSection, error) {
	if len(sections) > MaxQUICStreamFrames || len(encoder.Data) > MaxQUICStreamBytes {
		return nil, ErrHTTP3Limit
	}
	if maxTableCapacity >= 1<<62 {
		return nil, ErrInvalidHTTP3
	}
	total, last := len(encoder.Data), 0
	for _, in := range sections {
		if in.StreamID >= 1<<62 || in.StreamID&3 == 1 || in.StreamID&3 == 2 || in.Offset < 0 || in.Offset > MaxQUICStreamBytes ||
			len(in.Data) > MaxQUICStreamBytes-in.Offset || in.EncoderOffset < last || in.EncoderOffset > len(encoder.Data) {
			return nil, ErrInvalidHTTP3
		}
		if len(in.Data) > MaxQUICStreamInputBytes-total {
			return nil, ErrHTTP3Limit
		}
		total += len(in.Data)
		last = in.EncoderOffset
	}
	off := 0
	if len(encoder.Data) != 0 {
		if encoder.ID >= 1<<62 || encoder.ID&2 == 0 {
			return nil, ErrInvalidHTTP3
		}
		typ, size, ok := ReadQUICVarint(encoder.Data)
		switch {
		case !ok && (!encoder.Complete || encoder.Gap || encoder.Reset):
			off = len(encoder.Data)
		case !ok || typ != 2:
			return nil, ErrInvalidHTTP3
		default:
			off = size
		}
	}
	scan := qpackScan{max: maxTableCapacity, remaining: MaxHTTP2DecodedHeaderBytes, sections: sections, rows: make([]QPACKFieldSection, len(sections))}
	for n := 0; off < len(encoder.Data); n++ {
		if n == MaxQUICStreamFrames {
			return nil, ErrHTTP3Limit
		}
		p := hpackInput(encoder.Data[off:])
		inst, err := scan.instruction(&p)
		if err != nil && errors.Is(err, io.ErrUnexpectedEOF) && (!encoder.Complete || encoder.Gap || encoder.Reset) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrHTTPLimit) {
				return nil, ErrHTTP3Limit
			}
			return nil, fmt.Errorf("%w: QPACK encoder instruction at offset %d", ErrInvalidHTTP3, off)
		}
		off = len(encoder.Data) - len(p)
		scan.receiveBefore(off)
		scan.encoderEnd = off
		if err := scan.apply(inst); err != nil {
			return nil, err
		}
	}
	scan.receiveBefore(len(encoder.Data) + 1)
	return scan.rows, nil
}

type qpackScan struct {
	table                                 hpackTable
	max, inserts                          uint64
	remaining, next, blocked, queuedBytes int
	encoderEnd                            int
	sections                              []QPACKSectionInput
	rows                                  []QPACKFieldSection
	pending                               map[uint64][]qpackPending
}

type qpackPending struct {
	row  int
	base uint64
	body hpackInput
}

type qpackInstruction struct {
	resize   bool
	capacity uint64
	field    HTTPHeader
}

func (s *qpackScan) instruction(p *hpackInput) (in qpackInstruction, err error) {
	tag := (*p)[0]
	if s.max == 0 {
		return in, ErrInvalidHTTP3
	}
	switch {
	case tag&0x80 != 0:
		idx, err := p.prefixedInteger(63)
		if err != nil {
			return in, err
		}
		in.field, err = s.relative(idx, s.inserts, tag&0x40 != 0)
		if err != nil {
			return in, err
		}
		in.field.Value, err = p.prefixedString(127)
		return in, err
	case tag&0x40 != 0:
		in.field.Name, err = p.prefixedString(31)
		if err != nil {
			return in, err
		}
		in.field.Value, err = p.prefixedString(127)
	case tag&0x20 != 0:
		in.resize = true
		in.capacity, err = p.prefixedInteger(31)
	default:
		var idx uint64
		idx, err = p.prefixedInteger(31)
		if err == nil {
			in.field, err = s.relative(idx, s.inserts, false)
		}
	}
	return in, err
}

func (s *qpackScan) apply(in qpackInstruction) error {
	if in.resize {
		if in.capacity > s.max {
			return ErrInvalidHTTP3
		}
		if in.capacity > MaxQPACKTableBytes {
			return ErrHTTP3Limit
		}
		s.table.limit = int(in.capacity)
		s.table.evict(s.table.limit)
		return nil
	}
	size := len(in.field.Name) + len(in.field.Value) + 32
	if size > s.table.limit {
		return ErrInvalidHTTP3
	}
	s.table.evict(s.table.limit - size)
	s.table.entries = append(s.table.entries, in.field)
	s.table.size += size
	s.inserts++
	for _, waiting := range s.pending[s.inserts] {
		s.blocked--
		s.queuedBytes -= s.rows[waiting.row].Length
		s.decode(waiting)
	}
	delete(s.pending, s.inserts)
	return nil
}

func (s *qpackScan) absolute(index uint64) (HTTPHeader, error) {
	if index >= s.inserts || s.inserts-index > uint64(len(s.table.entries)) {
		return HTTPHeader{}, ErrInvalidHTTP3
	}
	return s.table.entries[len(s.table.entries)-int(s.inserts-index)], nil
}

func (s *qpackScan) relative(idx, base uint64, static bool) (HTTPHeader, error) {
	if static {
		if idx >= uint64(len(qpackStatic)) {
			return HTTPHeader{}, ErrInvalidHTTP3
		}
		return qpackStatic[idx], nil
	}
	if idx >= base {
		return HTTPHeader{}, ErrInvalidHTTP3
	}
	return s.absolute(base - 1 - idx)
}

// RFC 9204 section 4.5.1.1 reconstructs the absolute count at arrival, even
// when the section will wait for an encoder instruction.
func (s *qpackScan) required(encoded uint64) (uint64, bool) {
	if encoded == 0 {
		return 0, true
	}
	entries := s.max / 32
	full := 2 * entries
	if encoded > full {
		return 0, false
	}
	maxValue := s.inserts + entries
	count := maxValue/full*full + encoded - 1
	if count > maxValue {
		if count <= full {
			return 0, false
		}
		count -= full
	}
	return count, count != 0
}

func (s *qpackScan) receiveBefore(encoderEnd int) {
	for s.next < len(s.sections) && s.sections[s.next].EncoderOffset < encoderEnd {
		i := s.next
		s.next++
		in := &s.sections[i]
		row := &s.rows[i]
		*row = QPACKFieldSection{StreamID: in.StreamID, Offset: in.Offset, Length: len(in.Data), State: QPACKMalformed}
		if len(in.Data) > MaxHTTP2HeaderBlockBytes {
			row.State = QPACKLimited
			continue
		}
		p := hpackInput(in.Data)
		enc, err := p.prefixedInteger(255)
		if err != nil || len(p) == 0 {
			continue
		}
		count, ok := s.required(enc)
		if !ok {
			continue
		}
		row.RequiredInsertCount = count
		negative := p[0]&128 != 0
		delta, err := p.prefixedInteger(127)
		if err != nil || delta >= 1<<62 || negative && delta >= count {
			continue
		}
		base := count + delta
		if negative {
			base = count - delta - 1
		}
		waiting := qpackPending{row: i, base: base, body: p}
		if count <= s.inserts {
			s.decode(waiting)
			continue
		}
		if s.blocked == MaxQPACKBlockedSections || len(in.Data) > MaxQPACKBlockedBytes-s.queuedBytes {
			row.State = QPACKLimited
			continue
		}
		row.State = QPACKBlocked
		if s.pending == nil {
			s.pending = make(map[uint64][]qpackPending)
		}
		s.pending[count] = append(s.pending[count], waiting)
		s.blocked++
		s.queuedBytes += len(in.Data)
	}
}

func (s *qpackScan) decode(section qpackPending) {
	row := &s.rows[section.row]
	row.State = QPACKMalformed
	p := section.body
	var headers []HTTPHeader
	var highest uint64
	for len(p) > 0 {
		field, referenced, err := s.field(&p, section.base, row.RequiredInsertCount)
		if err != nil {
			if errors.Is(err, ErrHTTPLimit) {
				row.State = QPACKLimited
			}
			return
		}
		highest = max(highest, referenced)
		cost := len(field.Name) + len(field.Value) + 32
		if len(headers) == MaxHTTPHeaders || cost > s.remaining {
			row.State = QPACKLimited
			return
		}
		s.remaining -= cost
		headers = append(headers, field)
	}
	if highest == row.RequiredInsertCount {
		row.State, row.Headers = QPACKDecoded, headers
		if highest != 0 {
			row.EncoderOffset = s.encoderEnd
		}
	}
}

func (s *qpackScan) field(p *hpackInput, base, required uint64) (field HTTPHeader, referenced uint64, err error) {
	tag := (*p)[0]
	var mask byte
	var static, post, literal bool
	switch {
	case tag&128 != 0:
		mask, static = 63, tag&64 != 0
	case tag&64 != 0:
		mask, static, literal = 15, tag&16 != 0, true
	case tag&32 != 0:
		field.Name, err = p.prefixedString(7)
		if err == nil {
			field.Value, err = p.prefixedString(127)
		}
		return field, 0, err
	case tag&16 != 0:
		mask, post = 15, true
	default:
		mask, post, literal = 7, true, true
	}
	idx, err := p.prefixedInteger(mask)
	if err != nil {
		return field, 0, err
	}
	switch {
	case static:
		field, err = s.relative(idx, 0, true)
	case post:
		if base >= required || idx >= required-base {
			return field, 0, ErrInvalidHTTP3
		}
		referenced = base + idx + 1
		field, err = s.absolute(referenced - 1)
	default:
		if idx >= base || base-idx > required {
			return field, 0, ErrInvalidHTTP3
		}
		referenced = base - idx
		field, err = s.absolute(referenced - 1)
	}
	if err == nil && literal {
		field.Value, err = p.prefixedString(127)
	}
	return field, referenced, err
}
