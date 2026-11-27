package pcap

import (
	"errors"

	"github.com/cawalch/go-pcap/internal/hpackwire"
)

func readHPACKInteger(p *hpackwire.Input, mask byte) (uint64, error) {
	n, err := p.ReadInteger(mask)
	if err != nil {
		return 0, ErrInvalidHTTP
	}
	return n, nil
}

func readHPACKString(p *hpackwire.Input) (string, error) {
	s, err := p.ReadString(127, MaxHTTPHeaderLineBytes)
	if err == nil {
		return s, nil
	}
	if errors.Is(err, hpackwire.ErrStringLimit) {
		return "", ErrHTTPLimit
	}
	return "", ErrInvalidHTTP
}

type hpackTable struct {
	entries     []HTTPHeader
	size, limit int
}

func (t *hpackTable) entry(i uint64) (HTTPHeader, error) {
	if i == 0 {
		return HTTPHeader{}, ErrInvalidHTTP
	}
	if i <= uint64(len(hpackStatic)) {
		return hpackStatic[i-1], nil
	}
	i -= uint64(len(hpackStatic))
	if i > uint64(len(t.entries)) {
		return HTTPHeader{}, ErrInvalidHTTP
	}
	return t.entries[len(t.entries)-int(i)], nil
}
func (t *hpackTable) evict(limit int) {
	for t.size > limit && len(t.entries) > 0 {
		f := t.entries[0]
		t.size -= len(f.Name) + len(f.Value) + 32
		t.entries[0] = HTTPHeader{}
		t.entries = t.entries[1:]
	}
}
func (t *hpackTable) decode(data []byte, remaining *int) (HTTP2HeaderBlock, error) {
	var block HTTP2HeaderBlock
	// Empty blocks also occupy a result slot (for example a trailer).
	const blockOverhead = 128
	if *remaining < blockOverhead {
		return block, ErrHTTPLimit
	}
	*remaining -= blockOverhead
	p := hpackwire.Input(data)
	for len(p) > 0 {
		tag := p[0]
		var field HTTPHeader
		switch {
		case tag&128 != 0:
			index, err := readHPACKInteger(&p, 127)
			if err != nil {
				return block, err
			}
			field, err = t.entry(index)
			if err != nil {
				return block, err
			}
		case tag&224 == 32:
			if len(block.Headers) > 0 {
				return block, ErrInvalidHTTP
			}
			limit, err := readHPACKInteger(&p, 31)
			if err != nil {
				return block, err
			}
			if limit > MaxHTTP2DynamicTableBytes {
				return block, ErrHTTPLimit
			}
			t.limit = int(limit)
			t.evict(t.limit)
			continue
		default:
			indexed := tag&64 != 0
			mask := byte(15)
			if indexed {
				mask = 63
			}
			index, err := readHPACKInteger(&p, mask)
			if err != nil {
				return block, err
			}
			if index == 0 {
				field.Name, err = readHPACKString(&p)
			} else {
				field, err = t.entry(index)
			}
			if err != nil {
				return block, err
			}
			field.Value, err = readHPACKString(&p)
			if err != nil {
				return block, err
			}
			if indexed {
				n := len(field.Name) + len(field.Value) + 32
				t.evict(t.limit - n)
				if n <= t.limit {
					if len(t.entries) >= MaxHTTP2DynamicTableEntries {
						return block, ErrHTTPLimit
					}
					t.entries = append(t.entries, field)
					t.size += n
				}
			}
		}
		cost := 32 + len(field.Name) + len(field.Value)
		if len(block.Headers) >= MaxHTTPHeaders || cost > *remaining {
			return block, ErrHTTPLimit
		}
		*remaining -= cost
		if block.Headers == nil {
			// Most requests start with several indexed pseudo-headers. Each
			// remaining byte can represent at most one additional field.
			block.Headers = make([]HTTPHeader, 0, 1+min(len(p), 3))
		}
		block.Headers = append(block.Headers, field)
		switch field.Name {
		case ":method":
			block.Method = field.Value
		case ":scheme":
			block.Scheme = field.Value
		case ":authority":
			block.Authority = field.Value
		case ":path":
			block.Path = field.Value
		case ":status":
			block.Status = field.Value
		}
	}
	return block, nil
}
