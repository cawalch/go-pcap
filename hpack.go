package pcap

import (
	"errors"
	"io"
	"math"
	"sync"
)

// The Huffman alphabet is a fixed prefix code. Zero denotes a missing branch,
// including the reserved EOS symbol. Each leaf stores symbol + 1.
type hpackNode struct {
	next   [2]int
	symbol int
}

var hpackTree = sync.OnceValue(func() []hpackNode {
	tree := make([]hpackNode, 1, 513)
	for sym, code := range huffmanCodes {
		node := 0
		for shift := int(huffmanCodeLen[sym]) - 1; shift >= 0; shift-- {
			bit := (code >> shift) & 1
			if tree[node].next[bit] == 0 {
				tree[node].next[bit] = len(tree)
				tree = append(tree, hpackNode{})
			}
			node = tree[node].next[bit]
		}
		tree[node].symbol = sym + 1
	}
	return tree
})

func hpackHuffman(src []byte) (string, error) {
	tree := hpackTree()
	node, tail := 0, 0
	ones := true
	var scratch [64]byte
	out := scratch[:0]
	if len(src) > len(scratch) {
		out = make([]byte, 0, min(len(src), MaxHTTPHeaderLineBytes))
	}
	for _, b := range src {
		for shift := 7; shift >= 0; shift-- {
			bit := (b >> shift) & 1
			node = tree[node].next[bit]
			if node == 0 {
				return "", ErrInvalidHTTP
			}
			tail++
			ones = ones && bit == 1
			if sym := tree[node].symbol; sym != 0 {
				if len(out) == MaxHTTPHeaderLineBytes {
					return "", ErrHTTPLimit
				}
				out = append(out, byte(sym-1))
				node, tail, ones = 0, 0, true
			}
		}
	}
	if tail > 7 || !ones {
		return "", ErrInvalidHTTP
	}
	return string(out), nil
}

type hpackInput []byte

func (p *hpackInput) integer(mask byte) (uint64, error) {
	n, err := p.prefixedInteger(mask)
	if err != nil {
		return 0, ErrInvalidHTTP
	}
	return n, nil
}

// QPACK shares HPACK's integer and string wire formats and also needs to
// distinguish an incomplete encoder instruction at the end of a capture.
func (p *hpackInput) prefixedInteger(mask byte) (uint64, error) {
	if len(*p) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := uint64((*p)[0] & mask)
	*p = (*p)[1:]
	if n < uint64(mask) {
		return n, nil
	}
	for shift := uint(0); shift < 64; shift += 7 {
		if len(*p) == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		b := (*p)[0]
		*p = (*p)[1:]
		v := uint64(b & 127)
		if v > (math.MaxUint64-n)>>shift {
			return 0, ErrInvalidHTTP
		}
		n += v << shift
		if b < 128 {
			return n, nil
		}
	}
	return 0, ErrInvalidHTTP
}
func (p *hpackInput) text() (string, error) {
	s, err := p.prefixedString(127)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		return "", ErrInvalidHTTP
	}
	return s, err
}

func (p *hpackInput) prefixedString(mask byte) (string, error) {
	if len(*p) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	coded := (*p)[0]&(mask+1) != 0
	n, err := p.prefixedInteger(mask)
	if err != nil {
		return "", err
	}
	if n > uint64(len(*p)) {
		return "", io.ErrUnexpectedEOF
	}
	data := (*p)[:n]
	*p = (*p)[n:]
	if coded {
		return hpackHuffman(data)
	}
	if n > MaxHTTPHeaderLineBytes {
		return "", ErrHTTPLimit
	}
	return string(data), nil
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
	p := hpackInput(data)
	for len(p) > 0 {
		tag := p[0]
		var field HTTPHeader
		switch {
		case tag&128 != 0:
			index, err := p.integer(127)
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
			limit, err := p.integer(31)
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
			index, err := p.integer(mask)
			if err != nil {
				return block, err
			}
			if index == 0 {
				field.Name, err = p.text()
			} else {
				field, err = t.entry(index)
			}
			if err != nil {
				return block, err
			}
			field.Value, err = p.text()
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
