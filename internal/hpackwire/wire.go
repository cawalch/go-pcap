// Package hpackwire decodes the wire integers and strings shared by HPACK and
// QPACK.
package hpackwire

import (
	"errors"
	"io"
	"math"
	"sync"
)

var (
	// ErrInvalidEncoding reports an overflowing integer or malformed Huffman data.
	ErrInvalidEncoding = errors.New("invalid HPACK or QPACK wire encoding")
	// ErrStringLimit reports a decoded string longer than the caller's limit.
	ErrStringLimit = errors.New("HPACK or QPACK string exceeds limit")
)

// The Huffman alphabet is a fixed prefix code. Zero denotes a missing branch,
// including the reserved EOS symbol. Each leaf stores symbol + 1.
type huffmanNode struct {
	next   [2]int
	symbol int
}

var huffmanTree = sync.OnceValue(func() []huffmanNode {
	tree := make([]huffmanNode, 1, 513)
	for sym, code := range huffmanCodes {
		node := 0
		for shift := int(huffmanCodeLen[sym]) - 1; shift >= 0; shift-- {
			bit := (code >> shift) & 1
			if tree[node].next[bit] == 0 {
				tree[node].next[bit] = len(tree)
				tree = append(tree, huffmanNode{})
			}
			node = tree[node].next[bit]
		}
		tree[node].symbol = sym + 1
	}
	return tree
})

func decodeHuffman(src []byte, maxBytes int) (string, error) {
	tree := huffmanTree()
	node, tail := 0, 0
	var scratch [64]byte
	out := scratch[:0]
	if len(src) > len(scratch) {
		out = make([]byte, 0, min(len(src), maxBytes))
	}
	for _, b := range src {
		for shift := 7; shift >= 0; shift-- {
			bit := (b >> shift) & 1
			node = tree[node].next[bit]
			if node == 0 {
				return "", ErrInvalidEncoding
			}
			tail++
			if sym := tree[node].symbol; sym != 0 {
				if len(out) == maxBytes {
					return "", ErrStringLimit
				}
				out = append(out, byte(sym-1))
				node, tail = 0, 0
			}
		}
	}
	if tail > 7 {
		return "", ErrInvalidEncoding
	}
	// RFC 7541 section 5.2 permits at most seven padding bits. They must
	// match the all-ones prefix of EOS and are in the final byte.
	if tail != 0 {
		mask := byte(1<<tail - 1)
		if src[len(src)-1]&mask != mask {
			return "", ErrInvalidEncoding
		}
	}
	return string(out), nil
}

// Input is the unconsumed suffix of a compressed header block or encoder stream.
type Input []byte

// ReadInteger consumes a prefixed integer. Mask identifies the low prefix bits.
func (p *Input) ReadInteger(mask byte) (uint64, error) {
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
			return 0, ErrInvalidEncoding
		}
		n += v << shift
		if b < 128 {
			return n, nil
		}
	}
	return 0, ErrInvalidEncoding
}

// ReadString consumes a prefixed string with the Huffman flag above mask.
// The limit applies to decoded bytes. Short input returns [io.ErrUnexpectedEOF].
func (p *Input) ReadString(mask byte, maxBytes int) (string, error) {
	if len(*p) == 0 {
		return "", io.ErrUnexpectedEOF
	}
	coded := (*p)[0]&(mask+1) != 0
	n, err := p.ReadInteger(mask)
	if err != nil {
		return "", err
	}
	if n > uint64(len(*p)) {
		return "", io.ErrUnexpectedEOF
	}
	data := (*p)[:n]
	*p = (*p)[n:]
	if maxBytes < 0 {
		return "", ErrStringLimit
	}
	if coded {
		return decodeHuffman(data, maxBytes)
	}
	if n > uint64(maxBytes) {
		return "", ErrStringLimit
	}
	return string(data), nil
}
