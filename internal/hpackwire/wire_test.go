package hpackwire

import (
	"errors"
	"testing"
)

func TestHuffmanPadding(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want string
		err  error
	}{
		{"no-padding", []byte{0x81, 0xf8}, "&", nil},
		{"seven-bits", []byte{0x84, 0x18, 0xc6, 0x31, 0xff}, "aaaaa", nil},
		{"non-EOS-prefix", []byte{0x84, 0x18, 0xc6, 0x31, 0xfe}, "", ErrInvalidEncoding},
		{"eight-bits", []byte{0x81, 0xff}, "", ErrInvalidEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := Input(tc.wire)
			got, err := in.ReadString(127, 64)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("ReadString = %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
