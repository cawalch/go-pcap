package pcap

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestSafeReaderPrimitives(t *testing.T) {
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 'h', 'i', 0, 'x'}
	r := NewSafeReader(buf)

	if r.Size() != int64(len(buf)) {
		t.Fatalf("Size() = %d, want %d", r.Size(), len(buf))
	}

	u8, err := r.ReadUint8(0)
	if err != nil || u8 != 0x12 {
		t.Fatalf("ReadUint8(0) = (%#x, %v), want (0x12, nil)", u8, err)
	}

	u16LE, err := r.ReadUint16(0)
	if err != nil || u16LE != 0x3412 {
		t.Fatalf("ReadUint16(0) = (%#x, %v), want (0x3412, nil)", u16LE, err)
	}
	u16BE, err := r.ReadUint16BE(0)
	if err != nil || u16BE != 0x1234 {
		t.Fatalf("ReadUint16BE(0) = (%#x, %v), want (0x1234, nil)", u16BE, err)
	}
	u16Order, err := r.ReadUint16Order(0, binary.BigEndian)
	if err != nil || u16Order != 0x1234 {
		t.Fatalf("ReadUint16Order(0, BE) = (%#x, %v), want (0x1234, nil)", u16Order, err)
	}

	u32LE, err := r.ReadUint32(0)
	if err != nil || u32LE != 0x78563412 {
		t.Fatalf("ReadUint32(0) = (%#x, %v), want (0x78563412, nil)", u32LE, err)
	}
	u32BE, err := r.ReadUint32BE(0)
	if err != nil || u32BE != 0x12345678 {
		t.Fatalf("ReadUint32BE(0) = (%#x, %v), want (0x12345678, nil)", u32BE, err)
	}

	u64LE, err := r.ReadUint64(0)
	if err != nil || u64LE != 0xf0debc9a78563412 {
		t.Fatalf("ReadUint64(0) = (%#x, %v), want (0xf0debc9a78563412, nil)", u64LE, err)
	}
	u64BE, err := r.ReadUint64BE(0)
	if err != nil || u64BE != 0x123456789abcdef0 {
		t.Fatalf("ReadUint64BE(0) = (%#x, %v), want (0x123456789abcdef0, nil)", u64BE, err)
	}
	u64Order, err := r.ReadUint64Order(0, binary.BigEndian)
	if err != nil || u64Order != 0x123456789abcdef0 {
		t.Fatalf("ReadUint64Order(0, BE) = (%#x, %v), want (0x123456789abcdef0, nil)", u64Order, err)
	}

	str, err := r.ReadASCIIZ(8, 4)
	if err != nil || str != "hi" {
		t.Fatalf("ReadASCIIZ(8, 4) = (%q, %v), want (\"hi\", nil)", str, err)
	}
	if _, err := r.ReadASCIIZ(8, 2); !errors.Is(err, ErrUnterminatedString) {
		t.Fatalf("ReadASCIIZ(8, 2) err = %v, want ErrUnterminatedString", err)
	}
}

func TestSafeReaderBoundsAndOverflow(t *testing.T) {
	r := NewSafeReader([]byte{1, 2, 3, 4})

	if _, err := r.Slice(-1, 2); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("Slice(-1, 2) err = %v, want ErrOutOfBounds", err)
	}
	if _, err := r.Slice(1, -1); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("Slice(1, -1) err = %v, want ErrOutOfBounds", err)
	}
	if _, err := r.Slice(2, 3); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("Slice(2, 3) err = %v, want ErrOutOfBounds", err)
	}
	if _, err := r.Slice(1, math.MaxInt64); !errors.Is(err, ErrIntegerOverflow) {
		t.Fatalf("Slice(1, MaxInt64) err = %v, want ErrIntegerOverflow", err)
	}
	if r.CheckBounds(1, math.MaxInt64) {
		t.Fatal("CheckBounds(1, MaxInt64) = true, want false")
	}
	if !r.CheckBounds(0, 4) {
		t.Fatal("CheckBounds(0, 4) = false, want true")
	}
}
