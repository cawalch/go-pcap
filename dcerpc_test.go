package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"
)

func TestParseDCERPCContexts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
		kind  DCERPCPacketType
	}{
		{"little-endian bind", binary.LittleEndian, DCERPCBind},
		{"big-endian alter context", binary.BigEndian, DCERPCAlterContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := dcerpcTestPacket(tc.order, tc.kind, 3, dcerpcTestBindBody(tc.order, 2))
			msg, err := ParseDCERPC(wire)
			if err != nil {
				t.Fatal(err)
			}
			clear(wire)
			want := []DCERPCContext{
				{0, "11223344-5566-7788-99aa-bbccddeeff00", 0x1234, 0x5678},
				{1, "11223344-5566-7788-99aa-bbccddeeff00", 0x1234, 0x5678},
			}
			if msg.PacketType != tc.kind || msg.Flags != 3 || msg.CallID != 0x01234567 ||
				int(msg.FragmentLength) != len(wire) || !slices.Equal(msg.Contexts, want) {
				t.Fatalf("got %+v, want %v", msg, want)
			}
		})
	}
}

func TestParseDCERPCCall(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		body := make([]byte, 8+16)
		order.PutUint16(body[4:6], 0x1234)
		order.PutUint16(body[6:8], 0x4567)
		wire := dcerpcTestPacket(order, DCERPCRequest, 0x81, body)
		// Add authentication padding, the fixed trailer, and an opaque token.
		wire = append(wire, 0, 0, 0, 0, 1, 5, 4, 0, 0, 0, 0, 0, 0xaa, 0xbb)
		order.PutUint16(wire[8:10], uint16(len(wire)))
		order.PutUint16(wire[10:12], 2)
		following := dcerpcTestPacket(order, DCERPCResponse, 3, body[:8])
		msg, err := ParseDCERPC(append(bytes.Clone(wire), following...))
		if err != nil || int(msg.FragmentLength) != len(wire) || msg.PacketType != DCERPCRequest ||
			msg.Flags != 0x81 || msg.ContextID != 0x1234 || msg.Opnum != 0x4567 || len(msg.Contexts) != 0 {
			t.Fatalf("request: %+v, %v", msg, err)
		}
		response, err := ParseDCERPC(following)
		if err != nil || response.PacketType != DCERPCResponse || response.ContextID != 0x1234 ||
			response.Opnum != 0 || response.CallID != msg.CallID {
			t.Fatalf("response: %+v, %v", response, err)
		}
	}
}

func TestParseDCERPCBindAck(t *testing.T) {
	order := binary.LittleEndian
	// Three advertised address bytes, three alignment bytes, and one result.
	body := make([]byte, 16+4+24)
	order.PutUint16(body[8:10], 3)
	copy(body[10:13], "42\x00")
	body[16] = 1
	wire := dcerpcTestPacket(order, DCERPCBindAck, 3, body)
	msg, err := ParseDCERPC(wire)
	if err != nil || msg.PacketType != DCERPCBindAck || len(msg.Contexts) != 0 {
		t.Fatalf("Bind Ack: %+v, %v", msg, err)
	}
	for _, test := range []struct {
		edit func([]byte)
		want error
	}{
		{func(b []byte) { order.PutUint16(b[8:10], 0xffff) }, ErrInvalidDCERPC},
		{func(b []byte) { b[16] = 2 }, ErrInvalidDCERPC},
		{func(b []byte) { b[16] = MaxDCERPCContexts + 1 }, ErrDCERPCLimit},
	} {
		bad := bytes.Clone(body)
		test.edit(bad)
		if _, err := ParseDCERPC(dcerpcTestPacket(order, DCERPCBindAck, 3, bad)); !errors.Is(err, test.want) {
			t.Fatalf("bad Bind Ack returned %v, want %v", err, test.want)
		}
	}
}

func TestParseDCERPCRejectsMalformed(t *testing.T) {
	order := binary.LittleEndian
	bind := dcerpcTestPacket(order, DCERPCBind, 3, dcerpcTestBindBody(order, 1))
	for n := range bind {
		if _, err := ParseDCERPC(bind[:n]); !errors.Is(err, ErrInvalidDCERPC) {
			t.Fatalf("truncation at %d returned %v", n, err)
		}
	}
	for _, edit := range []func([]byte){
		func(b []byte) { b[0] = 4 },
		func(b []byte) { b[1] = 1 },
		func(b []byte) { b[2] = 99 },
		func(b []byte) { b[4] = 0x20 },
		func(b []byte) { order.PutUint16(b[8:10], 15) },
		func(b []byte) { order.PutUint16(b[8:10], uint16(len(b)-1)) },
		func(b []byte) { order.PutUint16(b[10:12], 0xffff) },
		func(b []byte) { order.PutUint16(b[10:12], 1); b[len(b)-7] = 0xff },
		func(b []byte) { b[24] = 0 },
		func(b []byte) { b[30] = 0 },
		func(b []byte) { b[30] = 0xff },
	} {
		bad := bytes.Clone(bind)
		edit(bad)
		if msg, err := ParseDCERPC(bad); !errors.Is(err, ErrInvalidDCERPC) || !reflect.DeepEqual(msg, DCERPCMessage{}) {
			t.Fatalf("malformed PDU returned %+v, %v", msg, err)
		}
	}
	for _, bad := range [][]byte{
		dcerpcTestPacket(order, DCERPCRequest, 0x83, make([]byte, 8)),
		dcerpcTestPacket(order, DCERPCResponse, 3, make([]byte, 7)),
		dcerpcTestPacket(order, DCERPCBindAck, 3, make([]byte, 12)),
		dcerpcTestPacket(order, DCERPCRequest, 3, make([]byte, 7)),
	} {
		if _, err := ParseDCERPC(bad); !errors.Is(err, ErrInvalidDCERPC) {
			t.Fatalf("accepted short PDU: %v", err)
		}
	}
}

func TestParseDCERPCContextLimit(t *testing.T) {
	order := binary.LittleEndian
	for _, count := range []int{MaxDCERPCContexts, MaxDCERPCContexts + 1} {
		wire := dcerpcTestPacket(order, DCERPCBind, 3, dcerpcTestBindBody(order, count))
		msg, err := ParseDCERPC(wire)
		if count == MaxDCERPCContexts && (err != nil || len(msg.Contexts) != count) {
			t.Fatalf("context limit: got %d, %v", len(msg.Contexts), err)
		}
		if count > MaxDCERPCContexts && (!errors.Is(err, ErrDCERPCLimit) || len(msg.Contexts) != 0) {
			t.Fatalf("past context limit: got %d, %v", len(msg.Contexts), err)
		}
	}
}

func BenchmarkParseDCERPC(b *testing.B) {
	order := binary.LittleEndian
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"request", dcerpcTestPacket(order, DCERPCRequest, 3, make([]byte, 8))},
		{"bind", dcerpcTestPacket(order, DCERPCBind, 3, dcerpcTestBindBody(order, 2))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.wire)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ParseDCERPC(tc.wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func dcerpcTestPacket(order binary.ByteOrder, kind DCERPCPacketType, flags byte, body []byte) []byte {
	buf := make([]byte, 16, 16+len(body))
	buf[0], buf[2], buf[3] = 5, byte(kind), flags
	if order == binary.LittleEndian {
		buf[4] = 0x10
	}
	order.PutUint16(buf[8:10], uint16(16+len(body)))
	order.PutUint32(buf[12:16], 0x01234567)
	return append(buf, body...)
}

func dcerpcTestBindBody(order binary.ByteOrder, count int) []byte {
	body := make([]byte, 12)
	body[8] = byte(count)
	for i := range count {
		fixed := make([]byte, 24)
		n := 1 + i%2
		fixed[2] = byte(n)
		order.PutUint16(fixed[:2], uint16(i))
		order.PutUint32(fixed[4:8], 0x11223344)
		order.PutUint16(fixed[8:10], 0x5566)
		order.PutUint16(fixed[10:12], 0x7788)
		copy(fixed[12:20], []byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0})
		order.PutUint32(fixed[20:24], 0x56781234)
		body = append(body, fixed...)
		body = append(body, make([]byte, n*20)...)
	}
	return body
}
