package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestDCERPCCaptureParityAndProvenance(t *testing.T) {
	order := binary.LittleEndian
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	const clientPort, serverPort = 50100, 50200
	tcp := func(seq uint32, flags uint8, data []byte) []byte {
		return buildEthernetIPv4TCPFrame(src, dst, clientPort, serverPort, seq, 0, flags, data)
	}
	bind := dcerpcTestPacket(order, DCERPCBind, 3, dcerpcTestBindBody(order, 1))
	body := make([]byte, 8)
	order.PutUint16(body[6:8], 42)
	request := dcerpcTestPacket(order, DCERPCRequest, 3, body)
	other := dcerpcTestPacket(order, DCERPCPacketType(16), 3, nil)
	tail := bytes.Join([][]byte{bind[2:], other, request, request}, nil)
	raw := buildClassicPCAP(order, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4UDPFrame(src, dst, clientPort, serverPort, request),
		tcp(100, TCPFlagSYN, nil),
		tcp(103, TCPFlagACK, tail),
		tcp(101, TCPFlagACK, bind[:2]),
		tcp(103, TCPFlagACK, tail),
		tcp(10000, TCPFlagACK, request),
		buildEthernetIPv4TCPFrame(src, dst, 50300, serverPort, 1, 0, TCPFlagACK, append([]byte{'X'}, request...)),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.DCERPC(raw)
	if err != nil {
		t.Fatal(err)
	}
	gotAt, err := c.DCERPCFromReaderAt(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(rows, gotAt) {
		t.Fatalf("ReaderAt parity: %v, %v", gotAt, err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	for i, want := range []struct {
		packet int
		kind   DCERPCPacketType
		opnum  uint16
	}{
		{2, DCERPCRequest, 42}, {2, DCERPCRequest, 42}, {3, DCERPCBind, 0},
	} {
		got := rows[i]
		if got.PacketIndex != want.packet || got.TimestampNs != packets[want.packet].TimestampNs || got.FlowIndex != 1 ||
			got.Source.Port() != clientPort || got.Destination.Port() != serverPort ||
			got.Message.PacketType != want.kind || got.Message.Opnum != want.opnum {
			t.Fatalf("row %d: %+v, want %+v", i, got, want)
		}
	}
	if contexts := rows[2].Message.Contexts; len(contexts) != 1 || contexts[0].AbstractSyntaxUUID != "11223344-5566-7788-99aa-bbccddeeff00" {
		t.Fatalf("bad bind context: %+v", contexts)
	}
}

func TestDCERPCCaptureLimitDiscardsResults(t *testing.T) {
	order := binary.LittleEndian
	pdu := dcerpcTestPacket(order, DCERPCBind, 3, dcerpcTestBindBody(order, MaxDCERPCContexts))
	frames := make([][]byte, MaxDCERPCContextsPerScan/MaxDCERPCContexts+1)
	// Use separate connections so the aggregate context limit is reached
	// before the per-flow TCP reassembly limit.
	for i := range frames {
		frames[i] = buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2},
			50000+uint16(i), 135, 1, 0, TCPFlagACK, pdu)
	}
	raw := buildClassicPCAP(order, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DCERPC(raw); got != nil || !errors.Is(err, ErrDCERPCLimit) {
		t.Fatalf("over-limit scan returned %d records, %v", len(got), err)
	}
}

func BenchmarkDCERPCCapture(b *testing.B) {
	order := binary.LittleEndian
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	pdu := dcerpcTestPacket(order, DCERPCRequest, 3, make([]byte, 8))
	frames := make([][]byte, 256)
	background := make([]byte, 1200)
	for i := range frames {
		payload := background
		if i%64 == 0 {
			payload = pdu
		}
		frames[i] = buildEthernetIPv4TCPFrame(src, dst, 50000+uint16(i), 50200, 1, 0, TCPFlagACK, payload)
	}
	raw := buildClassicPCAP(order, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	for _, workload := range []struct {
		name string
		scan func() ([]DCERPCRecord, error)
	}{
		{"slice", func() ([]DCERPCRecord, error) { return c.DCERPC(raw) }},
		{"reader", func() ([]DCERPCRecord, error) { return c.DCERPCFromReaderAt(r) }},
	} {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				records, err := workload.scan()
				if err != nil || len(records) != 4 {
					b.Fatalf("got %d records, %v", len(records), err)
				}
			}
		})
	}
}

func ExampleCapture_DCERPC() {
	wire := dcerpcTestPacket(binary.LittleEndian, DCERPCRequest, 3, []byte{0, 0, 0, 0, 1, 0, 42, 0})
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 50100, 50200, 1, 0, TCPFlagACK, wire)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
	c, err := New(raw)
	if err != nil {
		panic(err)
	}
	records, err := c.DCERPC(raw)
	if err != nil {
		panic(err)
	}
	fmt.Println(records[0].PacketIndex, records[0].Message.ContextID, records[0].Message.Opnum, records[0].SMB2Command)
	// Output:
	// 0 1 42 0
}
