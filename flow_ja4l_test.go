package pcap

import (
	"bytes"
	"reflect"
	"testing"
)

func TestFlowJA4LMatchesTCPHandshake(t *testing.T) {
	syn := func(seq uint32) []byte { return tcpInterfaceFrame(seq, 0, TCPFlagSYN, false, "") }
	synAck := func(seq, ack uint32) []byte {
		return tcpInterfaceFrame(seq, ack, TCPFlagSYN|TCPFlagACK, true, "")
	}
	ack := func(seq, ack uint32) []byte { return tcpInterfaceFrame(seq, ack, TCPFlagACK, false, "") }
	rst := tcpInterfaceFrame(0, 101, TCPFlagRST|TCPFlagACK, true, "")
	for _, tc := range []struct {
		name           string
		packets        []tcpCapturePacket
		client, server string
	}{
		{
			"reset and tuple reuse",
			[]tcpCapturePacket{{0, 1000, syn(100)}, {0, 1002, rst}, {0, 11000, syn(5000)},
				{0, 11002, synAck(7000, 5001)}, {0, 11004, ack(5001, 7001)}},
			"1000_64", "1000_64",
		},
		{
			"reset and same sequence",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 2, rst}, {0, 4, syn(100)},
				{0, 6, synAck(200, 101)}, {0, 10, ack(101, 201)}},
			"2000_64", "1000_64",
		},
		{
			"delayed reset for previous opening",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 4, syn(500)}, {0, 5, rst},
				{0, 6, synAck(700, 501)}, {0, 10, ack(501, 701)}},
			"2000_64", "1000_64",
		},
		{
			"client reset clears matched opening",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 3, synAck(200, 101)},
				{0, 4, tcpInterfaceFrame(101, 201, TCPFlagRST|TCPFlagACK, false, "")},
				{0, 10, syn(100)}, {0, 16, synAck(500, 101)}, {0, 20, ack(101, 501)}},
			"2000_64", "3000_64",
		},
		{
			"retransmissions retain first timestamps",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 3, syn(100)}, {0, 7, synAck(200, 101)},
				{0, 9, synAck(200, 101)}, {0, 11, ack(101, 201)}},
			"2000_64", "3000_64",
		},
		{
			"new opening rejects delayed SYN ACK and ACK",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 2, syn(500)}, {0, 3, synAck(200, 101)},
				{0, 4, synAck(700, 501)}, {0, 5, ack(101, 701)}, {0, 6, ack(501, 201)}, {0, 8, ack(501, 701)}},
			"2000_64", "1000_64",
		},
		{
			"first completed pair replaces earlier incomplete pair",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 3, synAck(200, 101)}, {0, 4, rst},
				{0, 10, syn(500)}, {0, 14, synAck(700, 501)}, {0, 20, ack(501, 701)},
				{0, 30, syn(900)}, {0, 38, synAck(1500, 901)}, {0, 48, ack(901, 1501)}},
			"3000_64", "2000_64",
		},
		{
			"incomplete first matching pair",
			[]tcpCapturePacket{{0, 1, syn(100)}, {0, 5, synAck(200, 101)}, {0, 6, rst},
				{0, 11, syn(500)}, {0, 13, synAck(700, 501)}},
			"", "2000_64",
		},
		{
			"reverse opener after pickup",
			[]tcpCapturePacket{{0, 1, tcpInterfaceFrame(100, 0, TCPFlagACK, false, "")},
				{0, 2, tcpInterfaceFrame(200, 0, TCPFlagSYN, true, "")},
				{0, 4, tcpInterfaceFrame(300, 201, TCPFlagSYN|TCPFlagACK, false, "")},
				{0, 10, tcpInterfaceFrame(201, 301, TCPFlagACK, true, "")}},
			"3000_64", "1000_64",
		},
		{
			"Fast Open with sequence wrap",
			[]tcpCapturePacket{{0, 1, tcpInterfaceFrame(0xffffffff, 0, TCPFlagSYN, false, "abc")},
				{0, 5, tcpInterfaceFrame(0xfffffffe, 3, TCPFlagSYN|TCPFlagACK, true, "abcd")},
				{0, 9, ack(3, 3)}},
			"2000_64", "2000_64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkFlowJA4L(t, tc.packets, false, tc.client, tc.server)
		})
	}
}

func TestFlowJA4LInterfaceObservations(t *testing.T) {
	packets := []tcpCapturePacket{
		{0, 1, tcpInterfaceFrame(100, 0, TCPFlagSYN, false, "")},
		{1, 2, tcpInterfaceFrame(500, 0, TCPFlagSYN, false, "")},
		{0, 5, tcpInterfaceFrame(200, 101, TCPFlagSYN|TCPFlagACK, true, "")},
		{0, 7, tcpInterfaceFrame(101, 201, TCPFlagACK, false, "")},
		{1, 8, tcpInterfaceFrame(600, 501, TCPFlagSYN|TCPFlagACK, true, "")},
		{1, 12, tcpInterfaceFrame(501, 601, TCPFlagACK, false, "")},
	}
	checkFlowJA4L(t, packets, true, "1000_64", "2000_64")
	checkFlowJA4L(t, packets, false, "2000_64", "3000_64")

	// Observation of one handshake can span interfaces in combined mode.
	packets = []tcpCapturePacket{
		{0, 1, packets[0].frame}, {1, 5, packets[2].frame}, {0, 7, packets[3].frame},
	}
	checkFlowJA4L(t, packets, true, "", "")
	checkFlowJA4L(t, packets, false, "1000_64", "2000_64")
}

func checkFlowJA4L(t *testing.T, packets []tcpCapturePacket, separate bool, client, server string) {
	t.Helper()
	data, err := tcpInterfaceCapture(packets)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(data)
	cr, err := NewFromReaderAt(reader, reader.Size())
	if err != nil {
		t.Fatal(err)
	}
	c.SeparateTCPInterfaces, cr.SeparateTCPInterfaces = separate, separate
	flows, err := c.Flows(data)
	if err != nil || len(flows) != 1 || flows[0].PacketCount != len(packets) {
		t.Fatalf("separate=%t flows=%+v err=%v", separate, flows, err)
	}
	if got := flows[0]; got.ClientJA4L != client || got.ServerJA4L != server {
		t.Fatalf("separate=%t JA4L client=%q server=%q want %q and %q", separate, got.ClientJA4L, got.ServerJA4L, client, server)
	}
	got, err := cr.FlowsFromReaderAt(reader)
	if err != nil || !reflect.DeepEqual(got, flows) {
		t.Fatalf("separate=%t ReaderAt flows=%+v err=%v", separate, got, err)
	}
}
