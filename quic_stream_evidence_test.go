package pcap

import (
	"slices"
	"testing"
)

func TestLocatedQUICStreamCaptureOrder(t *testing.T) {
	packets := []QUIC1RTTPacket{
		{PacketIndex: 10, Payload: []byte{0x0e, 0, 2, 2, 'c', 'd', 0x0b, 4, 1, 'x'}},
		{PacketIndex: 12, Payload: []byte{0x0e, 0, 0, 2, 'a', 'b'}},
		{PacketIndex: 14, Payload: []byte{0x0f, 0, 2, 2, 'c', 'd'}},
	}
	rows, err := locateQUICStreams(packets)
	if err != nil || len(rows) != 2 {
		t.Fatalf("streams %v, %v", rows, err)
	}
	a, b := rows[0], rows[1]
	if string(a.stream.Data) != "abcd" || !a.stream.Complete || !a.shared || !b.shared ||
		!slices.Equal(a.packets, []int{10, 12, 14}) || !slices.Equal(b.packets, []int{10}) ||
		a.arrival(4) != 3 || a.prefixAt(2) != 0 || a.prefixAt(4) != 4 ||
		!slices.Equal(a.contributions, []quicStreamContribution{{10, 2, 4}, {12, 0, 2}, {14, 2, 4}}) {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
}
