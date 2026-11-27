package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

func TestDNSTransactionScopes(t *testing.T) {
	client, other, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, [4]byte{192, 0, 2, 53}
	query := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'A', 1, 'b', 0, 0, 1, 0, 1}
	reply := bytes.Clone(query)
	reply[2], reply[13] = 0x81, 'a'
	queryTCP := append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
	replyTCP := append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)
	q := buildEthernetIPv4UDPFrame(client, server, 5000, 53, query)
	r := buildEthernetIPv4UDPFrame(server, client, 53, 5000, reply)
	var buf bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(opts); err != nil {
		t.Fatal(err)
	}
	for i, packet := range []struct {
		iface uint32
		data  []byte
	}{
		{0, q}, {1, r}, {0, buildEthernetIPv4UDPFrame(server, other, 53, 5000, reply)}, {0, r},
		// Identical rendered name "a.b", distinct DNS label boundaries.
		{0, q}, {0, buildEthernetIPv4UDPFrame(server, client, 53, 5000, bytes.Replace(reply, []byte{1, 'a', 1, 'b'}, []byte{3, 'a', '.', 'b'}, 1))},
		// Each TCP opening owns its queries, including at the same sequence
		// numbers on a separate interface.
		{0, buildEthernetIPv4TCPFrame(client, server, 5000, 53, 100, 0, TCPFlagSYN, nil)},
		{0, buildEthernetIPv4TCPFrame(client, server, 5000, 53, 101, 0, TCPFlagACK, queryTCP)},
		{1, buildEthernetIPv4TCPFrame(server, client, 53, 5000, 600, 0, TCPFlagACK, replyTCP)},
		{0, buildEthernetIPv4TCPFrame(client, server, 5000, 53, 300, 0, TCPFlagSYN, nil)},
		{0, buildEthernetIPv4TCPFrame(server, client, 53, 5000, 600, 0, TCPFlagACK, replyTCP)},
	} {
		if err := w.WritePacket(PacketRecord{InterfaceID: packet.iface, TimestampNs: int64(i+1) * 1000000}, packet.data); err != nil {
			t.Fatal(err)
		}
	}
	raw := buf.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.DNSTransactions, c.DNSTransactionsFromReaderAt)
	var got []DNSPairing
	for _, row := range rows {
		got = append(got, row.Pairing)
	}
	want := []DNSPairing{DNSPaired, DNSNoQueryObserved, DNSNoQueryObserved, DNSNoReplyObserved, DNSNoQueryObserved, DNSNoReplyObserved, DNSNoQueryObserved, DNSNoQueryObserved}
	if !slices.Equal(got, want) {
		t.Fatalf("pairings = %v, want %v", got, want)
	}
	if rows[0].Query.PacketIndex != 0 || rows[0].Reply.PacketIndex != 3 {
		t.Fatalf("paired wrong packets: %+v", rows[0])
	}
	if rows[5].Query.PacketIndex != 7 || rows[6].Reply.FlowIndex != rows[5].Query.FlowIndex || rows[7].Reply.FlowIndex != rows[5].Query.FlowIndex {
		t.Fatal("expected separate TCP openings on one flow")
	}
	for _, tc := range []struct {
		start, end int64
		ok         bool
	}{{1, 1, true}, {1, 2, true}, {0, 1, false}, {2, 1, false}} {
		row := rows[0]
		row.Query.TimestampNs, row.Reply.TimestampNs = tc.start, tc.end
		d, ok := row.Elapsed()
		if ok != tc.ok || ok && int64(d) != tc.end-tc.start {
			t.Errorf("Elapsed(%d,%d) = %v, %t", tc.start, tc.end, d, ok)
		}
	}
}

func TestDNSTransactionsLimit(t *testing.T) {
	// Ordinary orphan replies share no pending state, but count against the
	// same per-scan limit as outstanding queries and ambiguous observations.
	udp := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 1}, 53, 5000, []byte{0, 7, 0x81, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
	frames := make([][]byte, MaxDNSMessagesPerScan+1)
	for i := range frames {
		frames[i] = udp
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.DNSTransactions(raw)
	if !errors.Is(err, ErrDNSLimit) || rows != nil {
		t.Fatalf("got %d rows, %v", len(rows), err)
	}
}

func TestDNSTransactionsFragmentedReply(t *testing.T) {
	client, resolver := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 53}
	query := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	reply := bytes.Clone(query)
	reply[2] = 0x81
	udp := buildEthernetIPv4UDPFrame(resolver, client, 53, 5000, reply)[34:]
	other := bytes.Clone(udp)
	other[8+1]++ // A different DNS transaction in a fragment with the same IP ID.
	var buf bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddInterface(opts); err != nil {
		t.Fatal(err)
	}
	for _, pkt := range []struct {
		iface uint32
		frame []byte
	}{
		{0, buildEthernetIPv4UDPFrame(client, resolver, 5000, 53, query)},
		{1, buildEthernetIPv4FragmentFrame(resolver, client, IPProtoUDP, 7, 0, true, other[:16])},
		{0, buildEthernetIPv4FragmentFrame(resolver, client, IPProtoUDP, 7, 16, false, udp[16:])},
		{0, buildEthernetIPv4FragmentFrame(resolver, client, IPProtoUDP, 7, 0, true, udp[:16])},
	} {
		if err := w.WritePacket(PacketRecord{InterfaceID: pkt.iface}, pkt.frame); err != nil {
			t.Fatal(err)
		}
	}
	raw := buf.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.DNSTransactions, c.DNSTransactionsFromReaderAt)
	if len(rows) != 1 || rows[0].Pairing != DNSPaired {
		t.Fatalf("DNS transactions = %+v", rows)
	}
	q, r := rows[0].Query, rows[0].Reply
	if q.PacketIndex != 0 || r.PacketIndex != 3 || q.FlowIndex == r.FlowIndex {
		t.Fatalf("query packet/flow %d/%d and reply %d/%d", q.PacketIndex, q.FlowIndex, r.PacketIndex, r.FlowIndex)
	}
}

func TestDNSTransactionsSkipDiscoveryPayloads(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 53}
	reply := buildDNSQueryResponsePacket()
	large := append(bytes.Clone(reply), make([]byte, 32000)...)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4UDPFrame(server, client, 5353, 5000, large),
		buildEthernetIPv4UDPFrame(server, [4]byte{224, 0, 0, 251}, 53, 5000, large),
		buildEthernetIPv4UDPFrame(server, client, 53, 5000, reply),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	rows, err := c.DNSTransactionsFromReaderAt(r)
	if err != nil || len(rows) != 1 || rows[0].Reply == nil || rows[0].Reply.PacketIndex != 2 || r.bytesRead >= int64(len(large)) {
		t.Fatalf("got %d rows after %d bytes read, %v", len(rows), r.bytesRead, err)
	}
}
