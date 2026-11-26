package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func buildDNSQueryResponsePacket() []byte {
	var buf bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1337)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 2)
	buf.Write(hdr[:])

	buf.Write([]byte("\x02c2\x07example\x03com\x00"))
	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], DNSTypeA)
	binary.BigEndian.PutUint16(qTail[2:4], 1)
	buf.Write(qTail[:])

	buf.Write([]byte{0xc0, 0x0c})
	var rr1 [10]byte
	binary.BigEndian.PutUint16(rr1[0:2], DNSTypeCNAME)
	binary.BigEndian.PutUint16(rr1[2:4], 1)
	binary.BigEndian.PutUint32(rr1[4:8], 60)
	binary.BigEndian.PutUint16(rr1[8:10], 7)
	buf.Write(rr1[:])
	buf.Write([]byte{'\x04', 'e', 'd', 'g', 'e', 0xc0, 0x0f})

	buf.Write([]byte{0xc0, 0x0c})
	var rr2 [10]byte
	binary.BigEndian.PutUint16(rr2[0:2], DNSTypeA)
	binary.BigEndian.PutUint16(rr2[2:4], 1)
	binary.BigEndian.PutUint32(rr2[4:8], 300)
	binary.BigEndian.PutUint16(rr2[8:10], 4)
	buf.Write(rr2[:])
	buf.Write([]byte{203, 0, 113, 42})

	return buf.Bytes()
}

func TestDNSReaderAtBorrowedPayloadLifetime(t *testing.T) {
	src, dst := [4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 14}
	first := buildDNSQueryResponsePacket()
	second := bytes.ReplaceAll(first, []byte("example"), []byte("invalid"))
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4UDPFrame(src, dst, 53, 53000, first),
		buildEthernetIPv4UDPFrame(src, dst, 53, 53000, second),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	records := checkReaderParity(t, raw, c.DNS, c.DNSFromReaderAt)
	if len(records) != 2 || records[0].Message.Answers[0].Target != "edge.example.com" ||
		records[1].Message.Answers[0].Target != "edge.invalid.com" {
		t.Fatalf("DNS records = %+v", records)
	}
}

func buildEthernetIPv4UDPFrame(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	ipTotalLen := 20 + udpLen
	frame := make([]byte, 14+ipTotalLen)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen))
	ip[8] = 64
	ip[9] = IPProtoUDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(frame[42:], payload)
	return frame
}

func TestParseDNSAndCaptureDNSQueries(t *testing.T) {
	dnsBytes := buildDNSQueryResponsePacket()
	msg, err := ParseDNS(dnsBytes)
	if err != nil {
		t.Fatalf("ParseDNS() error = %v", err)
	}
	if !msg.IsResponse || msg.TransactionID != 0x1337 || len(msg.Questions) != 1 || len(msg.Answers) != 2 {
		t.Fatalf("DNSMessage = %+v", msg)
	}
	if msg.Questions[0].Name != "c2.example.com" {
		t.Fatalf("Question[0].Name = %q, want \"c2.example.com\"", msg.Questions[0].Name)
	}
	if msg.Answers[0].Target != "edge.example.com" {
		t.Fatalf("Answers[0].Target = %q, want \"edge.example.com\"", msg.Answers[0].Target)
	}
	if msg.Answers[1].Address != netip.MustParseAddr("203.0.113.42") {
		t.Fatalf("Answers[1].Address = %s, want 203.0.113.42", msg.Answers[1].Address)
	}

	udpFrame := buildEthernetIPv4UDPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 5}, 53, 55111, dnsBytes)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{udpFrame})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.DNS(rawPCAP)
	if err != nil || len(records) != 1 {
		t.Fatalf("cap.DNS() = (%d, %v), want 1", len(records), err)
	}
	found, err := cap.HasDNSQuery(rawPCAP, "C2.EXAMPLE.COM.")
	if err != nil || !found {
		t.Fatalf("HasDNSQuery(C2.EXAMPLE.COM.) = (%v, %v), want (true, nil)", found, err)
	}
	notFound, err := cap.HasDNSQuery(rawPCAP, "other.example.com")
	if err != nil || notFound {
		t.Fatalf("HasDNSQuery(other.example.com) = (%v, %v), want (false, nil)", notFound, err)
	}
}

func TestDNSCompressionLoopsForwardPointersAndLimits(t *testing.T) {
	if _, err := ParseDNS(make([]byte, 11)); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(11B) err = %v, want ErrInvalidDNS", err)
	}

	var oversizeQD [12]byte
	binary.BigEndian.PutUint16(oversizeQD[4:6], MaxDNSQuestions+1)
	if _, err := ParseDNS(oversizeQD[:]); !errors.Is(err, ErrDNSLimit) {
		t.Fatalf("ParseDNS(oversize QDCount) err = %v, want ErrDNSLimit", err)
	}

	var loopPkt [18]byte
	binary.BigEndian.PutUint16(loopPkt[4:6], 1)
	loopPkt[12] = 0xc0
	loopPkt[13] = 0x0c
	if _, err := ParseDNS(loopPkt[:]); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(self compression loop) err = %v, want ErrInvalidDNS", err)
	}

	var fwdPkt [24]byte
	binary.BigEndian.PutUint16(fwdPkt[4:6], 1)
	fwdPkt[12] = 0xc0
	fwdPkt[13] = 20
	if _, err := ParseDNS(fwdPkt[:]); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(forward compression pointer) err = %v, want ErrInvalidDNS", err)
	}

	// Compression pointer into the 12-byte DNS header must be rejected.
	var hdrPtrPkt [18]byte
	binary.BigEndian.PutUint16(hdrPtrPkt[4:6], 1)
	hdrPtrPkt[12] = 0xc0
	hdrPtrPkt[13] = 0x04
	if _, err := ParseDNS(hdrPtrPkt[:]); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(header compression pointer) err = %v, want ErrInvalidDNS", err)
	}

	var longName bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	longName.Write(hdr[:])
	for range 5 {
		longName.WriteByte(60)
		longName.WriteString(strings.Repeat("a", 60))
	}
	longName.WriteByte(0)
	longName.Write([]byte{0, 1, 0, 1})
	if _, err := ParseDNS(longName.Bytes()); !errors.Is(err, ErrDNSLimit) {
		t.Fatalf("ParseDNS(>255B name) err = %v, want ErrDNSLimit", err)
	}
}

func TestDNSLabelEntropyAndDomainStats(t *testing.T) {
	// Issue #13: Contrast low-entropy normal subdomain ("www.example.com") with
	// high-entropy DNS tunneling query ("4b8f9a1c0d2e3f4a5b6c7d8e9f0a1b2c.tunnel.example.com").
	lowEnt := DNSLabelEntropy("www.example.com")
	highEnt := DNSLabelEntropy("4b8f9a1c0d2e3f4a5b6c7d8e9f0a1b2c.tunnel.example.com")
	if lowEnt != 0 || highEnt < 3.5 {
		t.Fatalf("DNSLabelEntropy: low=%v (want 0), high=%v (want >= 3.5)", lowEnt, highEnt)
	}

	// Build a DNS query packet for the high-entropy subdomain.
	var qBuf bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x2222)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	qBuf.Write(hdr[:])
	label := "4b8f9a1c0d2e3f4a5b6c7d8e9f0a1b2c"
	qBuf.WriteByte(byte(len(label)))
	qBuf.WriteString(label)
	qBuf.Write([]byte("\x07example\x03com\x00"))
	qBuf.Write([]byte{0, byte(DNSTypeTXT), 0, 1})

	udpFrame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 55000, 53, qBuf.Bytes())
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{udpFrame})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	stats, err := cap.DNSDomainStats(rawPCAP)
	if err != nil || len(stats) != 1 {
		t.Fatalf("DNSDomainStats() = (%+v, %v)", stats, err)
	}
	st := stats[0]
	if st.Domain != "example.com" || st.QueryCount != 1 || st.UniqueSubdomains != 1 || st.MaxLabelLength != 32 || st.TunnelScore < 0.5 {
		t.Fatalf("DNSDomainStats[0] = %+v", st)
	}
}

func TestDNSAnswerTXTStrings(t *testing.T) {
	for _, bad := range []bool{false, true} {
		// Response with one root-name TXT answer and two strings.
		msg := []byte{0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 5, 2, 'a', 'b', 1, 'c'}
		if bad {
			msg[26] = 2
		}
		got, err := ParseDNS(msg)
		if err != nil || len(got.Answers) != 1 {
			t.Fatalf("TXT response: %+v, %v", got, err)
		}
		want := []string{"ab", "c"}
		if bad {
			want = want[:1]
		}
		if !slices.Equal(got.Answers[0].TXT, want) || got.Anomalies.InvalidRDataLength != bad {
			t.Fatalf("TXT answer: %+v, anomalies %+v", got.Answers[0], got.Anomalies)
		}
	}
}

func TestDNSTCPReassemblyAndDomainStatsNoDoubleCount(t *testing.T) {
	// Two-label name entropy matches docstring (computed over entire name).
	if ent := DNSLabelEntropy("ab.cd"); ent <= 0 {
		t.Fatalf("DNSLabelEntropy(ab.cd) = %v, want > 0", ent)
	}

	// Build a TCP DNS query + response pair split across multiple TCP segments.
	var qBuf bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1111)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	qBuf.Write(hdr[:])
	qBuf.Write([]byte("\x02c2\x07example\x03com\x00"))
	qBuf.Write([]byte{0, byte(DNSTypeA), 0, 1})
	qMsg := qBuf.Bytes()
	rMsg := buildDNSQueryResponsePacket()

	tcpFrame := func(msg []byte) []byte {
		out := make([]byte, 2+len(msg))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
		copy(out[2:], msg)
		return out
	}
	cStream := tcpFrame(qMsg)
	sStream := tcpFrame(rMsg)
	cSplit := len(cStream) / 2
	sSplit := len(sStream) / 2
	frames := [][]byte{
		buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 54000, 53, 1, 1, TCPFlagPSH|TCPFlagACK, cStream[:cSplit]),
		buildEthernetIPv4UDPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 1}, 53, 54000, make([]byte, 12)),
		buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 54000, 53, 1+uint32(cSplit), 1, TCPFlagPSH|TCPFlagACK, cStream[cSplit:]),
		buildEthernetIPv4TCPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 1}, 53, 54000, 1, 1+uint32(len(cStream)), TCPFlagPSH|TCPFlagACK, sStream[:sSplit]),
		buildEthernetIPv4TCPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 1}, 53, 54000, 1+uint32(sSplit), 1+uint32(len(cStream)), TCPFlagPSH|TCPFlagACK, sStream[sSplit:]),
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	budget := scanReadBudget{r: bytes.NewReader(raw), remaining: int64(len(raw))}
	if _, err := c.DNSFromReaderAt(&budget); err != nil {
		t.Fatalf("DNS exceeded a single walk of the fixture: %v", err)
	}
	checkReaderParity(t, raw, c.DNS, c.DNSFromReaderAt)
	recs, err := c.DNS(raw)
	if err != nil || len(recs) != 3 {
		t.Fatalf("DNS(multi-segment TCP) = (%d, %v), want 3", len(recs), err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{0, 1, 3} {
		if recs[i].PacketIndex != want || recs[i].TimestampNs != packets[want].TimestampNs {
			t.Fatalf("record %d: packet %d, time %d", i, recs[i].PacketIndex, recs[i].TimestampNs)
		}
	}
	if has, err := c.HasDNSQuery(raw, "c2.example.com"); err != nil || !has {
		t.Fatalf("HasDNSQuery(multi-segment TCP) = (%v, %v), want true", has, err)
	}

	// DNSDomainStats must not double-count echoed questions in responses.
	stats, err := c.DNSDomainStats(raw)
	if err != nil || len(stats) != 1 {
		t.Fatalf("DNSDomainStats() = (%+v, %v)", stats, err)
	}
	if stats[0].QueryCount != 1 || stats[0].UniqueSubdomains != 1 {
		t.Fatalf("DNSDomainStats[0] = %+v, want QueryCount=1 UniqueSubdomains=1", stats[0])
	}
}

func TestDNSApexAndCaptureWideSourceStats(t *testing.T) {
	if sub, apex := splitDNSSubdomainAndApex("www.alpha.co.uk."); sub != "www" || apex != "alpha.co.uk" {
		t.Fatalf("splitDNSSubdomainAndApex(www.alpha.co.uk.) = (%q, %q), want (www, alpha.co.uk)", sub, apex)
	}
	if sub, apex := splitDNSSubdomainAndApex("alpha.co.uk"); sub != "" || apex != "alpha.co.uk" {
		t.Fatalf("splitDNSSubdomainAndApex(alpha.co.uk) = (%q, %q), want (\"\", alpha.co.uk)", sub, apex)
	}

	buildDNSWire := func(txID uint16, resp bool, rcode uint8, qname string) []byte {
		var buf []byte
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[0:2], txID)
		flags := uint16(0x0100)
		if resp {
			flags = 0x8180 | uint16(rcode&0x0f)
		}
		binary.BigEndian.PutUint16(hdr[2:4], flags)
		binary.BigEndian.PutUint16(hdr[4:6], 1)
		buf = append(buf, hdr[:]...)
		for label := range strings.SplitSeq(qname, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
		buf = append(buf, 0, 0, 1, 0, 1) // A IN
		return buf
	}

	var frames [][]byte
	// Legitimate multi-label .co.uk queries (no NXDOMAINs).
	for i, name := range []string{"alpha.co.uk", "bravo.co.uk", "gov.co.uk", "shop.co.uk", "bank.co.uk"} {
		q := buildDNSWire(uint16(100+i), false, 0, name)
		frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 20}, [4]byte{8, 8, 8, 8}, uint16(41000+i), 53, q))
	}
	// Queries from 10.0.0.50: 10 distinct high-entropy .com NXDOMAINs.
	dgaNames := []string{
		"x8k2m9p4q1.com", "z3v7n1b5c8.com", "q9w2e4r6t8.com", "m1n3b5v7c9.com", "k4j6h8g2f1.com",
		"p7o5i3u1y9.com", "a2s4d6f8g0.com", "l9k7j5h3g1.com", "r8t6y4u2i0.com", "w1q3e5r7t9.com",
	}
	for i, name := range dgaNames {
		q := buildDNSWire(uint16(200+i), false, 0, name)
		r := buildDNSWire(uint16(200+i), true, DNSRCodeNameError, name)
		frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 50}, [4]byte{8, 8, 8, 8}, uint16(42000+i), 53, q))
		frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 50}, 53, uint16(42000+i), r))
	}

	// A multicast announcement has no individual destination client.
	announcement := buildDNSWire(0, true, 0, "printer.local")
	frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 22}, [4]byte{224, 0, 0, 251}, 5353, 5353, announcement))

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}

	domStats, err := c.DNSDomainStats(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, ds := range domStats {
		if ds.Domain == "co.uk" {
			t.Fatalf("unexpected collapse into co.uk: %+v", ds)
		}
	}

	srcStats, err := c.DNSSourceStats(raw)
	if err != nil || len(srcStats) != 2 {
		t.Fatalf("DNSSourceStats() = (%+v, %v)", srcStats, err)
	}
	if srcStats[0].DGAScore != 0 {
		t.Fatalf("benign client DGAScore = %v, want 0", srcStats[0].DGAScore)
	}
	if srcStats[1].NXDomainCount != 10 || srcStats[1].UniqueNXDomainApex != 10 || srcStats[1].DGAScore < 0.8 {
		t.Fatalf("DGA client stats = %+v, want NXDomainCount=10 UniqueNXDomainApex=10 DGAScore>=0.8", srcStats[1])
	}
	// Spreading the same observations across weeks preserves a capture-wide score.
	var spread bytes.Buffer
	writer, err := NewPCAPWriter(&spread, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range frames {
		if err := writer.WritePacket(int64(i)*int64(24*time.Hour), frame); err != nil {
			t.Fatal(err)
		}
	}
	spreadCapture, err := New(spread.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	spreadStats, err := spreadCapture.DNSSourceStats(spread.Bytes())
	if err != nil || !slices.Equal(srcStats, spreadStats) {
		t.Fatalf("time-spread stats = %+v, err = %v", spreadStats, err)
	}
}

func TestDNSPartialSectionCapacity(t *testing.T) {
	msg, err := ParseDNS([]byte{0, 1, 0x80, 0, 0, 0, 0, 20, 0, 0, 0, 0})
	if err != nil || !msg.Anomalies.TruncatedSection || cap(msg.Answers) != 0 || msg.AnswerCount != 20 {
		t.Fatalf("answers cap=%d count=%d anomalies=%+v err=%v", cap(msg.Answers), msg.AnswerCount, msg.Anomalies, err)
	}
}

func TestDNSTCPReusedTuple(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	var frames [][]byte
	for i, label := range []string{"one", "two"} {
		msg := []byte{0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3}
		msg = append(msg, label...)
		msg = append(msg, 0, 0, 1, 0, 1)
		wire := append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
		seq := uint32(100 - i)
		frames = append(frames, buildEthernetIPv4TCPFrame(a, b, 5000, 53, seq, 0, TCPFlagSYN, nil),
			buildEthernetIPv4TCPFrame(a, b, 5000, 53, seq+1, 0, TCPFlagACK, wire))
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.DNS(raw)
	if err != nil || len(rows) != 2 || rows[0].PacketIndex != 1 || rows[1].PacketIndex != 3 || rows[0].FlowIndex != rows[1].FlowIndex || rows[1].Message.Questions[0].Name != "two" {
		t.Fatalf("DNS = %+v, %v", rows, err)
	}
	if yes, err := c.HasDNSQuery(raw, "two"); err != nil || !yes {
		t.Fatalf("HasDNSQuery = %t, %v", yes, err)
	}
	checkReaderParity(t, raw, c.DNS, c.DNSFromReaderAt)
}
