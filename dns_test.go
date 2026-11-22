package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
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
