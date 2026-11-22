package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestReassembleTCPLimits(t *testing.T) {
	// 1. Segment count limit (> MaxSegmentsPerFlow).
	tooMany := make([]TCPSegmentInput, MaxSegmentsPerFlow+1)
	if _, err := ReassembleTCP(tooMany); !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("ReassembleTCP(tooMany) err = %v, want ErrReassemblyLimit", err)
	}

	// 2. Budget truncation sets StreamAnomalies.Truncated.
	segs := []TCPSegmentInput{
		{Seq: 1, Flags: TCPFlagSYN},
		{Seq: 2, Flags: TCPFlagACK, Payload: []byte("0123456789abcdef")},
	}
	buf, used, err := reassembleTCPWithBudget(segs, 6)
	if err != nil {
		t.Fatalf("reassembleTCPWithBudget() err = %v", err)
	}
	if used != 6 || string(buf.Data) != "012345" || !buf.Anomalies.Truncated {
		t.Fatalf("reassembleTCPWithBudget(6) = (%q, used=%d, %+v)", buf.Data, used, buf.Anomalies)
	}
}

func TestDNSCompressionLoopsForwardPointersAndLimits(t *testing.T) {
	// 1. Shorter than 12-byte DNS header.
	if _, err := ParseDNS(make([]byte, 11)); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(11B) err = %v, want ErrInvalidDNS", err)
	}

	// 2. Question count exceeding MaxDNSQuestions.
	var oversizeQD [12]byte
	binary.BigEndian.PutUint16(oversizeQD[4:6], MaxDNSQuestions+1)
	if _, err := ParseDNS(oversizeQD[:]); !errors.Is(err, ErrDNSLimit) {
		t.Fatalf("ParseDNS(oversize QDCount) err = %v, want ErrDNSLimit", err)
	}

	// 3. Self-referential DNS compression pointer loop at offset 12 (0xc00c -> 12).
	var loopPkt [18]byte
	binary.BigEndian.PutUint16(loopPkt[4:6], 1)
	loopPkt[12] = 0xc0
	loopPkt[13] = 0x0c // Points to itself (offset 12 >= current offset 12)
	if _, err := ParseDNS(loopPkt[:]); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(self compression loop) err = %v, want ErrInvalidDNS", err)
	}

	// 4. Forward DNS compression pointer (points ahead to offset 20 > 12).
	var fwdPkt [24]byte
	binary.BigEndian.PutUint16(fwdPkt[4:6], 1)
	fwdPkt[12] = 0xc0
	fwdPkt[13] = 20
	if _, err := ParseDNS(fwdPkt[:]); !errors.Is(err, ErrInvalidDNS) {
		t.Fatalf("ParseDNS(forward compression pointer) err = %v, want ErrInvalidDNS", err)
	}

	// 5. DNS name exceeding MaxDNSNameBytes (255).
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

func TestTLSBoundsAnomaliesAndMalformedInputs(t *testing.T) {
	// 1. Non-handshake record type (ApplicationData = 23).
	if _, err := ParseTLSRecords([]byte{TLSRecordApplicationData, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}); !errors.Is(err, ErrInvalidTLS) {
		t.Fatalf("ParseTLSRecords(AppData) err = %v, want ErrInvalidTLS", err)
	}

	// 2. Oversize TLS record (> MaxTLSRecordBytes).
	var oversizeRec [5]byte
	oversizeRec[0] = TLSRecordHandshake
	binary.BigEndian.PutUint16(oversizeRec[1:3], TLSVersion12)
	binary.BigEndian.PutUint16(oversizeRec[3:5], MaxTLSRecordBytes+1)
	if _, err := ParseTLSRecords(oversizeRec[:]); !errors.Is(err, ErrTLSLimit) {
		t.Fatalf("ParseTLSRecords(oversize record) err = %v, want ErrTLSLimit", err)
	}

	// 3. ClientHello with IP literal in SNI + HTTP/3 ALPN over TCP triggers SNIIPLiteral, ALPNTransportMismatch, and 'i' in JA4.
	chIPRec := buildTLS13ClientHelloRecord("192.0.2.99", "h3")
	hs, err := ParseTLSRecords(chIPRec)
	if err != nil {
		t.Fatalf("ParseTLSRecords(SNI IP literal) err = %v", err)
	}
	if !hs.ClientHello.Anomalies.SNIIPLiteral || !hs.ClientHello.Anomalies.ALPNTransportMismatch {
		t.Fatalf("ClientHello.Anomalies = %+v, want SNIIPLiteral and ALPNTransportMismatch", hs.ClientHello.Anomalies)
	}
	if !strings.HasPrefix(hs.ClientHello.JA4, "t13i") {
		t.Fatalf("ClientHello.JA4 = %q, want 't13i' prefix for IP-literal SNI", hs.ClientHello.JA4)
	}
}
