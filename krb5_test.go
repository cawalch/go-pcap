package pcap

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func asn1WrapExplicit(tag int, class int, inner []byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{
		Class:      class,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	})
	return b
}

func buildKRB5Principal(nameType int, parts ...string) []byte {
	ntBytes, _ := asn1.Marshal(nameType)
	var strSeq []byte
	for _, p := range parts {
		sb, _ := asn1.Marshal(p)
		strSeq = append(strSeq, sb...)
	}
	seqStr := asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, strSeq)
	body := append(
		asn1WrapExplicit(0, asn1.ClassContextSpecific, ntBytes),
		asn1WrapExplicit(1, asn1.ClassContextSpecific, seqStr)...,
	)
	return asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, body)
}

func buildKRB5ASReqFixture(realm string, cname string, sname []string, etypes []int) []byte {
	pvno, _ := asn1.Marshal(5)
	msgType, _ := asn1.Marshal(int(KRB5MsgASReq))
	kdcOpts, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x40, 0, 0, 0}, BitLength: 32})
	realmBytes, _ := asn1.Marshal(realm)
	var etypeSeq []byte
	for _, et := range etypes {
		eb, _ := asn1.Marshal(et)
		etypeSeq = append(etypeSeq, eb...)
	}
	var reqBody []byte
	reqBody = append(reqBody, asn1WrapExplicit(0, asn1.ClassContextSpecific, kdcOpts)...)
	reqBody = append(reqBody, asn1WrapExplicit(1, asn1.ClassContextSpecific, buildKRB5Principal(1, cname))...)
	reqBody = append(reqBody, asn1WrapExplicit(2, asn1.ClassContextSpecific, realmBytes)...)
	reqBody = append(reqBody, asn1WrapExplicit(3, asn1.ClassContextSpecific, buildKRB5Principal(2, sname...))...)
	reqBody = append(reqBody, asn1WrapExplicit(8, asn1.ClassContextSpecific, asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, etypeSeq))...)

	var kdcReq []byte
	kdcReq = append(kdcReq, asn1WrapExplicit(1, asn1.ClassContextSpecific, pvno)...)
	kdcReq = append(kdcReq, asn1WrapExplicit(2, asn1.ClassContextSpecific, msgType)...)
	kdcReq = append(kdcReq, asn1WrapExplicit(4, asn1.ClassContextSpecific, asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, reqBody))...)

	innerSeq := asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, kdcReq)
	return asn1WrapExplicit(int(KRB5MsgASReq), asn1.ClassApplication, innerSeq)
}

func TestParseKRB5AndCaptureKerberos(t *testing.T) {
	asReq := buildKRB5ASReqFixture("CORP.EXAMPLE.COM", "jdoe", []string{"krbtgt", "CORP.EXAMPLE.COM"}, []int{18, int(KRB5ETypeRC4HMAC)})

	msg, err := ParseKRB5(asReq)
	if err != nil {
		t.Fatalf("ParseKRB5() error = %v", err)
	}
	if msg.PVNO != 5 || msg.MsgType != KRB5MsgASReq || msg.Realm != "CORP.EXAMPLE.COM" {
		t.Fatalf("ParseKRB5() = %+v", msg)
	}
	if len(msg.ClientNames) != 1 || msg.ClientNames[0] != "jdoe" {
		t.Fatalf("ClientNames = %v, want [jdoe]", msg.ClientNames)
	}
	if len(msg.ServiceNames) != 2 || msg.ServiceNames[0] != "krbtgt" || !msg.HasRC4HMAC {
		t.Fatalf("ServiceNames=%v, HasRC4HMAC=%v", msg.ServiceNames, msg.HasRC4HMAC)
	}

	// Test 4-byte TCP record-marked Kerberos message in a capture on port 88.
	tcpKRB := make([]byte, 4+len(asReq))
	binary.BigEndian.PutUint32(tcpKRB[0:4], uint32(len(asReq)))
	copy(tcpKRB[4:], asReq)

	f1 := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 88}, 52000, 88, asReq)
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 88}, 52001, 88, 1, 1, TCPFlagPSH|TCPFlagACK, tcpKRB)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, append([][]byte{buildEthernetIPv4TCPFrame([4]byte{1}, [4]byte{2}, 123, 443, 1, 0, TCPFlagACK, nil)}, f1, f2))

	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.Kerberos(raw)
	if err != nil || len(records) != 2 {
		t.Fatalf("Capture.Kerberos() = (%d, %v), want 2", len(records), err)
	}
	if !records[0].Message.HasRC4HMAC || records[1].Message.Realm != "CORP.EXAMPLE.COM" {
		t.Fatalf("KRB5Record = %+v", records)
	}

	if _, err := ParseKRB5([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidKRB5) {
		t.Fatalf("ParseKRB5(short) err = %v, want ErrInvalidKRB5", err)
	}
}

func TestKRB5ErrorClientIdentity(t *testing.T) {
	const serviceRealm = "SERVICE.EXAMPLE"
	const clientRealm = "CLIENT.EXAMPLE"

	var frames [][]byte
	tests := []struct {
		name        string
		code        int32
		clientRealm string
		clientNames []string
	}{
		{"client identity", 24, clientRealm, []string{"alice", "admin"}},
		{"client realm only", 6, clientRealm, nil},
		{"client name only", 6, "", []string{"alice"}},
		{"no client identity", 25, "", nil},
	}
	for _, tt := range tests {
		var fields []byte
		add := func(tag int, data []byte) {
			fields = append(fields, asn1WrapExplicit(tag, asn1.ClassContextSpecific, data)...)
		}
		addInt := func(tag, value int) {
			data, _ := asn1.Marshal(value)
			add(tag, data)
		}
		addRealm := func(tag int, realm string) {
			data, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(realm)})
			add(tag, data)
		}
		addInt(0, 5)
		addInt(1, int(KRB5MsgError))
		stime, _ := asn1.MarshalWithParams(time.Unix(1_700_000_000, 0).UTC(), "generalized")
		add(4, stime)
		addInt(5, 0)
		addInt(6, int(tt.code))
		if tt.clientRealm != "" {
			addRealm(7, tt.clientRealm)
		}
		if len(tt.clientNames) > 0 {
			add(8, buildKRB5Principal(1, tt.clientNames...))
		}
		addRealm(9, serviceRealm)
		add(10, buildKRB5Principal(2, "krbtgt", serviceRealm))
		wire := asn1WrapExplicit(int(KRB5MsgError), asn1.ClassApplication,
			asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, fields))
		frames = append(frames, buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 88}, [4]byte{10, 0, 0, 5}, 88, 52000, wire))

		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseKRB5(wire)
			if err != nil {
				t.Fatal(err)
			}
			if msg.MsgType != KRB5MsgError || msg.ErrorCode != tt.code || msg.Realm != serviceRealm ||
				msg.ClientRealm != tt.clientRealm || !slices.Equal(msg.ClientNames, tt.clientNames) ||
				!slices.Equal(msg.ServiceNames, []string{"krbtgt", serviceRealm}) {
				t.Fatalf("KRB-ERROR = %+v", msg)
			}
		})
	}

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.Kerberos(raw)
	if err != nil || len(records) != len(tests) {
		t.Fatalf("Capture.Kerberos() = (%d, %v), want %d records", len(records), err, len(tests))
	}
	for i, record := range records {
		tt := tests[i]
		if record.PacketIndex != i || record.DstAddr != netip.MustParseAddr("10.0.0.5") ||
			record.Message.ErrorCode != tt.code || record.Message.ClientRealm != tt.clientRealm ||
			!slices.Equal(record.Message.ClientNames, tt.clientNames) {
			t.Fatalf("Kerberos record %d = %+v", i, record)
		}
	}
}

func buildKRB5TGSRepFixture(realm string, cname string, sname []string, ticketEType int, encPartEType int) []byte {
	pvno, _ := asn1.Marshal(5)
	msgType, _ := asn1.Marshal(int(KRB5MsgTGSRep))
	realmBytes, _ := asn1.Marshal(realm)

	encData := func(etype int) []byte {
		etB, _ := asn1.Marshal(etype)
		cipherB, _ := asn1.Marshal([]byte{0xde, 0xad, 0xbe, 0xef})
		seq := append(
			asn1WrapExplicit(0, asn1.ClassContextSpecific, etB),
			asn1WrapExplicit(2, asn1.ClassContextSpecific, cipherB)...,
		)
		return asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, seq)
	}

	tktVno, _ := asn1.Marshal(5)
	var tktBody []byte
	tktBody = append(tktBody, asn1WrapExplicit(0, asn1.ClassContextSpecific, tktVno)...)
	tktBody = append(tktBody, asn1WrapExplicit(1, asn1.ClassContextSpecific, realmBytes)...)
	tktBody = append(tktBody, asn1WrapExplicit(2, asn1.ClassContextSpecific, buildKRB5Principal(2, sname...))...)
	tktBody = append(tktBody, asn1WrapExplicit(3, asn1.ClassContextSpecific, encData(ticketEType))...)
	ticket := asn1WrapExplicit(1, asn1.ClassApplication, asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, tktBody))

	var repBody []byte
	repBody = append(repBody, asn1WrapExplicit(0, asn1.ClassContextSpecific, pvno)...)
	repBody = append(repBody, asn1WrapExplicit(1, asn1.ClassContextSpecific, msgType)...)
	repBody = append(repBody, asn1WrapExplicit(3, asn1.ClassContextSpecific, realmBytes)...)
	repBody = append(repBody, asn1WrapExplicit(4, asn1.ClassContextSpecific, buildKRB5Principal(1, cname))...)
	repBody = append(repBody, asn1WrapExplicit(5, asn1.ClassContextSpecific, ticket)...)
	repBody = append(repBody, asn1WrapExplicit(6, asn1.ClassContextSpecific, encData(encPartEType))...)

	return asn1WrapExplicit(int(KRB5MsgTGSRep), asn1.ClassApplication, asn1WrapExplicit(asn1.TagSequence, asn1.ClassUniversal, repBody))
}

func TestKRB5UDPRecordMarkCollisionRepliesAndMultiSegmentTCP(t *testing.T) {
	// 1. UDP Kerberos message whose byte 4 has bits 0x60 set (e.g., long-form outer length
	//    with inner SEQUENCE length 0x64) must NOT be misclassified as a 4-byte TCP record mark.
	tgsRep := buildKRB5TGSRepFixture("CORP.EXAMPLE.COM", "jdoe", []string{"MSSQLSvc", "sql01.corp.example.com"}, int(KRB5ETypeRC4HMAC), 18)
	if len(tgsRep) < 5 || (tgsRep[4]&0x60) != 0x60 {
		// Pad cname slightly if needed so inner SEQUENCE length falls in 0x60..0x7f.
		tgsRep = buildKRB5TGSRepFixture("CORP.EXAMPLE.COM", "jdoe_long_principal", []string{"MSSQLSvc", "sql01.corp.example.com"}, int(KRB5ETypeRC4HMAC), 18)
	}
	msg, err := ParseKRB5(tgsRep)
	if err != nil {
		t.Fatalf("ParseKRB5(TGS-REP) error = %v", err)
	}
	if msg.MsgType != KRB5MsgTGSRep || !msg.HasRC4HMAC || len(msg.ServiceNames) != 2 || msg.ServiceNames[0] != "MSSQLSvc" {
		t.Fatalf("TGS-REP = %+v", msg)
	}
	if len(msg.ETypes) != 2 || msg.ETypes[0] != KRB5ETypeRC4HMAC || msg.ETypes[1] != 18 {
		t.Fatalf("TGS-REP ETypes = %v, want [23 18]", msg.ETypes)
	}

	// 2. Multi-segment pipelined TCP Kerberos messages on port 88.
	asReq := buildKRB5ASReqFixture("CORP.EXAMPLE.COM", "jdoe", []string{"krbtgt", "CORP.EXAMPLE.COM"}, []int{18})
	var tcpStream []byte
	for _, m := range [][]byte{asReq, tgsRep} {
		var mark [4]byte
		binary.BigEndian.PutUint32(mark[:], uint32(len(m)))
		tcpStream = append(tcpStream, mark[:]...)
		tcpStream = append(tcpStream, m...)
	}
	split := 2
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 88}, 52002, 88, 1, 1, TCPFlagPSH|TCPFlagACK, tcpStream[:split])
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 88}, 52002, 88, 1+uint32(split), 1, TCPFlagPSH|TCPFlagACK, tcpStream[split:])
	unrelated := buildEthernetIPv4TCPFrame([4]byte{1}, [4]byte{2}, 123, 443, 1, 0, TCPFlagACK, []byte("data"))
	frames := make([][]byte, MaxSegmentsPerFlow+1)
	for i := range frames {
		frames[i] = unrelated
	}
	first := len(frames)
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, append(frames, f1, f2))

	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.Kerberos(raw)
	if err != nil || len(recs) != 2 {
		t.Fatalf("Capture.Kerberos(multi-segment TCP) = (%d, %v), want 2", len(recs), err)
	}
	if recs[0].PacketIndex != first || recs[1].PacketIndex != first+1 {
		t.Fatalf("packet attribution: %v", recs)
	}
	if recs[0].Message.MsgType != KRB5MsgASReq || recs[1].Message.MsgType != KRB5MsgTGSRep || !recs[1].Message.HasRC4HMAC {
		t.Fatalf("TCP Kerberos records = %+v", recs)
	}
}
