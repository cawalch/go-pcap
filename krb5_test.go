package pcap

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"testing"
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
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{f1, f2})

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
