package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func buildRDPConnReqPDU(cookie string, reqProtocols uint32) []byte {
	var varPart bytes.Buffer
	if cookie != "" {
		varPart.WriteString("Cookie: ")
		varPart.WriteString(cookie)
		varPart.WriteString("\r\n")
	}
	var negReq [8]byte
	negReq[0] = rdpTypeNegReq
	negReq[1] = 0x00
	binary.LittleEndian.PutUint16(negReq[2:4], 8)
	binary.LittleEndian.PutUint32(negReq[4:8], reqProtocols)
	varPart.Write(negReq[:])

	totalLen := 11 + varPart.Len()
	pdu := make([]byte, totalLen)
	pdu[0] = 0x03 // TPKT v3
	pdu[1] = 0x00
	binary.BigEndian.PutUint16(pdu[2:4], uint16(totalLen))
	pdu[4] = byte(totalLen - 5) // X.224 length indicator
	pdu[5] = x224CodeConnectionRequest
	copy(pdu[11:], varPart.Bytes())
	return pdu
}

func buildRDPConnConfirmPDU(selectedProtocol uint32) []byte {
	var negRsp [8]byte
	negRsp[0] = rdpTypeNegRsp
	negRsp[1] = 0x0f
	binary.LittleEndian.PutUint16(negRsp[2:4], 8)
	binary.LittleEndian.PutUint32(negRsp[4:8], selectedProtocol)

	totalLen := 11 + len(negRsp)
	pdu := make([]byte, totalLen)
	pdu[0] = 0x03
	pdu[1] = 0x00
	binary.BigEndian.PutUint16(pdu[2:4], uint16(totalLen))
	pdu[4] = byte(totalLen - 5)
	pdu[5] = x224CodeConnectionConfirm
	copy(pdu[11:], negRsp[:])
	return pdu
}

func TestParseRDPNegotiationAndCaptureRDP(t *testing.T) {
	reqPDU := buildRDPConnReqPDU("mstshash=ADMINISTRATOR", RDPProtoTLS|RDPProtoCredSSP)
	rspPDU := buildRDPConnConfirmPDU(RDPProtoCredSSP)

	req, err := ParseRDPNegotiation(reqPDU)
	if err != nil {
		t.Fatalf("ParseRDPNegotiation(req) error = %v", err)
	}
	if req.IsConfirm || req.Cookie != "mstshash=ADMINISTRATOR" || !req.HasNegReq || req.RequestedProtocols != (RDPProtoTLS|RDPProtoCredSSP) {
		t.Fatalf("ParseRDPNegotiation(req) = %+v", req)
	}

	rsp, err := ParseRDPNegotiation(rspPDU)
	if err != nil {
		t.Fatalf("ParseRDPNegotiation(rsp) error = %v", err)
	}
	if !rsp.IsConfirm || !rsp.HasNegRsp || rsp.SelectedProtocol != RDPProtoCredSSP {
		t.Fatalf("ParseRDPNegotiation(rsp) = %+v", rsp)
	}

	// Test Capture.RDP across a bidirectional TCP stream on port 3389.
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 53000, 3389, 100, 0, TCPFlagSYN, nil)
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 3389, 53000, 200, 101, TCPFlagSYN|TCPFlagACK, nil)
	f3 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 53000, 3389, 101, 201, TCPFlagPSH|TCPFlagACK, reqPDU)
	f4 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 3389, 53000, 201, 101+uint32(len(reqPDU)), TCPFlagPSH|TCPFlagACK, rspPDU)

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{f1, f2, f3, f4})
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.RDP(raw)
	if err != nil || len(records) != 2 {
		t.Fatalf("Capture.RDP() = (%d, %v), want 2", len(records), err)
	}
	if records[0].Negotiation.Cookie != "mstshash=ADMINISTRATOR" || records[1].Negotiation.SelectedProtocol != RDPProtoCredSSP {
		t.Fatalf("RDPRecords = %+v", records)
	}
	if records[0].SrcPort != 53000 || records[0].DstPort != 3389 ||
		records[1].SrcPort != 3389 || records[1].DstPort != 53000 ||
		records[0].SrcAddr != records[1].DstAddr || records[0].DstAddr != records[1].SrcAddr ||
		records[0].FlowIndex != records[1].FlowIndex {
		t.Fatalf("unexpected RDP record attribution: %+v", records)
	}

	if _, err := ParseRDPNegotiation([]byte{0x02, 0x00, 0x00}); !errors.Is(err, ErrInvalidRDP) {
		t.Fatalf("ParseRDPNegotiation(short) err = %v, want ErrInvalidRDP", err)
	}

	// x224Len < 6 must be rejected.
	badX224 := bytes.Clone(reqPDU)
	badX224[4] = 5
	if _, err := ParseRDPNegotiation(badX224); !errors.Is(err, ErrInvalidRDP) {
		t.Fatalf("ParseRDPNegotiation(x224Len=5) err = %v, want ErrInvalidRDP", err)
	}

	// Non-RDP TPKT/X.224 (e.g. ISO-TSAP on port 102 without Cookie/RDP_NEG_*) must not be emitted by Capture.RDP.
	isoTSAP := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, x224CodeConnectionRequest, 0, 0, 0, 1, 0}
	isoPkt := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 50000, 102, 1, 1, TCPFlagPSH|TCPFlagACK, isoTSAP)
	isoRaw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{isoPkt})
	isoCap, err := New(isoRaw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := isoCap.RDP(isoRaw); err != nil || len(got) != 0 {
		t.Fatalf("Capture.RDP(ISO-TSAP) = (%+v, %v), want empty", got, err)
	}
}
