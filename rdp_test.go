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

	if _, err := ParseRDPNegotiation([]byte{0x02, 0x00, 0x00}); !errors.Is(err, ErrInvalidRDP) {
		t.Fatalf("ParseRDPNegotiation(short) err = %v, want ErrInvalidRDP", err)
	}
}
