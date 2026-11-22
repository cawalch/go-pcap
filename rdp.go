package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const (
	x224CodeConnectionRequest uint8 = 0xe0
	x224CodeConnectionConfirm uint8 = 0xd0

	rdpTypeNegReq     uint8 = 0x01
	rdpTypeNegRsp     uint8 = 0x02
	rdpTypeNegFailure uint8 = 0x03
)

// RDPNegotiation contains metadata parsed from an RDP TPKT / X.224 Connection
// Request or Connection Confirm PDU (MS-RDPBCGR §2.2.1.1 / §2.2.1.2).
type RDPNegotiation struct {
	IsConfirm          bool
	Cookie             string
	RequestedProtocols uint32
	SelectedProtocol   uint32
	Flags              uint8
	FailureCode        uint32
	HasNegReq          bool
	HasNegRsp          bool
	HasNegFailure      bool
}

// RDPRecord associates a parsed [RDPNegotiation] with its 5-tuple TCP flow in a
// [Capture].
type RDPRecord struct {
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	Negotiation RDPNegotiation
}

// ParseRDPNegotiation parses a TPKT (version 3) and X.224 Connection Request or
// Connection Confirm PDU and extracts the RDP cookie (mstshash=...) and
// RDP_NEG_REQ / RDP_NEG_RSP / RDP_NEG_FAILURE security protocol flags.
func ParseRDPNegotiation(buf []byte) (RDPNegotiation, error) {
	if len(buf) < 11 {
		return RDPNegotiation{}, fmt.Errorf("%w: buffer shorter than 11-byte TPKT+X.224 header", ErrInvalidRDP)
	}
	// TPKT header: Version == 3, Reserved == 0, 16-bit BigEndian total length.
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return RDPNegotiation{}, fmt.Errorf("%w: missing TPKT version 3 header", ErrInvalidRDP)
	}
	tpktLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if tpktLen < 11 || tpktLen > MaxRDPPacketBytes || tpktLen > len(buf) {
		return RDPNegotiation{}, fmt.Errorf("%w: invalid TPKT length %d", ErrInvalidRDP, tpktLen)
	}

	x224Len := int(buf[4])
	x224Code := buf[5] & 0xf0
	if 5+x224Len > tpktLen || (x224Code != x224CodeConnectionRequest && x224Code != x224CodeConnectionConfirm) {
		return RDPNegotiation{}, fmt.Errorf("%w: invalid X.224 connection PDU code %#x", ErrInvalidRDP, buf[5])
	}

	out := RDPNegotiation{
		IsConfirm: x224Code == x224CodeConnectionConfirm,
	}

	// Variable part of X.224 TPDU starts at offset 11 (after 4-byte TPKT + 7-byte fixed X.224 header).
	varData := buf[11:tpktLen]
	if !out.IsConfirm && bytes.HasPrefix(varData, []byte("Cookie:")) {
		lineEnd := bytes.Index(varData, []byte("\r\n"))
		if lineEnd < 0 || lineEnd > MaxRDPCookieBytes {
			return RDPNegotiation{}, fmt.Errorf("%w: unterminated or oversize RDP Cookie", ErrRDPLimit)
		}
		out.Cookie = strings.TrimSpace(string(varData[len("Cookie:"):lineEnd]))
		varData = varData[lineEnd+2:]
	}

	if len(varData) >= 8 && varData[2] == 0x08 && varData[3] == 0x00 {
		negType := varData[0]
		out.Flags = varData[1]
		val := binary.LittleEndian.Uint32(varData[4:8])
		switch negType {
		case rdpTypeNegReq:
			out.HasNegReq = true
			out.RequestedProtocols = val
		case rdpTypeNegRsp:
			out.HasNegRsp = true
			out.SelectedProtocol = val
		case rdpTypeNegFailure:
			out.HasNegFailure = true
			out.FailureCode = val
		}
	}

	return out, nil
}

// RDP extracts RDP TPKT / X.224 negotiation PDUs across all reassembled TCP
// streams in the capture.
func (c *Capture) RDP(data []byte) ([]RDPRecord, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	var records []RDPRecord
	for i := range streams {
		st := &streams[i]
		if len(st.Client.Data) >= 11 && st.Client.Data[0] == 0x03 && st.Client.Data[1] == 0x00 {
			if neg, err := ParseRDPNegotiation(st.Client.Data); err == nil {
				if len(records) >= MaxRDPRecordsPerScan {
					return nil, fmt.Errorf("%w: exceeds %d RDP records", ErrRDPLimit, MaxRDPRecordsPerScan)
				}
				records = append(records, RDPRecord{
					FlowIndex:   st.FlowIndex,
					SrcAddr:     st.SrcAddr,
					DstAddr:     st.DstAddr,
					SrcPort:     st.SrcPort,
					DstPort:     st.DstPort,
					Negotiation: neg,
				})
			}
		}
		if len(st.Server.Data) >= 11 && st.Server.Data[0] == 0x03 && st.Server.Data[1] == 0x00 {
			if neg, err := ParseRDPNegotiation(st.Server.Data); err == nil {
				if len(records) >= MaxRDPRecordsPerScan {
					return nil, fmt.Errorf("%w: exceeds %d RDP records", ErrRDPLimit, MaxRDPRecordsPerScan)
				}
				records = append(records, RDPRecord{
					FlowIndex:   st.FlowIndex,
					SrcAddr:     st.DstAddr,
					DstAddr:     st.SrcAddr,
					SrcPort:     st.DstPort,
					DstPort:     st.SrcPort,
					Negotiation: neg,
				})
			}
		}
	}
	return records, nil
}
