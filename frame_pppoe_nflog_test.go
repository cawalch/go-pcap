package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func pppoeSession(ip []byte) []byte {
	data := []byte{0x11, 0, 0, 1, 0, 0, 0, 0x21}
	binary.BigEndian.PutUint16(data[4:], uint16(len(ip)+2))
	return append(data, ip...)
}

func nflogHeader() []byte {
	return []byte{2, 0, 0, 1}
}

func appendNFLOGTLV(data []byte, order binary.ByteOrder, kind uint16, value []byte) []byte {
	var header [4]byte
	length := 4 + len(value)
	order.PutUint16(header[:2], uint16(length))
	order.PutUint16(header[2:], kind)
	data = append(data, header[:]...)
	data = append(data, value...)
	return append(data, make([]byte, (4-length%4)%4)...)
}

func framingIPv4TCP(payload []byte) []byte {
	return buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 5000, 443, 1, 0, TCPFlagSYN, payload)[14:]
}

func TestPPPoEAndNFLOGFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/framing/pppoe-nflog.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, packets := readWrittenPackets(t, raw)
	if c.Anomalies().UnknownLinkType || len(packets) != 2 {
		t.Fatalf("packets = %d, anomalies %+v", len(packets), c.Anomalies())
	}
	for i, pkt := range packets {
		data, err := c.PacketPayload(raw, pkt)
		if err != nil {
			t.Fatal(err)
		}
		f, err := DecodeFrame(data, pkt.LinkType)
		if err != nil || f.Anomalies.Any() || f.IPProtocol != IPProtoTCP ||
			f.SrcPort != uint16(50100+i) || f.DstPort != 443 ||
			f.Layers[0].Proto != []LayerProto{LayerPPPoE, LayerNFLOG}[i] {
			t.Fatalf("packet %d = %+v, %v", i, f, err)
		}
	}
	r := bytes.NewReader(raw)
	file, err := NewFromReaderAt(r, r.Size())
	if err != nil || file.Anomalies().UnknownLinkType {
		t.Fatalf("ReaderAt capture = %v, %v", file, err)
	}
	checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
}

func TestDecodePPPoESessionBounds(t *testing.T) {
	session := pppoeSession(framingIPv4TCP([]byte("123")))
	for _, wire := range [][]byte{session[:5], session[:len(session)-1], append([]byte{0x11, 0, 0, 1, 0, 2}, session[6:]...)} {
		f, err := DecodeFrame(wire, LinkTypePPPEther)
		if err != nil || !f.Anomalies.TruncatedLayer || f.IPVersion != 0 {
			t.Fatalf("truncated PPPoE = %+v, %v", f, err)
		}
	}
	f, err := DecodeFrame(append(session, 1, 2, 3), LinkTypePPPEther)
	if err != nil || f.Anomalies.Any() || f.PayloadLength != 3 {
		t.Fatalf("PPPoE with trailing bytes = %+v, %v", f, err)
	}
	session[1] = 0xa7 // Discovery stage termination.
	f, err = DecodeFrame(session, LinkTypePPPEther)
	if err != nil || f.IPVersion != 0 {
		t.Fatalf("PPPoE discovery = %+v, %v", f, err)
	}
}

func TestDecodeNFLOGByteOrders(t *testing.T) {
	ip := framingIPv4TCP([]byte("123"))
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := appendNFLOGTLV(nflogHeader(), order, 18, []byte{1}) // An attribute with padding.
		payload := appendNFLOGTLV(data, order, 9, ip)
		data = appendNFLOGTLV(payload, order, 18, []byte{2})
		f, err := DecodeFrame(data, LinkTypeNFLOG)
		if err != nil || f.Anomalies.Any() || f.PayloadOffset != 56 || f.PayloadLength != 3 ||
			f.SrcPort != 5000 || f.Layers[0] != (LayerSpan{LayerNFLOG, 0, 16}) {
			t.Fatalf("%s NFLOG = %+v, %v", order, f, err)
		}
	}
}

func TestDecodeNFLOGRejectsUnusableTLVs(t *testing.T) {
	le := binary.LittleEndian
	ip := framingIPv4TCP(nil)
	payload := appendNFLOGTLV(nflogHeader(), le, 9, ip)
	ambiguous := appendNFLOGTLV(nflogHeader(), le, 9, append(bytes.Clone(ip), make([]byte, 213)...))
	tooMany := bytes.Clone(payload)
	for range nflogMaxTLVs {
		tooMany = appendNFLOGTLV(tooMany, le, 18, nil)
	}
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"short header", payload[:3]},
		{"short TLV header", payload[:7]},
		{"TLV past end", payload[:len(payload)-1]},
		{"zero length", append(nflogHeader(), 0, 0, 9, 0)},
		{"empty payload", appendNFLOGTLV(nflogHeader(), le, 9, nil)},
		{"duplicate payload", appendNFLOGTLV(bytes.Clone(payload), le, 9, ip)},
		{"ambiguous byte order", ambiguous}, // First TLV length is 0x0101.
		{"too many TLVs", tooMany},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := DecodeFrame(tc.wire, LinkTypeNFLOG)
			if err != nil || !f.Anomalies.TruncatedLayer || f.IPVersion != 0 {
				t.Fatalf("NFLOG frame = %+v, %v", f, err)
			}
		})
	}
}

func TestPPPoEAndNFLOGExtendedPrefixes(t *testing.T) {
	le := binary.LittleEndian
	longIP := framingIPv4TCP(make([]byte, 512))
	nflog := appendNFLOGTLV(nflogHeader(), le, 9, framingIPv4TCP(nil))
	shortPrefix := appendNFLOGTLV(bytes.Clone(nflog), le, 18, make([]byte, 256-len(nflog)-4))
	wrappedPrefix := appendNFLOGTLV(bytes.Clone(nflog), le, 18, make([]byte, 100-len(nflog)-4))
	for _, tc := range []struct {
		name  string
		link  LinkType
		wire  []byte
		flows int
	}{
		{"PPPoE", LinkTypePPPEther, pppoeSession(longIP), 1},
		{"NFLOG payload past prefix", LinkTypeNFLOG, appendNFLOGTLV(nflogHeader(), le, 9, longIP), 1},
		{"NFLOG valid suffix", LinkTypeNFLOG, appendNFLOGTLV(bytes.Clone(shortPrefix), le, 18, []byte{1}), 1},
		{"NFLOG malformed suffix", LinkTypeNFLOG, append(shortPrefix, 2, 0, 18, 0), 0},
		{"PKTAP NFLOG malformed suffix", LinkTypeApplePktap, pktapFrame(156, 239, append(wrappedPrefix, 2, 0, 18, 0)), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildClassicPCAP(le, false, tc.link, MaxSnapLen, [][]byte{tc.wire})
			c, _ := readWrittenPackets(t, raw)
			r := bytes.NewReader(raw)
			file, err := NewFromReaderAt(r, r.Size())
			if err != nil || file.Anomalies().UnknownLinkType {
				t.Fatalf("ReaderAt capture = %v, %v", file, err)
			}
			flows := checkReaderParity(t, raw, c.Flows, file.FlowsFromReaderAt)
			if len(flows) != tc.flows || len(flows) == 1 && flows[0].DstPort != 443 {
				t.Fatalf("flows = %+v", flows)
			}
		})
	}
}

func BenchmarkDecodeFramePPPoEAndNFLOG(b *testing.B) {
	ip := framingIPv4TCP([]byte("payload"))
	for _, tc := range []struct {
		name string
		link LinkType
		wire []byte
	}{
		{"PPPoE", LinkTypePPPEther, pppoeSession(ip)},
		{"NFLOG", LinkTypeNFLOG, appendNFLOGTLV(nflogHeader(), binary.LittleEndian, 9, ip)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if f, err := DecodeFrame(tc.wire, tc.link); err != nil || f.IPVersion != 4 {
					b.Fatal(f, err)
				}
			}
		})
	}
}
