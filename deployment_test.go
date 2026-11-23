package pcap

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"os"
	"slices"
	"testing"
)

// TShark commands, packet numbering and capture provenance are in
// testdata/deployments/README.md.
func TestDeploymentCaptures(t *testing.T) {
	type flow struct {
		protocol       uint8
		source, target string
		packets        int
	}
	type handshake struct {
		flow      int
		sni, alpn string
		suite     uint16
	}
	for _, tc := range []struct {
		name            string
		wireLengths     []uint32
		flows           []flow
		dnsFrames       []int
		dnsFlow         int
		dnsName         string
		dnsAnswer       string
		handshakes      []handshake
		exportFlow      int
		exportInterface string
		exportFrames    []int
		attributed      int
		truncatedFrame  int
	}{
		{
			name:        "client",
			wireLengths: []uint32{73, 54, 89, 54, 54, 202, 149, 54, 54, 54, 54, 54, 76, 54},
			flows: []flow{
				{IPProtoUDP, "192.0.2.14:53000", "192.0.2.53:53", 2},
				{IPProtoTCP, "192.0.2.14:50000", "198.51.100.80:443", 11},
				{IPProtoTCP, "192.0.2.14:50001", "198.51.100.81:443", 1},
			},
			dnsFrames:       []int{1, 3},
			dnsFlow:         0,
			dnsName:         "trace.example",
			dnsAnswer:       "198.51.100.80",
			handshakes:      []handshake{{1, "trace.example", "h2", 0x1301}},
			exportFlow:      1,
			exportInterface: "client-before-nat",
			exportFrames:    []int{2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14},
			truncatedFrame:  13,
		},
		{
			name:        "proxy",
			wireLengths: []uint32{54, 54, 54, 54, 54, 54, 200, 209, 149, 149, 91, 91},
			flows: []flow{
				{IPProtoTCP, "192.0.2.21:51000", "192.0.2.10:443", 6},
				{IPProtoTCP, "198.51.100.10:52000", "198.51.100.90:443", 6},
			},
			handshakes: []handshake{
				{0, "app.example", "h2", 0x1301},
				{1, "origin.example", "http/1.1", 0x1302},
			},
			exportFlow:      1,
			exportInterface: "proxy-origin",
			exportFrames:    []int{2, 4, 6, 8, 10, 12},
			attributed:      8,
		},
		{
			name:        "iot",
			wireLengths: []uint32{286, 298, 77, 47, 93, 47},
			flows: []flow{
				{IPProtoUDP, "0.0.0.0:68", "255.255.255.255:67", 1},
				{IPProtoUDP, "203.0.113.1:67", "255.255.255.255:68", 1},
				{IPProtoUDP, "203.0.113.42:53001", "203.0.113.1:53", 2},
				{IPProtoUDP, "203.0.113.42:48000", "203.0.113.7:49555", 2},
			},
			dnsFrames:       []int{3, 5},
			dnsFlow:         2,
			dnsName:         "collector.example",
			dnsAnswer:       "203.0.113.7",
			exportFlow:      3,
			exportInterface: "iot-local",
			exportFrames:    []int{4, 6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/deployments/" + tc.name + ".pcapng")
			if err != nil {
				t.Fatal(err)
			}
			reader := bytes.NewReader(raw)
			capture, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			fromReader, err := NewFromReaderAt(reader, reader.Size())
			if err != nil {
				t.Fatal(err)
			}

			packets := checkReaderParity(t, raw, capture.Packets, fromReader.PacketsFromReaderAt)
			if capture.PacketCount != len(tc.wireLengths) || fromReader.PacketCount != capture.PacketCount || len(packets) != capture.PacketCount {
				t.Fatalf("packet counts = %d/%d/%d, want %d", capture.PacketCount, fromReader.PacketCount, len(packets), len(tc.wireLengths))
			}
			for i, pkt := range packets {
				wireLen := tc.wireLengths[i]
				captureLen := wireLen
				if i+1 == tc.truncatedFrame {
					captureLen = 58
				}
				if pkt.Index != i || pkt.OriginalLen != wireLen || pkt.CaptureLen != captureLen {
					t.Errorf("frame %d: index=%d lengths=%d/%d, want %d and %d/%d", i+1, pkt.Index, pkt.CaptureLen, pkt.OriginalLen, i, captureLen, wireLen)
				}
				if i+1 == tc.attributed {
					if !pkt.HasProcessID || pkt.ProcessID != 4242 || pkt.ProcessName != "fixture-proxy" {
						t.Errorf("frame %d: attribution = %+v", i+1, pkt)
					}
				} else if pkt.HasProcessID || pkt.ProcessName != "" {
					t.Errorf("frame %d: unexpected attribution = %+v", i+1, pkt)
				}
			}

			flows := checkReaderParity(t, raw, capture.Flows, fromReader.FlowsFromReaderAt)
			if len(flows) != len(tc.flows) {
				t.Fatalf("flows = %+v, want %d", flows, len(tc.flows))
			}
			for i, got := range flows {
				want := tc.flows[i]
				if got.Protocol != want.protocol || got.PacketCount != want.packets ||
					netip.AddrPortFrom(got.SrcAddr, got.SrcPort).String() != want.source ||
					netip.AddrPortFrom(got.DstAddr, got.DstPort).String() != want.target {
					t.Errorf("flow %d = %+v, want %+v", i, got, want)
				}
			}
			if tc.name == "client" && (!flows[1].Anomalies.IPTotalLengthExceedsFrame || flows[2].TCPFlags != TCPFlagSYN) {
				t.Errorf("client truncation or unanswered SYN missing: %+v", flows)
			}
			if tc.name == "proxy" && (flows[0].HasProcessID || !flows[1].HasProcessID || flows[1].ProcessName != "fixture-proxy") {
				t.Errorf("front and back flow attribution = %+v", flows)
			}

			dns := checkReaderParity(t, raw, capture.DNS, fromReader.DNSFromReaderAt)
			if len(dns) != len(tc.dnsFrames) {
				t.Fatalf("DNS records = %+v, want %d", dns, len(tc.dnsFrames))
			}
			for i, record := range dns {
				packet := packets[tc.dnsFrames[i]-1]
				msg := record.Message
				if record.PacketIndex != packet.Index || record.TimestampNs != packet.TimestampNs || record.FlowIndex != tc.dnsFlow ||
					msg.TransactionID != 0x1020 || msg.RCode != 0 || len(msg.Questions) != 1 ||
					msg.Questions[0].Name != tc.dnsName || msg.Questions[0].Type != DNSTypeA {
					t.Errorf("DNS record %d = %+v", i, record)
				}
			}
			if len(dns) == 2 {
				query, reply := dns[0].Message, dns[1].Message
				if query.IsResponse || len(query.Answers) != 0 || !reply.IsResponse ||
					len(reply.Answers) != 1 || reply.Answers[0].Address.String() != tc.dnsAnswer {
					t.Errorf("DNS query/reply = %+v / %+v, want A %s", query, reply, tc.dnsAnswer)
				}
			}

			dhcp := checkReaderParity(t, raw, capture.DHCPv4, fromReader.DHCPv4FromReaderAt)
			if tc.name == "iot" {
				if len(dhcp) != 2 {
					t.Fatalf("DHCP observations = %+v, want Discover and Offer", dhcp)
				}
				for i, record := range dhcp {
					pkt := packets[i]
					wantType := []DHCPv4MessageType{DHCPv4Discover, DHCPv4Offer}[i]
					if record.PacketIndex != pkt.Index || record.TimestampNs != pkt.TimestampNs || record.InterfaceID != pkt.InterfaceID ||
						record.MessageType != wantType || record.TransactionID != 0x31514159 ||
						record.ClientHardwareAddr.String() != "02:00:00:00:00:2a" {
						t.Errorf("DHCP observation %d = %+v", i, record)
					}
				}
				discover, offer := dhcp[0], dhcp[1]
				if discover.YourAddr.IsValid() || discover.HasLease ||
					offer.YourAddr.String() != "203.0.113.42" || offer.ServerIdentifier.String() != "203.0.113.1" ||
					!offer.HasLease || offer.LeaseSeconds != 3600 {
					t.Errorf("DHCP discover/offer = %+v / %+v", discover, offer)
				}
			} else if len(dhcp) != 0 {
				t.Errorf("unexpected DHCP observations: %+v", dhcp)
			}

			tls := checkReaderParity(t, raw, capture.TLS, fromReader.TLSFromReaderAt)
			if len(tls) != len(tc.handshakes) {
				t.Fatalf("TLS records = %+v, want %d", tls, len(tc.handshakes))
			}
			for i, record := range tls {
				want := tc.handshakes[i]
				hs := record.Handshake
				if record.FlowIndex != want.flow ||
					netip.AddrPortFrom(record.SrcAddr, record.SrcPort).String() != tc.flows[want.flow].source ||
					netip.AddrPortFrom(record.DstAddr, record.DstPort).String() != tc.flows[want.flow].target ||
					!hs.HasClientHello || !hs.HasServerHello ||
					hs.ClientHello.SNI != want.sni || !slices.Equal(hs.ClientHello.ALPNs, []string{want.alpn}) ||
					hs.ServerHello.NegotiatedVersion != TLSVersion13 || hs.ServerHello.CipherSuite != want.suite {
					t.Errorf("TLS record %d = %+v, want %+v", i, record, want)
				}
				if hs.ServerHello.ALPN != "" || len(hs.Certificates) != 0 || len(hs.ClientCertificates) != 0 {
					t.Errorf("TLS record %d has unexpected negotiated ALPN or certificate data: %+v", i, hs)
				}
			}
			if tc.name == "proxy" {
				decrypted, err := capture.DecryptedTLSStreams(raw, nil)
				if err != nil || len(decrypted) != 0 {
					t.Errorf("unkeyed proxy traffic yielded %d decrypted streams, %v", len(decrypted), err)
				}
			}

			var export, fileExport bytes.Buffer
			if err := capture.ExtractFlowPCAPNG(raw, &export, tc.exportFlow); err != nil {
				t.Fatal(err)
			}
			if err := fromReader.ExtractFlowPCAPNGFromReaderAt(reader, &fileExport, tc.exportFlow); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(export.Bytes(), fileExport.Bytes()) {
				t.Fatal("slice and ReaderAt exports differ")
			}
			extracted, outgoing := readWrittenPackets(t, export.Bytes())
			if len(outgoing) != len(tc.exportFrames) || len(extracted.Interfaces) != 1 {
				t.Fatalf("export has %d packets on %d interfaces, want %d on 1", len(outgoing), len(extracted.Interfaces), len(tc.exportFrames))
			}
			for i, frame := range tc.exportFrames {
				want := packets[frame-1]
				got := outgoing[i]
				if got.Index != i || got.InterfaceID != 0 || extracted.Interfaces[0].Name != tc.exportInterface ||
					capture.Interfaces[want.InterfaceID].Name != tc.exportInterface {
					t.Errorf("export frame %d has wrong index or interface: %+v", i+1, got)
				}
				in, err := capture.PacketPayload(raw, want)
				if err != nil {
					t.Fatal(err)
				}
				out, err := extracted.PacketPayload(export.Bytes(), got)
				if err != nil {
					t.Fatal(err)
				}
				want.Index, want.InterfaceID, want.PayloadOffset = i, 0, got.PayloadOffset
				if got != want || !bytes.Equal(in, out) {
					t.Errorf("export frame %d differs from source frame %d", i+1, frame)
				}
				if tc.name == "iot" {
					decoded, err := DecodeFrame(out, got.LinkType)
					if err != nil {
						t.Fatal(err)
					}
					payload := out[decoded.PayloadOffset : decoded.PayloadOffset+decoded.PayloadLength]
					wantHex := []string{"d391ee0102", "d391ee0304"}[i]
					if hex.EncodeToString(payload) != wantHex {
						t.Errorf("opaque UDP frame %d payload = %x, want %s", frame, payload, wantHex)
					}
				}
			}
		})
	}
}
