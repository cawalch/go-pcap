package pcap_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/cawalch/go-pcap"
)

func ExampleParseLDAP() {
	// LDAPv3 anonymous BindRequest.
	wire := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	msg, err := pcap.ParseLDAP(wire)
	if err != nil {
		panic(err)
	}
	fmt.Println(msg.MessageID, msg.Version, msg.AuthType)
	// Output:
	// 1 3 simple
}

func ExampleParseDCERPC() {
	// One little-endian DCE/RPC request fragment.
	wire := []byte{
		5, 0, 0, 3, 0x10, 0, 0, 0, 24, 0, 0, 0, 7, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 42, 0,
	}
	msg, err := pcap.ParseDCERPC(wire)
	if err != nil {
		panic(err)
	}
	fmt.Println(msg.CallID, msg.ContextID, msg.Opnum)
	// Output:
	// 7 1 42
}

func buildExampleEthernetUDPFrame() []byte {
	frame := make([]byte, 14+20+8+4)
	binary.BigEndian.PutUint16(frame[12:14], pcap.EtherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20+8+4)
	ip[8] = 64
	ip[9] = pcap.IPProtoUDP
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 51, 100, 53})

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 55000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(frame[42:], []byte("ping"))
	return frame
}

func buildExamplePCAPNG() []byte {
	var buf bytes.Buffer
	writer, err := pcap.NewPCAPNGWriter(&buf, pcap.PCAPNGWriterOptions{
		LinkType:      pcap.LinkTypeEthernet,
		SnapLen:       65535,
		InterfaceName: "en0",
	})
	if err != nil {
		log.Fatal(err)
	}
	err = writer.WriteNameResolution([]pcap.NameResolutionRecord{
		{Addr: netip.MustParseAddr("198.51.100.53"), Names: []string{"ns1.example.com"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	err = writer.WritePacket(pcap.PacketRecord{
		TimestampNs:  1700000000000000000,
		ProcessID:    4242,
		ProcessName:  "dig",
		HasProcessID: true,
	}, buildExampleEthernetUDPFrame())
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func ExampleNew() {
	data := buildExamplePCAPNG()
	capture, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	flows, err := capture.Flows(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("format=%s packets=%d host=%s proc=%s(%d) flow=%s:%d->%s:%d bytes=%d\n",
		capture.Format, capture.PacketCount,
		capture.NameRecords[0].Names[0],
		flows[0].ProcessName, flows[0].ProcessID,
		flows[0].SrcAddr, flows[0].SrcPort,
		flows[0].DstAddr, flows[0].DstPort,
		flows[0].ClientBytes)
	// Output:
	// format=pcapng packets=1 host=ns1.example.com proc=dig(4242) flow=192.0.2.10:55000->198.51.100.53:53 bytes=4
}

func ExampleNewFromReaderAt() {
	data := buildExamplePCAPNG()
	r := bytes.NewReader(data)
	capture, err := pcap.NewFromReaderAt(r, int64(len(data)))
	if err != nil {
		log.Fatal(err)
	}
	for pkt, err := range capture.PacketSeqFromReaderAt(r) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("format=%s packets=%d pid=%d\n", capture.Format, capture.PacketCount, pkt.ProcessID)
		break
	}
	// Output:
	// format=pcapng packets=1 pid=4242
}

func ExampleNew_compressedSignature() {
	_, err := pcap.New([]byte("\x28\xb5\x2f\xfd"))
	if errors.Is(err, pcap.ErrUnsupportedZstd) {
		fmt.Println("decode zstd before opening the capture")
	}
	// Output:
	// decode zstd before opening the capture
}

func ExampleNewFromReaderAt_spoolGzip() {
	// Simulate gzip bytes read from a pipe.
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(buildExamplePCAPNG()); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	input, err := gzip.NewReader(&compressed)
	if err != nil {
		panic(err)
	}
	defer func() { _ = input.Close() }()

	file, err := os.CreateTemp("", "capture-*.pcapng")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()

	const maxCaptureBytes = 128 << 20 // The application's disk budget per capture.
	size, err := io.Copy(file, io.LimitReader(input, maxCaptureBytes+1))
	if err != nil {
		panic(err)
	}
	if size > maxCaptureBytes {
		panic("capture exceeds the temporary file budget")
	}

	capture, err := pcap.NewFromReaderAt(file, size)
	if err != nil {
		panic(err)
	}
	if capture.InputTruncated() {
		panic("incomplete capture")
	}
	fmt.Printf("format=%s packets=%d\n", capture.Format, capture.PacketCount)
	// Output:
	// format=pcapng packets=1
}

func ExampleCapture_PacketSeq() {
	data := buildExamplePCAPNG()
	capture, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	for pkt, err := range capture.PacketSeq(data) {
		if err != nil {
			log.Fatal(err)
		}
		payload, err := capture.PacketPayload(data, pkt)
		if err != nil {
			log.Fatal(err)
		}
		frame, err := pcap.DecodeFrame(payload, pkt.LinkType)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("pkt=%d ipv=%d proto=%d payload=%s\n",
			pkt.Index, frame.IPVersion, frame.IPProtocol,
			payload[frame.PayloadOffset:frame.PayloadOffset+frame.PayloadLength])
	}
	// Output:
	// pkt=0 ipv=4 proto=17 payload=ping
}

func ExampleUnwrapProxyStream() {
	client := []byte("CONNECT example.org:443 HTTP/1.1\r\n\r\n")
	server := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	_, _, kind, host, port, ok := pcap.UnwrapProxyStream(client, server)
	fmt.Println(ok, kind, host, port)
	// Output: true http-connect example.org 443
}

func ExampleParseTLSRecords_recordLimit() {
	emptyRecord := []byte{pcap.TLSRecordHandshake, 3, 3, 0, 0}
	stream := bytes.Repeat(emptyRecord, pcap.MaxTLSHandshakeRecords+1)
	_, err := pcap.ParseTLSRecords(stream)
	fmt.Println(errors.Is(err, pcap.ErrTLSLimit))
	// Output: true
}

func ExampleParseHTTPRequest() {
	raw := []byte("POST /submit HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"User-Agent: Go-http-client/1.1\r\n" +
		"Accept-Language: en-US\r\n" +
		"Cookie: session=abc\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello")

	req, _, err := pcap.ParseHTTPRequest(raw)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("method=%s host=%s body=%s ja4h=%s\n",
		req.Method, req.Host, req.Body, req.JA4H[:12])
	fmt.Printf("truncated=%t\n", req.Anomalies.TruncatedBody)
	// Output:
	// method=POST host=api.example.com body=hello ja4h=po11cn04enus
	// truncated=false
}

func ExampleParseHTTPResponse_contentEncoding() {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}

	raw := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", compressed.Len())
	raw = append(raw, compressed.Bytes()...)
	resp, consumed, err := pcap.ParseHTTPResponse(raw)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encoding=%s decoded=%t body=%s bytes=%d complete=%t\n",
		resp.ContentEncoding, resp.IsDecompressed, resp.Body, resp.BodyLength, consumed == len(raw))
	// Output:
	// encoding=gzip decoded=true body=hello bytes=5 complete=true
}

func ExampleJA4T() {
	// TCP options: MSS (2) = 1460, SACK Permitted (4), Timestamps (8), NOP (1), Window Scale (3) = 8.
	opts := []byte{
		2, 4, 0x05, 0xb4,
		4, 2,
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		1,
		3, 3, 8,
	}
	fp, ok := pcap.JA4T(64240, opts)
	fmt.Printf("ok=%t ja4t=%s ja4l=%s\n", ok, fp, pcap.JA4L(2_400_000, 64))
	// Output:
	// ok=true ja4t=64240_2-4-8-1-3_1460_8 ja4l=1200_64
}

func ExampleDNSLabelEntropy() {
	normal := pcap.DNSLabelEntropy("www.example.com")
	tunnel := pcap.DNSLabelEntropy("4b8f9a1c0d2e3f4a5b6c7d8e9f0a1b2c.example.com")
	fmt.Printf("normal=%.1f high_entropy=%t\n", normal, tunnel > 3.5)
	// Output:
	// normal=0.0 high_entropy=true
}

func ExampleFlowSummary_CommunityID() {
	f := pcap.FlowSummary{
		Protocol: pcap.IPProtoTCP,
		SrcAddr:  netip.MustParseAddr("1.2.3.4"), SrcPort: 1122,
		DstAddr: netip.MustParseAddr("5.6.7.8"), DstPort: 3344,
	}
	fmt.Println(f.CommunityID(0))
	// Output: 1:wCb3OG7yAFWelaUydu0D+125CLM=
}

func ExampleDecompressCapture() {
	input, err := os.ReadFile("traffic.pcapng.gz")
	if err != nil {
		log.Fatal(err)
	}
	data, err := pcap.DecompressCapture(input)
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	for pkt, err := range c.PacketSeq(data) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(pkt.Index, pkt.CaptureLen)
	}
}

func ExampleNewPCAPWriter() {
	var buf bytes.Buffer
	w, err := pcap.NewPCAPWriter(&buf, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.WritePacket(123456789, buildExampleEthernetUDPFrame()); err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c.Format, c.PacketCount, c.NanoTimestamp)
	// Output: pcap 1 true
}

func ExamplePCAPWriter_WritePacketWithOriginalLen() {
	var buf bytes.Buffer
	w, err := pcap.NewPCAPWriter(&buf, pcap.LinkTypeEthernet, 65535)
	if err != nil {
		log.Fatal(err)
	}
	// Only the first 96 bytes of a 1,500-byte packet were captured.
	if err := w.WritePacketWithOriginalLen(123456789, make([]byte, 96), 1500); err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	for pkt, err := range c.PacketSeq(buf.Bytes()) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(pkt.CaptureLen, pkt.OriginalLen)
	}
	// Output: 96 1500
}

func ExamplePCAPNGWriter_AddInterface() {
	var buf bytes.Buffer
	w, err := pcap.NewPCAPNGWriter(&buf, pcap.PCAPNGWriterOptions{InterfaceName: "eth0"})
	if err != nil {
		log.Fatal(err)
	}
	id, err := w.AddInterface(pcap.PCAPNGWriterOptions{LinkType: pcap.LinkTypeIPv4, InterfaceName: "raw-ip"})
	if err != nil {
		log.Fatal(err)
	}
	ipPacket := buildExampleEthernetUDPFrame()[14:]
	if err := w.WritePacket(pcap.PacketRecord{InterfaceID: id}, ipPacket); err != nil {
		log.Fatal(err)
	}
	fmt.Println(id)
	// Output: 1
}

func ExampleCapture_ExtractFlowPCAPNG() {
	data := buildExamplePCAPNG()
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	var out bytes.Buffer
	if err := c.ExtractFlowPCAPNG(data, &out, 0); err != nil {
		log.Fatal(err)
	}
	selected, err := pcap.New(out.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(selected.Format, selected.PacketCount, selected.Interfaces[0].Name)
	// Output: pcapng 1 en0
}

func ExampleCapture_ExtractFlowPCAPNGFromReaderAt() {
	r := bytes.NewReader(buildExamplePCAPNG())
	c, err := pcap.NewFromReaderAt(r, r.Size())
	if err != nil {
		log.Fatal(err)
	}
	var out bytes.Buffer
	if err := c.ExtractFlowPCAPNGFromReaderAt(r, &out, 0); err != nil {
		log.Fatal(err)
	}
	selected, err := pcap.New(out.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(selected.Format, selected.PacketCount, selected.Interfaces[0].Name)
	// Output: pcapng 1 en0
}

func ExampleCapture_ExtractFlowPacketsPCAPNG() {
	data := buildExamplePCAPNG()
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	var out bytes.Buffer
	// The packet headers and payloads retain the endpoints and application data.
	if err := c.ExtractFlowPacketsPCAPNG(data, &out, 0); err != nil {
		log.Fatal(err)
	}
	selected, err := pcap.New(out.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s packets=%d interface name=%q\n", selected.Format, selected.PacketCount, selected.Interfaces[0].Name)
	// Output: pcapng packets=1 interface name=""
}

func ExampleCapture_ExtractHTTP1TransactionPCAPNG() {
	data, err := os.ReadFile("testdata/deployments/http1-transactions.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := c.HTTP1Transactions(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, tx := range rows {
		if tx.Request.Target != "/reused" || tx.Response == nil {
			continue
		}
		var selected bytes.Buffer
		if err := c.ExtractHTTP1TransactionPCAPNG(data, &selected, tx.ID()); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s %s: %d %q\n", tx.Request.Method, tx.Request.Target,
			tx.Response.StatusCode, tx.Response.Body)
	}
	// Output: GET /reused: 200 "reused"
}

func ExampleParseHTTP2Frames_headers() {
	// Indexed GET, http and / fields from the HPACK static table.
	data := append(bytes.Clone(pcap.HTTP2ClientPreface), 0, 0, 3, 1, 4, 0, 0, 0, 1, 0x82, 0x86, 0x84)
	summary, err := pcap.ParseHTTP2Frames(data)
	if err != nil {
		log.Fatal(err)
	}
	request := summary.Streams[0].HeaderBlocks[0]
	fmt.Println(request.Method, request.Path)
	// Output: GET /
}

func ExampleHTTP2HeaderBlock_DNSOverHTTPS() {
	block := pcap.HTTP2HeaderBlock{Method: "GET", Path: "/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDb3JnAAABAAE"}
	msg, match, err := block.DNSOverHTTPS(nil)
	if err != nil {
		log.Fatal(err)
	}
	if match && len(msg.Questions) != 0 {
		fmt.Println(msg.Questions[0].Name)
	}
	// Output: example.org
}

func ExampleCapture_Web() {
	data, err := os.ReadFile("testdata/deployments/proxy.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	records, err := c.Web(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(records.TLS), len(records.HTTP), len(records.HTTP2))
	// Output: 2 0 0
}

func ExampleParseWebSocketFrames() {
	// The unmasked text frame from RFC 6455 section 5.7.
	messages, err := pcap.ParseWebSocketFrames([]byte{0x81, 5, 'H', 'e', 'l', 'l', 'o'})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(messages[0].Payload))
	// Output: Hello
}

func ExampleCapture_WebWithWebSockets() {
	data, err := os.ReadFile("testdata/deployments/proxy.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	web, messages, err := c.WebWithWebSockets(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(web.TLS), len(messages))
	// Output: 2 0
}

func ExampleCapture_DNSSourceStats() {
	data, err := os.ReadFile("testdata/deployments/client.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	sources, err := c.DNSSourceStats(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range sources {
		fmt.Println(s.SrcAddr, s.QueryCount, s.ResponseCount, s.NXDomainCount)
	}
	// Output: 192.0.2.14 1 1 0
}

func ExampleCapture_BeaconsWithOptions() {
	data, err := os.ReadFile("testdata/deployments/client.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	groups, err := c.BeaconsWithOptions(data, pcap.BeaconOptions{GroupBy3Tuple: true})
	if err != nil {
		log.Fatal(err)
	}
	for _, g := range groups {
		fmt.Println(g.DstAddr, g.DstPort, g.Stats.SampleCount)
	}
	// Output:
	// 198.51.100.80 443 1
	// 198.51.100.81 443 1
}

func ExampleCapture_DecryptedTLSStreams_earlyData() {
	raw, err := os.ReadFile("testdata/rfc8448-0rtt.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(raw)
	if err != nil {
		log.Fatal(err)
	}
	streams, err := c.DecryptedTLSStreams(raw, nil)
	if err != nil {
		log.Fatal(err)
	}
	// The trace sends six early bytes followed by 50 client application bytes.
	fmt.Println(string(streams[0].Client.Data[:6]), len(streams[0].Client.Data))
	// Output: ABCDEF 56
}

func ExampleTLSCertificate_ValidityAt() {
	cert := pcap.TLSCertificate{Version: 3, NotBefore: 1700000000, NotAfter: 1800000000}
	at := time.Unix(1750000000, 0)
	fmt.Println(cert.ValidityAt(at) == pcap.TLSValidityCurrent)
	// Output: true
}

func ExampleTLSHandshake_ServerNameMatch() {
	hs := pcap.TLSHandshake{
		HasClientHello: true,
		ClientHello:    pcap.TLSClientHello{SNI: "api.example.org"},
		Certificates:   []pcap.TLSCertificate{{DNSNames: []string{"*.example.org"}}},
	}
	fmt.Println(hs.ServerNameMatch())
	// Output: true true
}

func ExampleTLSHandshake_ServerNameMatch_ech() {
	hs := pcap.TLSHandshake{
		HasClientHello: true,
		ClientHello:    pcap.TLSClientHello{SNI: "public.example", HasECH: true},
		Certificates:   []pcap.TLSCertificate{{DNSNames: []string{"public.example"}}},
	}
	match, known := hs.ServerNameMatch()
	fmt.Printf("observed SNI=%q ECH extension=%t leaf match=%t known=%t\n",
		hs.ClientHello.SNI, hs.ClientHello.HasECH, match, known)
	if hs.ClientHello.HasECH {
		fmt.Println("inner name unavailable")
	}
	// Output:
	// observed SNI="public.example" ECH extension=true leaf match=true known=true
	// inner name unavailable
}

func ExampleCapture_HTTP2Transactions() {
	data, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	capture, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := capture.HTTP2Transactions(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		if row.Request.Path == "/two" && row.Response != nil {
			id := row.ID()
			fmt.Printf("packet %d + %d, stream %d: %s %s → %d %q\n",
				id.PacketIndex, id.PacketPayloadOffset, id.StreamID, row.Request.Method,
				row.Request.Path, row.StatusCode, row.Response.Body)
		}
	}
	// Output: packet 6 + 50, stream 3: POST /two → 201 "two"
}

func ExampleCapture_ExtractHTTP2TransactionPCAPNG() {
	data, err := os.ReadFile("testdata/deployments/http2-transactions.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := c.HTTP2Transactions(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		if row.StreamID != 3 || row.Request.Path != "/two" {
			continue
		}
		var subset bytes.Buffer
		if err := c.ExtractHTTP2TransactionPCAPNG(data, &subset, row.ID()); err != nil {
			log.Fatal(err)
		}
		reopened, err := pcap.New(subset.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		txs, err := reopened.HTTP2Transactions(subset.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		for _, tx := range txs {
			if tx.StreamID == row.StreamID && tx.Response != nil {
				fmt.Printf("stream %d, %s %s → %d %q (%d packets)\n", tx.StreamID,
					tx.Request.Method, tx.Request.Path, tx.StatusCode, tx.Response.Body, reopened.PacketCount)
			}
		}
	}
	// Output: stream 3, POST /two → 201 "two" (9 packets)
}

func ExampleCapture_TLSHandshakeEvidence() {
	data, err := os.ReadFile("testdata/deployments/client.pcapng")
	if err != nil {
		panic(err)
	}
	c, err := pcap.New(data)
	if err != nil {
		panic(err)
	}
	rows, err := c.TLSHandshakeEvidence(data, nil)
	if err != nil {
		panic(err)
	}
	// A later TCP opening reuses this five-tuple. Resolve the selected
	// observation against packet numbers in the original file.
	packets, err := c.Packets(data)
	if err != nil {
		panic(err)
	}
	for _, row := range rows {
		if row.Handshake.ClientHello.SNI == "trace.example" {
			for _, index := range row.ClientHello.PacketIndices {
				pkt := packets[index]
				fmt.Printf("flow=%d opening_frame=%d hello_frame=%d link=%d\n", row.FlowIndex, row.OpeningPacket+1, pkt.Index+1, pkt.LinkType)
			}
		}
	}
	// Output:
	// flow=1 opening_frame=2 hello_frame=6 link=1
}
