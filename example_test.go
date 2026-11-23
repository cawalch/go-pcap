package pcap_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/cawalch/go-pcap"
)

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
	// Output:
	// method=POST host=api.example.com body=hello ja4h=po11cn04enus
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
