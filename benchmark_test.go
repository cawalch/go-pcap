package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func BenchmarkNewRejectNonPCAP(b *testing.B) {
	nonPCAP := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00not a capture")
	b.ReportAllocs()
	b.SetBytes(int64(len(nonPCAP)))
	for b.Loop() {
		_, _ = New(nonPCAP)
	}
}

func BenchmarkNewPCAPNG(b *testing.B) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51234, 443, 100, 0, TCPFlagSYN, []byte("client-hello"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 51234, 200, 112, TCPFlagSYN|TCPFlagACK, []byte("server-hello"))
	raw := buildPCAPNGFixture(binary.LittleEndian, []byte("CLIENT_HANDSHAKE_TRAFFIC_SECRET aa bb\n"), [][]byte{f1, f2})

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := New(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeFrameEthernetIPv4TCP(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51234, 443, 100, 200, TCPFlagPSH|TCPFlagACK, []byte("application-payload"))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for b.Loop() {
		if _, err := DecodeFrame(frame, LinkTypeEthernet); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFlows(b *testing.B) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51234, 443, 100, 0, TCPFlagSYN, []byte("client-hello"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 51234, 200, 112, TCPFlagSYN|TCPFlagACK, []byte("server-hello"))
	frames := make([][]byte, 0, 64)
	for range 32 {
		frames = append(frames, f1, f2)
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	cap, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := cap.Flows(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJA4T(b *testing.B) {
	opts := []byte{
		2, 4, 0x05, 0xb4,
		4, 2,
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		1,
		3, 3, 8,
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = JA4T(64240, opts)
	}
}

func BenchmarkParseDNS(b *testing.B) {
	pkt := buildDNSQueryResponsePacket()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if _, err := ParseDNS(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTLSClientHelloJA4(b *testing.B) {
	rec := buildTLS13ClientHelloRecord("c2.example.com", "h2")
	b.ReportAllocs()
	b.SetBytes(int64(len(rec)))
	for b.Loop() {
		if _, err := ParseTLSRecords(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptQUICInitial(b *testing.B) {
	tlsRecord := buildTLS13ClientHelloRecord("quic.c2.example.com", "h3")
	hsMsg := tlsRecord[5:]
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44}
	t := &testing.T{}
	dgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, dcid, scid, nil, 1, 0, hsMsg)
	batch := [][]byte{dgram}

	b.ReportAllocs()
	b.SetBytes(int64(len(dgram)))
	for b.Loop() {
		if _, err := DecryptQUICInitial(batch); err != nil {
			b.Fatal(err)
		}
	}
}

var measuredHTTPRecords []HTTPRecord

func BenchmarkCaptureHTTPContent(b *testing.B) {
	plain := bytes.Repeat([]byte("Capture HTTP body for content decoding benchmark.\n"), 1<<10)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name, coding string
		body         []byte
	}{
		{"plain", "", plain}, {"gzip", "Content-Encoding: gzip\r\n", compressed.Bytes()},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := []byte("GET / HTTP/1.1\r\nHost: bench.invalid\r\n\r\n")
			response := append(fmt.Appendf(nil, "HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n", tc.coding, len(tc.body)), tc.body...)
			var frames [][]byte
			for i := range 64 {
				src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
				sport := uint16(40000 + i)
				frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, sport, 80, 1, 1, TCPFlagPSH|TCPFlagACK, req))
				frames = append(frames, buildEthernetIPv4TCPFrame(dst, src, 80, sport, 1, 1+uint32(len(req)), TCPFlagPSH|TCPFlagACK, response))
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			capture, err := New(raw)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				records, err := capture.HTTP(raw)
				if len(records) != 128 || err != nil {
					b.Fatalf("records = %d, err = %v", len(records), err)
				}
				measuredHTTPRecords = records
			}
			b.ReportMetric(float64(len(measuredHTTPRecords[127].Response.Body)), "returned-B/body")
		})
	}
}

func BenchmarkParseHTTPRequestJA4H(b *testing.B) {
	rawReq := []byte("POST /gate.php HTTP/1.1\r\n" +
		"Host: c2.example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Cookie: z_token=999; a_sid=123\r\n" +
		"Content-Length: 10\r\n" +
		"\r\n" +
		"MZ_PAYLOAD")

	b.ReportAllocs()
	b.SetBytes(int64(len(rawReq)))
	for b.Loop() {
		if _, _, err := ParseHTTPRequest(rawReq); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSSHHandshakeHASSH(b *testing.B) {
	cStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6",
		"curve25519-sha256",
		"ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)
	sStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6p1",
		"curve25519-sha256",
		"ssh-ed25519",
		"aes128-gcm@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(cStream) + len(sStream)))
	for b.Loop() {
		if _, err := ParseSSHHandshake(cStream, sStream); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSMB2NTLM(b *testing.B) {
	pkt := buildSMB2SessionSetupNTLMChallenge()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if _, err := ParseSMB2Message(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeBeaconStats(b *testing.B) {
	ts := []int64{10e9, 20e9, 30e9, 40e9, 50e9, 60e9, 70e9, 80e9}
	sizes := []uint64{64, 64, 64, 64, 64, 64, 64, 64}
	b.ReportAllocs()
	for b.Loop() {
		_ = ComputeBeaconStats(ts, sizes, 512, 512)
	}
}

func BenchmarkReaderAtFlows(b *testing.B) {
	for _, size := range []int{16, 1440} {
		frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 0, TCPFlagACK, make([]byte, size))
		frames := make([][]byte, 512)
		for i := range frames {
			frames[i] = frame
		}
		for _, format := range []string{"PCAP", "PcapNG"} {
			var raw []byte
			if format == "PCAP" {
				raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			} else {
				raw = buildPCAPNGFixture(binary.LittleEndian, nil, frames)
			}
			b.Run(fmt.Sprintf("%s/%d", format, size), func(b *testing.B) {
				r := bytes.NewReader(raw)
				c, err := NewFromReaderAt(r, int64(len(raw)))
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := c.FlowsFromReaderAt(r); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// RFC 7541 Appendix C.4 uses Huffman literals and dynamic references across
// three requests on the same connection.
func BenchmarkCaptureHTTP2Huffman(b *testing.B) {
	req := bytes.Clone(HTTP2ClientPreface)
	for i, encoded := range rfc7541HuffmanRequests {
		block, err := hex.DecodeString(encoded)
		if err != nil {
			b.Fatal(err)
		}
		req = append(req, buildHTTP2Frame(HTTP2FrameHeaders, 4, uint32(2*i+1), block)...)
	}
	var frames [][]byte
	for i := range 32 {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, uint16(30000+i), 80, 1, 0, TCPFlagACK, req))
	}
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.HTTP2(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCaptureWeb(b *testing.B) {
	for _, h2 := range []bool{false, true} {
		for _, keyed := range []bool{false, true} {
			b.Run(fmt.Sprintf("h2=%t/keyed=%t", h2, keyed), func(b *testing.B) {
				raw, c := mixedWebCapture(b, h2, keyed)
				b.ReportAllocs()
				for b.Loop() {
					var err error
					if h2 {
						_, err = c.HTTP2(raw)
					} else {
						_, err = c.HTTP(raw)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkCaptureStreams(b *testing.B) {
	for _, tc := range []struct {
		name            string
		flows, segments int
	}{{"ManyFlows", 256, 4}, {"ManySegments", 4, 256}} {
		b.Run(tc.name, func(b *testing.B) {
			var frames [][]byte
			payload := make([]byte, 128)
			for seg := range tc.segments {
				for flow := range tc.flows {
					frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, uint16(10000+flow), 80, uint32(seg*len(payload)), 0, TCPFlagACK, payload))
				}
			}
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
			c, err := New(raw)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.Streams(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Embed the file so counting preserves the file-backed reader's capabilities.
type measuredFile struct {
	*os.File
	calls, bytesRead int64
}

func (r *measuredFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.File.ReadAt(p, off)
	r.calls++
	r.bytesRead += int64(n)
	return n, err
}

type measuredReaderAt struct {
	*bytes.Reader
	calls, bytesRead int64
}

func (r *measuredReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	r.calls++
	r.bytesRead += int64(n)
	return n, err
}

func BenchmarkReaderAtScan(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 0, TCPFlagACK, make([]byte, 1440))
	frames := make([][]byte, 512)
	for i := range frames {
		frames[i] = frame
	}
	order := binary.LittleEndian
	for _, format := range []string{"PCAP", "PcapNG", "PcapNG-obsolete"} {
		var raw []byte
		switch format {
		case "PCAP":
			raw = buildClassicPCAP(order, false, LinkTypeEthernet, 65535, frames)
		case "PcapNG":
			raw = buildPCAPNGFixture(order, nil, frames)
		case "PcapNG-obsolete":
			buf := bytes.NewBuffer(buildPCAPNGFixture(order, nil, nil))
			for i, frame := range frames {
				appendPCAPNGBlock(buf, order, blockTypeLegacyPacket, legacyPacketBody(order, 0, 2, uint64(i), frame))
			}
			raw = buf.Bytes()
		}
		for _, op := range []string{"open", "packets", "flows", "iterate", "first"} {
			b.Run(format+"/"+op, func(b *testing.B) {
				c, err := New(raw)
				if err != nil {
					b.Fatal(err)
				}
				r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
				b.ReportAllocs()
				for b.Loop() {
					switch op {
					case "open":
						_, err = NewFromReaderAt(r, int64(len(raw)))
					case "packets":
						_, err = c.PacketsFromReaderAt(r)
					case "iterate", "first":
						for _, packetErr := range c.PacketSeqFromReaderAt(r) {
							if packetErr != nil {
								b.Fatal(packetErr)
							}
							if op == "first" {
								break
							}
						}
					case "flows":
						_, err = c.FlowsFromReaderAt(r)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(r.calls)/float64(b.N), "reads/op")
				b.ReportMetric(float64(r.bytesRead)/float64(b.N), "read-B/op")
			})
		}
	}
}

// Most of the bytes are unrelated UDP traffic. Each scanner also has a real
// record to find, so the benchmark includes protocol parsing and output.
func BenchmarkReaderAtProtocols(b *testing.B) {
	benchmarkReaderAtProtocols(b, false)
}

func BenchmarkReaderAtFileProtocols(b *testing.B) {
	benchmarkReaderAtProtocols(b, true)
}

func benchmarkReaderAtProtocols(b *testing.B, file bool) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	noise := buildEthernetIPv4UDPFrame(src, dst, 1234, 5678, make([]byte, 1440))
	frames := make([][]byte, 512)
	for i := range frames {
		frames[i] = noise
	}
	hello := buildTLS13ClientHelloRecord("bench.example", "h2")
	initial := buildEncryptedQUICInitialDatagram(b, QUICVersion1, []byte{1, 2, 3, 4}, nil, nil, 0, 0, hello[5:])
	frames = append(frames, buildEthernetIPv4UDPFrame(src, dst, 1234, 53, buildDNSQueryResponsePacket()), buildEthernetIPv4TCPFrame(src, dst, 1234, 443, 1, 0, TCPFlagACK, hello), buildEthernetIPv4UDPFrame(src, dst, 1234, 443, initial))
	for _, format := range []string{"PCAP", "PcapNG"} {
		var raw []byte
		if format == "PCAP" {
			raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		} else {
			raw = buildPCAPNGFixture(binary.LittleEndian, nil, frames)
		}
		c, err := New(raw)
		if err != nil {
			b.Fatal(err)
		}
		for _, proto := range []string{"DNS", "TLS", "QUIC"} {
			b.Run(format+"/"+proto, func(b *testing.B) {
				mem := &measuredReaderAt{Reader: bytes.NewReader(raw)}
				var r io.ReaderAt = mem
				calls, bytesRead := &mem.calls, &mem.bytesRead
				if file {
					f := tempCaptureFile(b, raw)
					disk := &measuredFile{File: f}
					r = disk
					calls, bytesRead = &disk.calls, &disk.bytesRead
				}
				b.ReportAllocs()
				for b.Loop() {
					switch proto {
					case "DNS":
						_, err = c.DNSFromReaderAt(r)
					case "TLS":
						_, err = c.TLSFromReaderAt(r)
					case "QUIC":
						_, err = c.QUICFromReaderAt(r)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(*calls)/float64(b.N), "reads/op")
				b.ReportMetric(float64(*bytesRead)/float64(b.N), "read-B/op")
			})
		}
	}
}

// Measure capture parsing, flow grouping and both directions of Initial
// decryption with the RFC 9001 and RFC 9369 example packets.
func BenchmarkCaptureQUICInitials(b *testing.B) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	var frames [][]byte
	for group, rfc := range []string{"rfc9001", "rfc9369"} {
		read := func(side string) []byte {
			data, err := os.ReadFile("testdata/" + rfc + "-" + side + ".bin")
			if err != nil {
				b.Fatal(err)
			}
			return data
		}
		ch, sh := read("client"), read("server")
		for i := range 32 {
			// Replayed RFC packets have identical IDs. Give each exchange its own client IP.
			client[3] = byte(10 + group*32 + i)
			port := uint16(10000 + group*32 + i)
			frames = append(frames, buildEthernetIPv4UDPFrame(client, server, port, 443, ch), buildEthernetIPv4UDPFrame(server, client, 443, port, sh))
		}
	}
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		records, err := c.QUIC(raw)
		if err != nil || len(records) != 64 || !records[63].Handshake.HasServerHello {
			b.Fatalf("got %d records, err %v", len(records), err)
		}
	}
}

// Measure CID lookup across a port change for each two-packet ClientHello.
// All exchanges share both IPs and the server port.
func BenchmarkCaptureQUICRebinding(b *testing.B) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello := buildTLS13ClientHelloRecord("rebound.example", "h3")[5:]
	half := len(hello) / 2
	var frames [][]byte
	for i := range 64 {
		dcid, scid := []byte{1, byte(i)}, []byte{2, byte(i)}
		start := buildEncryptedQUICInitialDatagram(b, QUICVersion1, dcid, scid, nil, 1, 0, hello[:half])
		end := buildEncryptedQUICInitialDatagram(b, QUICVersion1, dcid, scid, nil, 2, uint16(half), hello[half:])
		frames = append(frames, buildEthernetIPv4UDPFrame(client, server, uint16(10000+i), 443, start),
			buildEthernetIPv4UDPFrame(client, server, uint16(20000+i), 443, end))
	}
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, frames)
	r := bytes.NewReader(raw)
	c, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		records, err := c.QUICFromReaderAt(r)
		if err != nil || len(records) != 64 || records[63].Handshake.ClientHello.SNI != "rebound.example" {
			b.Fatalf("got %d records, err %v", len(records), err)
		}
	}
}

// BenchmarkCaptureFingerprints includes flow grouping, reassembly and parsing
// for 32 independent connections carrying the same application exchange.
func BenchmarkCaptureFingerprints(b *testing.B) {
	read := func(name string) []byte {
		b.Helper()
		p, err := os.ReadFile("testdata/foxio/" + name)
		if err != nil {
			b.Fatal(err)
		}
		return p
	}
	der := read("h2-leaf.der")
	listLen := 3 + len(der)
	cert := []byte{byte(listLen >> 16), byte(listLen >> 8), byte(listLen), byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	tlsServer := append(read("h2-server.tls"), wrapTLSHandshakeRecord(TLSHandshakeCertificate, append(cert, der...))...)
	for _, tc := range []struct {
		name           string
		port           uint16
		client, server []byte
	}{
		{"TLS", 443, read("grease-client.tls"), tlsServer},
		{"HTTP", 80, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/8.1.2\r\nCookie: z_sid=123; theme=dark; a_key=0123456789\r\nAccept-Language: en-US\r\n\r\n"), nil},
		{"HTTPNoCookies", 80, []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), nil},
		{"HTTPLargeCookies", 80, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nCookie: " + strings.Repeat("session="+strings.Repeat("a", 96)+"; ", 48) + "\r\n\r\n"), nil},
		{"SSH", 22, buildSSHKexStream("SSH-2.0-OpenSSH_9.6", "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com", "umac-128-etm@openssh.com", "none"), buildSSHKexStream("SSH-2.0-OpenSSH_9.6", "curve25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com", "umac-128-etm@openssh.com", "none")},
	} {
		b.Run(tc.name, func(b *testing.B) {
			client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
			var frames [][]byte
			for i := range 32 {
				port := uint16(10000 + i)
				frames = append(frames, buildEthernetIPv4TCPFrame(client, server, port, tc.port, 1, 0, TCPFlagACK, tc.client))
				if tc.server != nil {
					frames = append(frames, buildEthernetIPv4TCPFrame(server, client, tc.port, port, 1, 0, TCPFlagACK, tc.server))
				}
			}
			raw := buildPCAPNGFixture(binary.LittleEndian, nil, frames)
			c, err := New(raw)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				switch tc.name {
				case "TLS":
					rs, e := c.TLS(raw)
					if e != nil || len(rs) != 32 || len(rs[0].Handshake.Certificates) != 1 || rs[0].Handshake.Certificates[0].JA4X == "" || rs[0].Handshake.ServerHello.JA4S == "" || rs[0].Handshake.ClientHello.JA4 == "" {
						b.Fatal("missing TLS fingerprints", e)
					}
				case "HTTP", "HTTPNoCookies", "HTTPLargeCookies":
					rs, e := c.HTTP(raw)
					if e != nil || len(rs) != 32 || rs[0].Request.JA4H == "" {
						b.Fatal("missing JA4H", e)
					}
				case "SSH":
					rs, e := c.SSH(raw)
					if e != nil || len(rs) != 32 || rs[0].Handshake.HASSH == "" || rs[0].Handshake.HASSHServer == "" {
						b.Fatal("missing HASSH", e)
					}
				}
			}
		})
	}
}

// BenchmarkPacketFingerprints opens a capture, walks every record, decodes the
// Ethernet frame and computes a JA4T for each SYN with MSS and window scale.
func BenchmarkPacketFingerprints(b *testing.B) {
	var frames [][]byte
	for i := range 256 {
		options := []byte{2, 4, 5, 180, 1, 3, 3, 7}
		frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, uint16(10000+i), 443, 1, 0, TCPFlagSYN, options)
		frame[14+20+12] = 7 << 4 // Include the options in the TCP header.
		frames = append(frames, frame)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"Classic", buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)},
		{"PcapNG", buildPCAPNGFixture(binary.LittleEndian, nil, frames)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c, err := New(tc.raw)
				if err != nil {
					b.Fatal(err)
				}
				count := 0
				for pkt, err := range c.PacketSeq(tc.raw) {
					if err != nil {
						b.Fatal(err)
					}
					data, err := c.PacketPayload(tc.raw, pkt)
					if err != nil {
						b.Fatal(err)
					}
					f, err := DecodeFrame(data, pkt.LinkType)
					if err != nil {
						b.Fatal(err)
					}
					if fp, ok := f.JA4T(data); !ok || fp != "65535_2-1-3_1460_7" {
						b.Fatal(fp, ok)
					}
					count++
				}
				if count != len(frames) {
					b.Fatal(count)
				}
			}
		})
	}
}

// BenchmarkFlowCommunityID scans 512 packets across 128 TCP flows. Each
// WithIDs case also materializes the ID for every returned summary.
func BenchmarkFlowCommunityID(b *testing.B) {
	var frames [][]byte
	for range 4 {
		for i := range 128 {
			frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, uint16(10000+i), 443, 1, 0, TCPFlagACK, nil))
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	r := bytes.NewReader(raw)
	for _, reader := range []string{"Slice", "ReaderAt"} {
		for _, mode := range []string{"Flows", "WithIDs"} {
			b.Run(reader+"/"+mode, func(b *testing.B) {
				var scan func() ([]FlowSummary, error)
				if reader == "ReaderAt" {
					c, err := NewFromReaderAt(r, r.Size())
					if err != nil {
						b.Fatal(err)
					}
					scan = func() ([]FlowSummary, error) { return c.FlowsFromReaderAt(r) }
				} else {
					c, err := New(raw)
					if err != nil {
						b.Fatal(err)
					}
					scan = func() ([]FlowSummary, error) { return c.Flows(raw) }
				}
				b.ReportAllocs()
				for b.Loop() {
					flows, err := scan()
					if err != nil || len(flows) != 128 {
						b.Fatalf("%d flows, %v", len(flows), err)
					}
					if mode == "WithIDs" {
						for i := range flows {
							if len(flows[i].CommunityID(0)) != 30 {
								b.Fatal("missing Community ID")
							}
						}
					}
				}
			})
		}
	}
}
