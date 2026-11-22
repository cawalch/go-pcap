package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
