package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"net/netip"
	"testing"
)

func FuzzSafeReader(f *testing.F) {
	f.Add([]byte{}, int64(0), int64(0))
	f.Add([]byte("hello\x00world"), int64(0), int64(6))
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, int64(2), int64(4))

	f.Fuzz(func(t *testing.T, data []byte, offset, length int64) {
		r := NewSafeReader(data)
		_, _ = r.Slice(offset, length)
		_, _ = r.ReadUint8(offset)
		_, _ = r.ReadUint16(offset)
		_, _ = r.ReadUint16BE(offset)
		_, _ = r.ReadUint32(offset)
		_, _ = r.ReadUint32BE(offset)
		_, _ = r.ReadUint64(offset)
		_, _ = r.ReadUint64BE(offset)
		_, _ = r.ReadASCIIZ(offset, length)
		_ = r.CheckBounds(offset, length)
	})
}

func FuzzNew(f *testing.F) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 1, TCPFlagSYN, []byte("tls"))
	f.Add(buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame}))
	f.Add(buildClassicPCAP(binary.BigEndian, true, LinkTypeEthernet, 65535, [][]byte{frame}))
	f.Add(buildPCAPNGFixture(binary.LittleEndian, []byte("CLIENT_RANDOM deadbeef cafebabe\n"), [][]byte{frame}))

	f.Fuzz(func(t *testing.T, data []byte) {
		cap, err := New(data)
		if err != nil {
			return
		}
		if cap.FileSize() != int64(len(data)) {
			t.Fatalf("FileSize() = %d, want %d", cap.FileSize(), len(data))
		}
		_, _ = cap.DeclaredExtent()
		_ = cap.InputTruncated()
		_ = cap.Anomalies()
	})
}

func FuzzPackets(f *testing.F) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 1, TCPFlagSYN, []byte("payload"))
	f.Add(buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame}))
	f.Add(buildPCAPNGFixture(binary.LittleEndian, []byte("KEYLOG"), [][]byte{frame}))

	f.Fuzz(func(t *testing.T, data []byte) {
		cap, err := New(data)
		if err != nil {
			return
		}
		packets, err := cap.Packets(data)
		if err != nil {
			return
		}
		for _, pkt := range packets {
			payload, err := cap.PacketPayload(data, pkt)
			if err != nil {
				t.Fatalf("PacketPayload failed for valid PacketRecord: %v", err)
			}
			_, _ = DecodeFrame(payload, pkt.LinkType)
		}
		_, _ = cap.Flows(data)
	})
}

func FuzzDecodeFrame(f *testing.F) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 1, TCPFlagSYN, []byte("payload"))
	f.Add(frame, uint16(LinkTypeEthernet))
	f.Add(frame[14:], uint16(LinkTypeRaw))

	f.Fuzz(func(t *testing.T, data []byte, rawLinkType uint16) {
		decoded, err := DecodeFrame(data, LinkType(rawLinkType))
		if err != nil {
			return
		}
		if int(decoded.PayloadOffset)+int(decoded.PayloadLength) > len(data) {
			t.Fatalf("Payload span (%d + %d) exceeds data length %d",
				decoded.PayloadOffset, decoded.PayloadLength, len(data))
		}
		for _, layer := range decoded.LayerSlices() {
			if int(layer.Offset)+int(layer.Length) > len(data) {
				t.Fatalf("Layer %s span (%d + %d) exceeds data length %d",
					layer.Proto, layer.Offset, layer.Length, len(data))
			}
		}
		_, _ = decoded.JA4T(data)
	})
}

func FuzzReassembleTCP(f *testing.F) {
	f.Add(uint32(100), uint8(TCPFlagSYN), []byte{}, uint32(101), uint8(TCPFlagACK), []byte("hello"), uint32(106), uint8(TCPFlagACK), []byte("world"))

	f.Fuzz(func(t *testing.T, seq1 uint32, flags1 uint8, p1 []byte, seq2 uint32, flags2 uint8, p2 []byte, seq3 uint32, flags3 uint8, p3 []byte) {
		segs := []TCPSegmentInput{
			{Seq: seq1, Flags: flags1, Payload: p1},
			{Seq: seq2, Flags: flags2, Payload: p2},
			{Seq: seq3, Flags: flags3, Payload: p3},
		}
		buf, err := ReassembleTCP(segs)
		if err != nil {
			return
		}
		if len(buf.Data) > MaxFlowStreamBytes {
			t.Fatalf("Reassembled stream length %d exceeds MaxFlowStreamBytes %d", len(buf.Data), MaxFlowStreamBytes)
		}
	})
}

func FuzzParseDNS(f *testing.F) {
	f.Add(buildDNSQueryResponsePacket())
	f.Add(testServiceDNS(DNSTypeHTTPS, testServiceParams()))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseDNS(data)
		if err != nil {
			return
		}
		if len(msg.Questions) > MaxDNSQuestions {
			t.Fatalf("Questions len %d exceeds %d", len(msg.Questions), MaxDNSQuestions)
		}
		if len(msg.Answers)+len(msg.Authorities)+len(msg.Additionals) > MaxDNSResourceRecords {
			t.Fatalf("Total resource records exceed %d", MaxDNSResourceRecords)
		}
	})
}

func FuzzParseTLSRecords(f *testing.F) {
	f.Add(buildTLS13ClientHelloRecord("c2.example.com", "h2"))
	client, server := testKeyShareRecords(true)
	f.Add(client)
	f.Add(server)

	f.Fuzz(func(t *testing.T, data []byte) {
		hs, err := ParseTLSRecords(data)
		if err != nil {
			return
		}
		if hs.HasClientHello && len(hs.ClientHello.JA4) != 36 {
			t.Fatalf("Invalid JA4 length %d (%q)", len(hs.ClientHello.JA4), hs.ClientHello.JA4)
		}
		if hs.HasServerHello && len(hs.ServerHello.JA4S) != 25 {
			t.Fatalf("Invalid JA4S length %d (%q)", len(hs.ServerHello.JA4S), hs.ServerHello.JA4S)
		}
	})
}

func FuzzDecryptQUICInitial(f *testing.F) {
	seed := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x14}
	f.Add(seed, seed)

	f.Fuzz(func(t *testing.T, d1, d2 []byte) {
		hdr, err := ParseQUICInitialPacket(d1)
		if err == nil && (hdr.PayloadOffset <= 0 || hdr.PacketLength > len(d1) || hdr.PayloadLength < 20 || hdr.PacketLength-hdr.PayloadOffset != hdr.PayloadLength) {
			t.Fatalf("invalid decoded packet bounds: %+v (input %d)", hdr, len(d1))
		}
		_, _ = DecryptQUICInitial([][]byte{d1, d2})
	})
}

func FuzzParseHTTP(f *testing.F) {
	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=2\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if req, _, err := ParseHTTPRequest(data); err == nil {
			if len(req.Body) > MaxHTTPBodyBytes {
				t.Fatalf("HTTP request body %d exceeds %d", len(req.Body), MaxHTTPBodyBytes)
			}
		}
		if resp, _, err := ParseHTTPResponse(data); err == nil {
			if len(resp.Body) > MaxHTTPBodyBytes {
				t.Fatalf("HTTP response body %d exceeds %d", len(resp.Body), MaxHTTPBodyBytes)
			}
		}
	})
}

func FuzzParseSSHHandshake(f *testing.F) {
	f.Add(
		buildSSHKexStream("SSH-2.0-OpenSSH_9.6", "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com", "umac-128-etm@openssh.com", "none"),
		buildSSHKexStream("SSH-2.0-OpenSSH_9.6p1", "curve25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com", "umac-128-etm@openssh.com", "none"),
	)

	f.Fuzz(func(t *testing.T, client, server []byte) {
		_, _ = ParseSSHHandshake(client, server)
	})
}

func FuzzParseSMB2AndNTLM(f *testing.F) {
	f.Add(buildSMB2SessionSetupNTLMChallenge())
	f.Add(smbSessionFrame(smbNameRequest(SMB2CommandTreeConnect, `\\server\share`)))
	f.Add(smbNameRequest(SMB2CommandCreate, "srvsvc"))
	f.Add(smbSessionFrame(smbTransformPacket()))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSMB2Message(data)
		_, _ = ParseNTLMSSP(data)
	})
}

func FuzzParseBPFBuffer(f *testing.F) {
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := ParseBPFBuffer(data, LinkTypeEthernet)
		if err != nil {
			return
		}
		for _, r := range records {
			if r.PayloadOffset+r.PayloadLength > int64(len(data)) {
				t.Fatalf("BPF record span (%d + %d) exceeds %d", r.PayloadOffset, r.PayloadLength, len(data))
			}
		}
	})
}

func FuzzDefragmentIP(f *testing.F) {
	f.Add(false, int16(0), true, []byte("01234567"), int16(8), false, []byte("89ABCDEF"), int16(0), true, []byte{})
	f.Add(true, int16(0), true, []byte("01234567"), int16(8), false, []byte("89ABCDEF"), int16(4), true, []byte("xxxx"))

	f.Fuzz(func(t *testing.T, ipv6 bool, off1 int16, mf1 bool, p1 []byte, off2 int16, mf2 bool, p2 []byte, off3 int16, mf3 bool, p3 []byte) {
		src := netip.AddrFrom4([4]byte{10, 0, 0, 1})
		dst := netip.AddrFrom4([4]byte{10, 0, 0, 2})
		if ipv6 {
			src = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
			dst = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		}
		frags := []IPFragmentInput{
			{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, FragmentOffset: int(off1), MoreFragments: mf1, Payload: p1},
			{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, FragmentOffset: int(off2), MoreFragments: mf2, Payload: p2},
			{SrcAddr: src, DstAddr: dst, Protocol: IPProtoUDP, FragmentOffset: int(off3), MoreFragments: mf3, Payload: p3},
		}
		out, _, err := DefragmentIP(frags)
		if err != nil {
			return
		}
		if len(out) > MaxReassembledIPPacketBytes {
			t.Fatalf("DefragmentIP len %d exceeds %d", len(out), MaxReassembledIPPacketBytes)
		}
	})
}

func FuzzParseHTTP2Frames(f *testing.F) {
	f.Add(append(append([]byte{}, HTTP2ClientPreface...), buildHTTP2Frame(HTTP2FrameSettings, 0, 0, make([]byte, 6))...))

	f.Fuzz(func(t *testing.T, data []byte) {
		sum, err := ParseHTTP2Frames(data)
		if err != nil {
			return
		}
		for _, s := range sum.Streams {
			if len(s.Data) > MaxHTTPBodyBytes {
				t.Fatalf("HTTP/2 stream data %d exceeds %d", len(s.Data), MaxHTTPBodyBytes)
			}
		}
	})
}

func FuzzEvalBPF(f *testing.F) {
	var prog [16]byte
	binary.LittleEndian.PutUint16(prog[0:2], bpfClassLD|bpfSizeH|bpfModeABS)
	binary.LittleEndian.PutUint32(prog[4:8], 12)
	binary.LittleEndian.PutUint16(prog[8:10], bpfClassRET|bpfRetA)
	f.Add(prog[:], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00})

	f.Fuzz(func(t *testing.T, rawProg, frame []byte) {
		count := min(len(rawProg)/8, 64)
		insns := make([]BPFInstruction, count)
		for i := range count {
			b := rawProg[i*8 : i*8+8]
			insns[i] = BPFInstruction{
				Code: binary.LittleEndian.Uint16(b[0:2]),
				JT:   b[2],
				JF:   b[3],
				K:    binary.LittleEndian.Uint32(b[4:8]),
			}
		}
		_, _ = EvalBPF(insns, frame)
	})
}

func FuzzParseKRB5(f *testing.F) {
	f.Add(buildKRB5ASReqFixture("EXAMPLE.COM", "alice", []string{"krbtgt", "EXAMPLE.COM"}, []int{18, 23}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseKRB5(data)
	})
}

func FuzzParseRDPNegotiation(f *testing.F) {
	f.Add(buildRDPConnReqPDU("mstshash=USER", RDPProtoCredSSP))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRDPNegotiation(data)
	})
}

func FuzzReaderAt(f *testing.F) {
	frame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 12345, 443, 1, 1, TCPFlagSYN, []byte("payload"))
	f.Add(buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame}))
	f.Add(buildPCAPNGFixture(binary.LittleEndian, []byte("CLIENT_RANDOM deadbeef cafebabe\n"), [][]byte{frame}))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		c, err := NewFromReaderAt(r, int64(len(data)))
		if err != nil {
			return
		}
		for _, e := range c.PacketSeqFromReaderAt(r) {
			if e != nil {
				break
			}
		}
		_, _ = c.PacketsFromReaderAt(r)
		_, _ = c.FlowsFromReaderAt(r)
		_, _ = c.DNSFromReaderAt(r)
		_, _ = c.TLSFromReaderAt(r)
		_, _ = c.QUICFromReaderAt(r)
	})
}

func FuzzTLSDecrypt(f *testing.F) {
	f.Add([]byte("CLIENT_RANDOM 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 0102030405060708090a0b0c0d0e0f10\n"), []byte{0x17, 0x03, 0x03, 0x00, 0x15, 1, 2, 3, 4, 5}, uint16(TLS_AES_128_GCM_SHA256))

	f.Fuzz(func(t *testing.T, keylog, records []byte, suite uint16) {
		kl, err := ParseTLSKeyLog(keylog)
		if err == nil && len(kl.Entries) > MaxTLSKeyLogEntries {
			t.Fatalf("keylog entries %d exceeds %d", len(kl.Entries), MaxTLSKeyLogEntries)
		}
		var secret, crand [32]byte
		var master [48]byte
		copy(secret[:], keylog)
		copy(master[:], keylog)
		copy(crand[:], records)
		_, _, _ = DecryptTLS13Records(records, suite, secret[:], secret[:])
		_, _ = DecryptTLS12Records(records, suite, master[:], crand, crand, true)
	})
}

func FuzzDecompressCapture(f *testing.F) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, nil))
	_ = zw.Close()
	f.Add(gz.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := DecompressCapture(data)
		if err != nil {
			return
		}
		if len(out) > MaxDecompressedCaptureBytes {
			t.Fatalf("DecompressCapture len %d exceeds %d", len(out), MaxDecompressedCaptureBytes)
		}
	})
}

func FuzzJA4XFromDER(f *testing.F) {
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = JA4XFromDER(der)
	})
}
