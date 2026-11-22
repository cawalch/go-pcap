package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], v)
	}
	return out
}

func TestReaderAtAndPCAPNGWriterRoundTrip(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 443, 1, 0, TCPFlagSYN, []byte("hello"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 40000, 10, 6, TCPFlagSYN|TCPFlagACK, []byte("world"))
	secret := []byte("CLIENT_TRAFFIC_SECRET_0 0102 0304\n")

	var out bytes.Buffer
	pw, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{
		LinkType:             LinkTypeEthernet,
		SnapLen:              65535,
		InterfaceName:        "en0",
		InterfaceDescription: "Primary Ethernet",
		Hardware:             "arm64",
		OS:                   "darwin",
		UserApplication:      "go-pcap-test",
	})
	if err != nil {
		t.Fatalf("NewPCAPNGWriter() error = %v", err)
	}
	if err := pw.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, secret); err != nil {
		t.Fatalf("WriteDecryptionSecrets() error = %v", err)
	}
	if err := pw.WritePacket(PacketRecord{
		TimestampNs:  1700000000123456789,
		ProcessID:    1337,
		ThreadID:     42,
		HasProcessID: true,
		HasThreadID:  true,
	}, f1); err != nil {
		t.Fatalf("WritePacket(1) error = %v", err)
	}
	if err := pw.WritePacket(PacketRecord{
		TimestampNs: 1700000001123456789,
	}, f2); err != nil {
		t.Fatalf("WritePacket(2) error = %v", err)
	}

	raw := out.Bytes()
	readerAt := bytes.NewReader(raw)
	cap, err := NewFromReaderAt(readerAt, int64(len(raw)))
	if err != nil {
		t.Fatalf("NewFromReaderAt() error = %v", err)
	}
	if cap.Format != FormatPCAPNG || cap.PacketCount != 2 || len(cap.Secrets) != 1 {
		t.Fatalf("Capture from ReaderAt = %+v", cap)
	}
	if !bytes.Equal(cap.Secrets[0].Data, secret) {
		t.Fatalf("DSB secret mismatch: got %q", cap.Secrets[0].Data)
	}

	pkts, err := cap.PacketsFromReaderAt(readerAt)
	if err != nil || len(pkts) != 2 {
		t.Fatalf("PacketsFromReaderAt() = (%d, %v)", len(pkts), err)
	}
	if !pkts[0].HasProcessID || pkts[0].ProcessID != 1337 || pkts[0].TimestampNs != 1700000000123456789 {
		t.Fatalf("pkt[0] = %+v", pkts[0])
	}
	p1Bytes, err := cap.PacketPayloadFromReaderAt(readerAt, pkts[0])
	if err != nil || !bytes.Equal(p1Bytes, f1) {
		t.Fatalf("PacketPayloadFromReaderAt(0) mismatch (err=%v)", err)
	}

	// Also verify classic PCAP via NewFromReaderAt.
	classicRaw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, [][]byte{f1, f2})
	classicReader := bytes.NewReader(classicRaw)
	classicCap, err := NewFromReaderAt(classicReader, int64(len(classicRaw)))
	if err != nil || classicCap.PacketCount != 2 {
		t.Fatalf("NewFromReaderAt(classic) = (%+v, %v)", classicCap, err)
	}
	classicPkts, err := classicCap.PacketsFromReaderAt(classicReader)
	if err != nil || len(classicPkts) != 2 {
		t.Fatalf("classicCap.PacketsFromReaderAt() = (%d, %v)", len(classicPkts), err)
	}
}

func TestParseBPFBufferBatch(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1111, 80, 1, 0, TCPFlagSYN, []byte("a"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 80, 1111, 2, 2, TCPFlagSYN|TCPFlagACK, []byte("bc"))

	var bpfBuf bytes.Buffer
	for i, frame := range [][]byte{f1, f2} {
		var hdr [18]byte
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(hdr[4:8], 500)
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(frame)))
		binary.LittleEndian.PutUint16(hdr[16:18], 18)
		bpfBuf.Write(hdr[:])
		bpfBuf.Write(frame)
		aligned := BPFWordAlign(18 + len(frame))
		if pad := aligned - (18 + len(frame)); pad > 0 {
			bpfBuf.Write(make([]byte, pad))
		}
	}

	records, err := ParseBPFBuffer(bpfBuf.Bytes(), LinkTypeEthernet)
	if err != nil || len(records) != 2 {
		t.Fatalf("ParseBPFBuffer() = (%d, %v), want 2", len(records), err)
	}
	raw := bpfBuf.Bytes()
	if !bytes.Equal(raw[records[0].PayloadOffset:records[0].PayloadOffset+records[0].PayloadLength], f1) {
		t.Fatal("BPF record 0 payload mismatch")
	}
	if !bytes.Equal(raw[records[1].PayloadOffset:records[1].PayloadOffset+records[1].PayloadLength], f2) {
		t.Fatal("BPF record 1 payload mismatch")
	}
}

func buildSMB2SessionSetupNTLMChallenge() []byte {
	// Build an NTLMSSP Type 2 Challenge token with TargetName "CORP" and AvPairs.
	targetUTF16 := encodeUTF16LE("CORP")
	var av bytes.Buffer
	writeAv := func(id uint16, s string) {
		b := encodeUTF16LE(s)
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(b)))
		av.Write(hdr[:])
		av.Write(b)
	}
	writeAv(ntlmAvNbDomainName, "CORP")
	writeAv(ntlmAvNbComputerName, "DC01")
	writeAv(ntlmAvDNSDomainName, "corp.example.com")
	writeAv(ntlmAvDNSComputerName, "dc01.corp.example.com")
	av.Write([]byte{0, 0, 0, 0}) // AvEOL

	targetOff := 56
	avOff := targetOff + len(targetUTF16)
	token := make([]byte, avOff+av.Len())
	copy(token[0:8], ntlmsspSig)
	binary.LittleEndian.PutUint32(token[8:12], NTLMChallengeMessage)
	// TargetName security buffer at offset 12.
	binary.LittleEndian.PutUint16(token[12:14], uint16(len(targetUTF16)))
	binary.LittleEndian.PutUint16(token[14:16], uint16(len(targetUTF16)))
	binary.LittleEndian.PutUint32(token[16:20], uint32(targetOff))
	// Flags at offset 20: NTLMSSP_NEGOTIATE_UNICODE (0x00000001).
	binary.LittleEndian.PutUint32(token[20:24], 0x00000001)
	// ServerChallenge at 24..32.
	copy(token[24:32], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	// TargetInfo security buffer at offset 40.
	binary.LittleEndian.PutUint16(token[40:42], uint16(av.Len()))
	binary.LittleEndian.PutUint16(token[42:44], uint16(av.Len()))
	binary.LittleEndian.PutUint32(token[44:48], uint32(avOff))
	copy(token[targetOff:], targetUTF16)
	copy(token[avOff:], av.Bytes())

	// Wrap in a 64-byte SMB2 Header + 9-byte Session Setup response header + NetBIOS 4-byte framing.
	smbLen := 64 + 8 + len(token)
	pkt := make([]byte, 4+smbLen)
	pkt[0] = 0x00
	pkt[1] = byte(smbLen >> 16)
	pkt[2] = byte(smbLen >> 8)
	pkt[3] = byte(smbLen)

	smb := pkt[4:]
	copy(smb[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(smb[4:6], 64)
	binary.LittleEndian.PutUint32(smb[8:12], 0xc0000016) // STATUS_MORE_PROCESSING_REQUIRED
	binary.LittleEndian.PutUint16(smb[12:14], SMB2CommandSessionSetup)
	binary.LittleEndian.PutUint32(smb[16:20], 0x00000001) // Server-to-client response
	binary.LittleEndian.PutUint64(smb[24:32], 1)
	binary.LittleEndian.PutUint64(smb[40:48], 0xdeadbeef)
	copy(smb[64+8:], token)
	return pkt
}

func TestSMB2AndNTLMSSPDissector(t *testing.T) {
	pkt := buildSMB2SessionSetupNTLMChallenge()
	msg, err := ParseSMB2Message(pkt)
	if err != nil {
		t.Fatalf("ParseSMB2Message() error = %v", err)
	}
	if !msg.IsResponse || msg.Command != SMB2CommandSessionSetup || !msg.HasNTLM {
		t.Fatalf("SMB2Message = %+v", msg)
	}
	ntlm := msg.NTLM
	if ntlm.MessageType != NTLMChallengeMessage ||
		ntlm.ServerChallenge != "1122334455667788" ||
		ntlm.TargetName != "CORP" ||
		ntlm.NetBIOSComputerName != "DC01" ||
		ntlm.DNSComputerName != "dc01.corp.example.com" ||
		ntlm.DNSDomainName != "corp.example.com" {
		t.Fatalf("NTLMInfo = %+v", ntlm)
	}

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 1}, 445, 51000, 1, 1, TCPFlagPSH|TCPFlagACK, pkt)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{p1})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.SMB(rawPCAP)
	if err != nil || len(records) != 1 || !records[0].Message.HasNTLM {
		t.Fatalf("cap.SMB() = (%+v, %v)", records, err)
	}
}

func TestBeaconStatsAndCaptureBeacons(t *testing.T) {
	// 5 packets spaced at 10s intervals with identical 64-byte payloads.
	ts := []int64{
		10_000_000_000,
		20_000_000_000,
		30_000_000_000,
		40_000_000_000,
		50_000_000_000,
	}
	sizes := []uint64{64, 64, 64, 64, 64}
	stats := ComputeBeaconStats(ts, sizes, 320, 320)
	if stats.MedianIntervalNs != 10_000_000_000 || stats.MADIntervalNs != 0 || stats.BeaconScore < 0.99 {
		t.Fatalf("BeaconStats = %+v, want high periodicity and uniformity", stats)
	}
	if stats.ProducerConsumerRatio != 0 {
		t.Fatalf("PCR = %v, want 0", stats.ProducerConsumerRatio)
	}

	var frames [][]byte
	for range 5 {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 1}, 50000, 443, 1, 1, TCPFlagPSH|TCPFlagACK, bytes.Repeat([]byte{'A'}, 64)))
	}
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	beacons, err := cap.Beacons(rawPCAP)
	if err != nil || len(beacons) != 1 || beacons[0].Stats.BeaconScore < 0.95 {
		t.Fatalf("cap.Beacons() = (%+v, %v)", beacons, err)
	}
}
