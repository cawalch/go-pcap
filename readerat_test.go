package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

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
		TimestampNs:  int64(1700000000123456789),
		ProcessID:    1337,
		ThreadID:     42,
		HasProcessID: true,
		HasThreadID:  true,
	}, f1); err != nil {
		t.Fatalf("WritePacket(1) error = %v", err)
	}
	if err := pw.WritePacket(PacketRecord{
		TimestampNs: int64(1700000001123456789),
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
	if !pkts[0].HasProcessID || pkts[0].ProcessID != 1337 || pkts[0].TimestampNs != int64(1700000000123456789) {
		t.Fatalf("pkt[0] = %+v", pkts[0])
	}
	p1Bytes, err := cap.PacketPayloadFromReaderAt(readerAt, pkts[0])
	if err != nil || !bytes.Equal(p1Bytes, f1) {
		t.Fatalf("PacketPayloadFromReaderAt(0) mismatch (err=%v)", err)
	}

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

func TestReaderAtAndWriterBounds(t *testing.T) {
	if _, err := NewFromReaderAt(nil, 100); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewFromReaderAt(nil) err = %v, want ErrInvalidHeader", err)
	}
	if _, err := NewFromReaderAt(bytes.NewReader([]byte{1, 2}), 2); !errors.Is(err, ErrNotPCAP) {
		t.Fatalf("NewFromReaderAt(2B) err = %v, want ErrNotPCAP", err)
	}
	if _, err := NewPCAPNGWriter(nil, PCAPNGWriterOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewPCAPNGWriter(nil) err = %v, want ErrInvalidHeader", err)
	}
	if _, err := NewPCAPNGWriter(&bytes.Buffer{}, PCAPNGWriterOptions{SnapLen: MaxSnapLen + 1}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewPCAPNGWriter(oversize snaplen) err = %v, want ErrInvalidHeader", err)
	}
}

func TestPCAPNGNRBISBAndProcessExtensionsRoundTrip(t *testing.T) {
	// Issues #5 and #6: Name Resolution Block (NRB), Interface Statistics Block (ISB),
	// Darwin Process Event Block (DPEB), and EPB process attribution options (comm, args, UID, containerID).
	var out bytes.Buffer
	pw, err := NewPCAPNGWriter(&out, PCAPNGWriterOptions{
		LinkType:      LinkTypeEthernet,
		SnapLen:       65535,
		InterfaceName: "en0",
	})
	if err != nil {
		t.Fatalf("NewPCAPNGWriter() error = %v", err)
	}

	if err := pw.WriteNameResolution([]NameResolutionRecord{
		{Addr: netip.MustParseAddr("192.0.2.10"), Names: []string{"c2.example.com", "alias.example.com"}},
		{Addr: netip.MustParseAddr("2001:db8::10"), Names: []string{"v6.example.com"}},
	}); err != nil {
		t.Fatalf("WriteNameResolution() error = %v", err)
	}

	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 1}, 44444, 443, 1, 0, TCPFlagSYN, []byte("hi"))
	if err := pw.WritePacket(PacketRecord{
		TimestampNs:  int64(1700000000000000000),
		ProcessID:    9001,
		ThreadID:     77,
		UserID:       501,
		ProcessName:  "curl",
		ProcessArgs:  "curl -k https://c2.example.com",
		ContainerID:  "ctr-123456",
		HasProcessID: true,
		HasThreadID:  true,
		HasUserID:    true,
	}, frame); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}

	if err := pw.WriteInterfaceStats(InterfaceStatistics{
		InterfaceID:        0,
		TimestampNs:        int64(1700000010000000000),
		StartTimeNs:        int64(1700000000000000000),
		EndTimeNs:          int64(1700000010000000000),
		PacketsReceived:    100,
		PacketsDropped:     2,
		HasStartTime:       true,
		HasEndTime:         true,
		HasPacketsReceived: true,
		HasPacketsDropped:  true,
	}); err != nil {
		t.Fatalf("WriteInterfaceStats() error = %v", err)
	}

	// Also append a Darwin Process Event Block (DPEB) and an EPB referencing DPEB index 0.
	var dpebBody bytes.Buffer
	var pidBytes [4]byte
	binary.LittleEndian.PutUint32(pidBytes[:], 8888)
	dpebBody.Write(pidBytes[:])
	writePCAPNGOptionLE(&dpebBody, optDPEBProcessName, []byte("safari\x00"))
	writePCAPNGOptionLE(&dpebBody, optEndOfOpt, nil)
	writePCAPNGBlockLE(&out, BlockTypeDarwinProcessEvent, dpebBody.Bytes())

	raw := out.Bytes()
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(cap.NameRecords) != 2 || cap.NameRecords[0].Names[0] != "c2.example.com" || cap.NameRecords[1].Names[0] != "v6.example.com" {
		t.Fatalf("NameRecords = %+v", cap.NameRecords)
	}
	if len(cap.InterfaceStats) != 1 || cap.InterfaceStats[0].PacketsReceived != 100 || cap.InterfaceStats[0].PacketsDropped != 2 {
		t.Fatalf("InterfaceStats = %+v", cap.InterfaceStats)
	}
	if len(cap.Processes) != 1 || cap.Processes[0].ProcessID != 8888 || cap.Processes[0].ProcessName != "safari" {
		t.Fatalf("Processes = %+v", cap.Processes)
	}

	flows, err := cap.Flows(raw)
	if err != nil || len(flows) != 1 {
		t.Fatalf("Flows() = (%d, %v)", len(flows), err)
	}
	f := flows[0]
	if f.ProcessID != 9001 || f.UserID != 501 || !f.HasUserID || f.ProcessName != "curl" || f.ProcessArgs != "curl -k https://c2.example.com" || f.ContainerID != "ctr-123456" {
		t.Fatalf("FlowSummary process metadata = %+v", f)
	}
}

func TestReaderAtDissectorsParity(t *testing.T) {
	dnsMsg := buildDNSQueryResponsePacket()
	dnsFrame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 55123, 53, dnsMsg)

	tlsCH := buildTLS13ClientHelloRecord("readerat.example.com", "h2")
	tlsSyn := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 49152, 443, 100, 0, TCPFlagSYN, nil)
	tlsPsh := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 49152, 443, 101, 1, TCPFlagPSH|TCPFlagACK, tlsCH)

	quicCH := buildTLS13ClientHelloRecord("quic-readerat.example.com", "h3")
	quicDgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12}, nil, 1, 0, quicCH[5:])
	quicFrame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 3}, 55124, 443, quicDgram)

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		dnsFrame, tlsSyn, tlsPsh, quicFrame,
	})
	ra := bytes.NewReader(raw)
	cap, err := NewFromReaderAt(ra, int64(len(raw)))
	if err != nil {
		t.Fatalf("NewFromReaderAt() error = %v", err)
	}

	flows, err := cap.FlowsFromReaderAt(ra)
	if err != nil || len(flows) != 3 {
		t.Fatalf("FlowsFromReaderAt() = (%d, %v), want 3", len(flows), err)
	}

	dnsRecs, err := cap.DNSFromReaderAt(ra)
	if err != nil || len(dnsRecs) != 1 || len(dnsRecs[0].Message.Questions) != 1 {
		t.Fatalf("DNSFromReaderAt() = (%+v, %v)", dnsRecs, err)
	}

	tlsRecs, err := cap.TLSFromReaderAt(ra)
	if err != nil || len(tlsRecs) != 1 || tlsRecs[0].Handshake.ClientHello.SNI != "readerat.example.com" {
		t.Fatalf("TLSFromReaderAt() = (%+v, %v)", tlsRecs, err)
	}

	quicRecs, err := cap.QUICFromReaderAt(ra)
	if err != nil || len(quicRecs) != 1 || quicRecs[0].Handshake.ClientHello.SNI != "quic-readerat.example.com" {
		t.Fatalf("QUICFromReaderAt() = (%+v, %v)", quicRecs, err)
	}
}
