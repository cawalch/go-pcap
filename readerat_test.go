package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
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
