package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func buildEthernetIPv4TCPFrame(
	srcIP, dstIP [4]byte,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags uint8,
	payload []byte,
) []byte {
	tcpLen := 20 + len(payload)
	ipTotalLen := 20 + tcpLen
	frame := make([]byte, 14+ipTotalLen)

	// Ethernet header: dst MAC (6), src MAC (6), EtherType IPv4 (2).
	frame[0], frame[1], frame[2], frame[3], frame[4], frame[5] = 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
	frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] = 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)

	// IPv4 header (20 bytes).
	ip := frame[14:34]
	ip[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen))
	ip[8] = 64 // TTL
	ip[9] = IPProtoTCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	// TCP header (20 bytes).
	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // Data offset = 20 bytes
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(frame[54:], payload)
	return frame
}

func buildClassicPCAP(order binary.ByteOrder, nano bool, linkType LinkType, snapLen uint32, frames [][]byte) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 24)
	magic := PCAPMagicMicroLE
	if nano {
		magic = PCAPMagicNanoLE
	}
	// When writing in big-endian order, writing PCAPMagicMicroLE (0xa1b2c3d4)
	// via binary.BigEndian produces bytes a1 b2 c3 d4 on wire, which reads back
	// as 0xd4c3b2a1 in little-endian (PCAPMagicMicroBE).
	order.PutUint32(hdr[0:4], magic)
	order.PutUint16(hdr[4:6], 2)
	order.PutUint16(hdr[6:8], 4)
	order.PutUint32(hdr[16:20], snapLen)
	order.PutUint32(hdr[20:24], uint32(linkType))
	buf.Write(hdr)

	for i, frame := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec[0:4], uint32(1700000000+i))
		order.PutUint32(rec[4:8], uint32((i+1)*500))
		order.PutUint32(rec[8:12], uint32(len(frame)))
		order.PutUint32(rec[12:16], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes()
}

func appendPCAPNGBlock(buf *bytes.Buffer, order binary.ByteOrder, blockType uint32, body []byte) {
	paddedBodyLen := len(body)
	if rem := paddedBodyLen % 4; rem != 0 {
		paddedBodyLen += 4 - rem
	}
	totalLen := uint32(12 + paddedBodyLen)
	var tmp [8]byte
	order.PutUint32(tmp[0:4], blockType)
	order.PutUint32(tmp[4:8], totalLen)
	buf.Write(tmp[:])
	buf.Write(body)
	if pad := paddedBodyLen - len(body); pad > 0 {
		buf.Write(make([]byte, pad))
	}
	order.PutUint32(tmp[0:4], totalLen)
	buf.Write(tmp[0:4])
}

func appendPCAPNGOption(buf *bytes.Buffer, order binary.ByteOrder, code uint16, val []byte) {
	var hdr [4]byte
	order.PutUint16(hdr[0:2], code)
	order.PutUint16(hdr[2:4], uint16(len(val)))
	buf.Write(hdr[:])
	buf.Write(val)
	if rem := len(val) % 4; rem != 0 {
		buf.Write(make([]byte, 4-rem))
	}
}

func buildPCAPNGFixture(order binary.ByteOrder, secretData []byte, frames [][]byte) []byte {
	var buf bytes.Buffer

	// 1. Section Header Block (SHB).
	var shb bytes.Buffer
	var shbFixed [16]byte
	order.PutUint32(shbFixed[0:4], PCAPNGByteOrderMagic)
	order.PutUint16(shbFixed[4:6], 1)
	order.PutUint16(shbFixed[6:8], 0)
	order.PutUint64(shbFixed[8:16], 0xffffffffffffffff)
	shb.Write(shbFixed[:])
	appendPCAPNGOption(&shb, order, optSHBHardware, []byte("arm64"))
	appendPCAPNGOption(&shb, order, optSHBOS, []byte("darwin"))
	appendPCAPNGOption(&shb, order, optSHBUserAppl, []byte("go-pcap"))
	appendPCAPNGOption(&shb, order, optEndOfOpt, nil)
	appendPCAPNGBlock(&buf, order, BlockTypeSectionHeader, shb.Bytes())

	// 2. Interface Description Block (IDB).
	var idb bytes.Buffer
	var idbFixed [8]byte
	order.PutUint16(idbFixed[0:2], uint16(LinkTypeEthernet))
	order.PutUint32(idbFixed[4:8], 65535)
	idb.Write(idbFixed[:])
	appendPCAPNGOption(&idb, order, optIDBName, []byte("en0"))
	appendPCAPNGOption(&idb, order, optIDBDescription, []byte("Wi-Fi"))
	appendPCAPNGOption(&idb, order, optIDBTsResol, []byte{9}) // 10^-9 s (nanoseconds)
	appendPCAPNGOption(&idb, order, optEndOfOpt, nil)
	appendPCAPNGBlock(&buf, order, BlockTypeInterfaceDesc, idb.Bytes())

	// 3. Optional Decryption Secrets Block (DSB).
	if len(secretData) > 0 {
		var dsb bytes.Buffer
		var dsbFixed [8]byte
		order.PutUint32(dsbFixed[0:4], SecretsTypeTLSKeyLog)
		order.PutUint32(dsbFixed[4:8], uint32(len(secretData)))
		dsb.Write(dsbFixed[:])
		dsb.Write(secretData)
		if rem := len(secretData) % 4; rem != 0 {
			dsb.Write(make([]byte, 4-rem))
		}
		appendPCAPNGOption(&dsb, order, optEndOfOpt, nil)
		appendPCAPNGBlock(&buf, order, BlockTypeDecryptionSecrets, dsb.Bytes())
	}

	// 4. Enhanced Packet Blocks (EPB) with process attribution options.
	for i, frame := range frames {
		var epb bytes.Buffer
		var epbFixed [20]byte
		ts := uint64(1700000000000000000) + uint64(i)*1000000
		order.PutUint32(epbFixed[0:4], 0) // Interface ID 0
		order.PutUint32(epbFixed[4:8], uint32(ts>>32))
		order.PutUint32(epbFixed[8:12], uint32(ts&0xffffffff))
		order.PutUint32(epbFixed[12:16], uint32(len(frame)))
		order.PutUint32(epbFixed[16:20], uint32(len(frame)))
		epb.Write(epbFixed[:])
		epb.Write(frame)
		if rem := len(frame) % 4; rem != 0 {
			epb.Write(make([]byte, 4-rem))
		}
		var pidBytes, tidBytes [4]byte
		order.PutUint32(pidBytes[:], 4242)
		order.PutUint32(tidBytes[:], 99)
		appendPCAPNGOption(&epb, order, optEPBDarwinProcessIndex, pidBytes[:])
		appendPCAPNGOption(&epb, order, optEPBLegacyThreadID, tidBytes[:])
		appendPCAPNGOption(&epb, order, optEndOfOpt, nil)
		appendPCAPNGBlock(&buf, order, BlockTypeEnhancedPacket, epb.Bytes())
	}

	return buf.Bytes()
}

func TestClassicPCAPVariants(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 51234, 443, 100, 0, TCPFlagSYN, nil)
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 443, 51234, 200, 101, TCPFlagSYN|TCPFlagACK, []byte("hello"))

	cases := []struct {
		name  string
		order binary.ByteOrder
		nano  bool
	}{
		{"MicroLE", binary.LittleEndian, false},
		{"MicroBE", binary.BigEndian, false},
		{"NanoLE", binary.LittleEndian, true},
		{"NanoBE", binary.BigEndian, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildClassicPCAP(tc.order, tc.nano, LinkTypeEthernet, 65535, [][]byte{f1, f2})
			cap, err := New(raw)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if cap.Format != FormatPCAP {
				t.Fatalf("Format = %v, want FormatPCAP", cap.Format)
			}
			if cap.PacketCount != 2 {
				t.Fatalf("PacketCount = %d, want 2", cap.PacketCount)
			}
			if cap.InputTruncated() {
				t.Fatal("InputTruncated() = true, want false")
			}
			if cap.Anomalies().Any() {
				t.Fatalf("Anomalies() = %+v, want none", cap.Anomalies())
			}

			packets, err := cap.Packets(raw)
			if err != nil || len(packets) != 2 {
				t.Fatalf("Packets() = (%d, %v), want (2, nil)", len(packets), err)
			}
			p2Bytes, err := cap.PacketPayload(raw, packets[1])
			if err != nil || !bytes.Equal(p2Bytes, f2) {
				t.Fatalf("PacketPayload(1) mismatch (err=%v)", err)
			}
		})
	}
}

func TestPCAPNGWithDSBProcessAttributionAndFlows(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{192, 168, 1, 10}, [4]byte{93, 184, 216, 34}, 54321, 443, 1, 0, TCPFlagSYN, []byte("client-hello"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{93, 184, 216, 34}, [4]byte{192, 168, 1, 10}, 443, 54321, 10, 13, TCPFlagSYN|TCPFlagACK, []byte("server-hello-reply"))
	keylog := []byte("CLIENT_HANDSHAKE_TRAFFIC_SECRET 01020304 05060708\n")

	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		raw := buildPCAPNGFixture(order, keylog, [][]byte{f1, f2})
		cap, err := New(raw)
		if err != nil {
			t.Fatalf("New(PCAPNG) error = %v", err)
		}
		if cap.Format != FormatPCAPNG {
			t.Fatalf("Format = %v, want FormatPCAPNG", cap.Format)
		}
		if cap.Hardware != "arm64" || cap.OS != "darwin" || cap.UserAppl != "go-pcap" {
			t.Fatalf("SHB options = (%q, %q, %q)", cap.Hardware, cap.OS, cap.UserAppl)
		}
		if len(cap.Interfaces) != 1 || cap.Interfaces[0].Name != "en0" {
			t.Fatalf("Interfaces = %+v", cap.Interfaces)
		}
		if len(cap.Secrets) != 1 || cap.Secrets[0].SecretsType != SecretsTypeTLSKeyLog || !bytes.Equal(cap.Secrets[0].Data, keylog) {
			t.Fatalf("Secrets = %+v", cap.Secrets)
		}

		packets, err := cap.Packets(raw)
		if err != nil || len(packets) != 2 {
			t.Fatalf("Packets() = (%d, %v), want 2", len(packets), err)
		}
		if !packets[0].HasProcessID || packets[0].ProcessID != 4242 || !packets[0].HasThreadID || packets[0].ThreadID != 99 {
			t.Fatalf("EPB process metadata = %+v", packets[0])
		}

		flows, err := cap.Flows(raw)
		if err != nil || len(flows) != 1 {
			t.Fatalf("Flows() = (%d, %v), want 1", len(flows), err)
		}
		flow := flows[0]
		if flow.Protocol != IPProtoTCP ||
			flow.SrcAddr != netip.MustParseAddr("192.168.1.10") ||
			flow.DstAddr != netip.MustParseAddr("93.184.216.34") ||
			flow.SrcPort != 54321 ||
			flow.DstPort != 443 ||
			flow.ClientPackets != 1 ||
			flow.ServerPackets != 1 ||
			flow.ClientBytes != uint64(len("client-hello")) ||
			flow.ServerBytes != uint64(len("server-hello-reply")) ||
			flow.ProcessID != 4242 ||
			!flow.HasProcessID ||
			flow.TCPFlags != (TCPFlagSYN|TCPFlagACK) {
			t.Fatalf("FlowSummary = %+v", flow)
		}
	}
}

func TestOpenFile(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 1234, 80, 1, 1, TCPFlagACK, []byte("GET / HTTP/1.1\r\n\r\n"))
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{f1})
	path := filepath.Join(t.TempDir(), "sample.pcap")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cap, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if cap.PacketCount != 1 || cap.FileSize() != int64(len(raw)) {
		t.Fatalf("Capture = %+v, fileSize=%d", cap, cap.FileSize())
	}
}

func ExampleCapture_UnsupportedLinkTypePackets() {
	var buf bytes.Buffer
	writer, err := NewPCAPWriter(&buf, LinkType(9), 64) // LINKTYPE_PPP
	if err != nil {
		panic(err)
	}
	if err := writer.WritePacket(1, []byte{0xff, 0x03, 0x00, 0x21}); err != nil {
		panic(err)
	}
	capture, err := New(buf.Bytes())
	if err != nil {
		panic(err)
	}
	count, interfaces := capture.UnsupportedLinkTypePackets()
	fmt.Printf("%d of %d packets have unsupported link types on interfaces %v\n", count, capture.PacketCount, interfaces)
	// Output:
	// 1 of 1 packets have unsupported link types on interfaces [0]
}
