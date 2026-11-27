package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
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
	if len(cap.Processes) != 1 || cap.Processes[0].ProcessID != 9001 || cap.Processes[0].ProcessName != "curl" {
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

	quicCH := buildTLS13ClientHelloRecord("quic-readerat.example.com", "h3")
	quicDgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12}, nil, 1, 0, quicCH[5:])
	quicFrame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 3}, 55124, 443, quicDgram)

	// Deliver a split ClientHello out of order, after its SYN.
	tlsTail := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 49152, 443, 121, 1, TCPFlagACK, tlsCH[20:])
	tlsPsh := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 49152, 443, 101, 1, TCPFlagACK, tlsCH[:20])
	frames := [][]byte{dnsFrame, tlsSyn, tlsTail, tlsPsh, quicFrame}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	for _, data := range [][]byte{raw, buildPCAPNGFixture(binary.BigEndian, nil, frames)} {
		c, err := NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		checkReaderParity(t, data, c.DNS, c.DNSFromReaderAt)
		checkReaderParity(t, data, c.TLS, c.TLSFromReaderAt)
		checkReaderParity(t, data, c.QUIC, c.QUICFromReaderAt)
	}

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

func TestReaderAtFlowParity(t *testing.T) {
	var frames [][]byte
	for i, size := range []int{4, 16, 1440, 1440, 300} {
		f := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, uint16(1024+i), 443, 1, 0, TCPFlagACK, make([]byte, size))
		switch i {
		case 0, 4:
			f = append(f, make([]byte, 30)...)
		case 1, 3:
			f = f[:len(f)-8]
		}
		frames = append(frames, f)
	}
	// A 256-byte hop-by-hop header places TCP beyond the initial prefix.
	v6 := make([]byte, 14+40+256+20+1440)
	binary.BigEndian.PutUint16(v6[12:], EtherTypeIPv6)
	v6[14] = 0x60
	binary.BigEndian.PutUint16(v6[18:], uint16(len(v6)-54))
	v6[54], v6[55] = IPProtoTCP, 31
	copy(v6[310:], frames[0][34:54])
	frames = append(frames, v6)

	// Long UDP frames (> flowPrefixBytes) where IP and UDP declared lengths differ.
	udpShorter := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40001, 50001, make([]byte, 400))
	binary.BigEndian.PutUint16(udpShorter[34+4:34+6], 300) // UDP length < IP payload
	udpLonger := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40002, 50002, make([]byte, 400))
	binary.BigEndian.PutUint16(udpLonger[34+4:34+6], 500) // UDP length > IP payload
	frames = append(frames, udpShorter, udpLonger)

	// Classic PCAP metadata and all flow headers are available. Reading the
	// application payload past byte 512 of the frame would return EOF.
	classic := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{v6})
	r := bytes.NewReader(classic[:pcapGlobalHeaderSize+pcapPacketHeaderSize+512])
	c, err := NewFromReaderAt(r, int64(len(classic)))
	if err != nil {
		t.Fatal(err)
	}
	deep, err := c.FlowsFromReaderAt(r)
	if err != nil || len(deep) != 1 || deep[0].ClientBytes != 1440 || deep[0].DstPort != 443 {
		t.Fatalf("deep header flow: %+v, %v", deep, err)
	}
	for _, raw := range [][]byte{buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames), buildPCAPNGFixture(binary.LittleEndian, nil, frames)} {
		buf, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		want, err := buf.Flows(raw)
		if err != nil || len(want) != len(frames) {
			t.Fatalf("slice flows = %v, %v", want, err)
		}
		r := bytes.NewReader(raw)
		c, err := NewFromReaderAt(r, int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.FlowsFromReaderAt(r)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("%v flows = %+v, %v; want %+v", c.Format, got, err, want)
		}
	}
}

func TestPCAPNGSectionInterfaces(t *testing.T) {
	first := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{{1, 2, 3}})
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		var section bytes.Buffer
		shb := make([]byte, 16)
		order.PutUint32(shb, PCAPNGByteOrderMagic)
		order.PutUint16(shb[4:], 1)
		order.PutUint64(shb[8:], ^uint64(0))
		appendPCAPNGBlock(&section, order, BlockTypeSectionHeader, shb)
		header := bytes.Clone(section.Bytes())
		idb := make([]byte, 8)
		order.PutUint16(idb, uint16(LinkTypeRaw))
		order.PutUint32(idb[4:], 3)
		appendPCAPNGBlock(&section, order, BlockTypeInterfaceDesc, idb)
		epb := make([]byte, 24)
		order.PutUint32(epb[8:], 2)
		order.PutUint32(epb[12:], 3)
		order.PutUint32(epb[16:], 3)
		copy(epb[20:], []byte{4, 5, 6})
		appendPCAPNGBlock(&section, order, BlockTypeEnhancedPacket, epb)
		spb := make([]byte, 8)
		order.PutUint32(spb, 10)
		copy(spb[4:], []byte{7, 8, 9, 0})
		appendPCAPNGBlock(&section, order, BlockTypeSimplePacket, spb)
		isb := make([]byte, 12)
		order.PutUint32(isb[8:], 3)
		appendPCAPNGBlock(&section, order, BlockTypeInterfaceStats, isb)
		raw := append(bytes.Clone(first), section.Bytes()...)
		r := bytes.NewReader(raw)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := NewFromReaderAt(r, int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		for _, cap := range []*Capture{c, rc} {
			if len(cap.Interfaces) != 2 || len(cap.InterfaceStats) != 1 || cap.InterfaceStats[0].InterfaceID != 1 || cap.InterfaceStats[0].TimestampNs != 3000 {
				t.Fatalf("section metadata: %+v", cap)
			}
		}
		want, err := c.Packets(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rc.PacketsFromReaderAt(r)
		if err != nil || !slices.Equal(want, got) || len(got) != 3 {
			t.Fatalf("packet parity: %+v, %+v, %v", want, got, err)
		}
		if got[1].LinkType != LinkTypeRaw || got[1].TimestampNs != 2000 || got[1].InterfaceID != 1 || got[2].InterfaceID != 1 || got[2].LinkType != LinkTypeRaw || got[2].CaptureLen != 3 || got[2].OriginalLen != 10 {
			t.Fatalf("section packets: %+v", got)
		}
		a, err := c.PacketPayload(raw, want[2])
		if err != nil {
			t.Fatal(err)
		}
		b, err := rc.PacketPayloadFromReaderAt(r, got[2])
		if err != nil || !bytes.Equal(a, []byte{7, 8, 9}) || !bytes.Equal(a, b) {
			t.Fatalf("SPB payload: %x, %x, %v", a, b, err)
		}

		for _, tc := range []struct {
			kind uint32
			body []byte
		}{{BlockTypeEnhancedPacket, epb}, {BlockTypeSimplePacket, spb}, {BlockTypeInterfaceStats, isb}} {
			var bad bytes.Buffer
			bad.Write(first)
			bad.Write(header)
			appendPCAPNGBlock(&bad, order, tc.kind, tc.body)
			if _, err := New(bad.Bytes()); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("section without interface: %v", err)
			}
			if _, err := NewFromReaderAt(bytes.NewReader(bad.Bytes()), int64(bad.Len())); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("ReaderAt section without interface: %v", err)
			}
		}
		var bad bytes.Buffer
		bad.Write(first)
		appendPCAPNGBlock(&bad, binary.LittleEndian, BlockTypeSimplePacket, []byte{16, 0, 0, 0, 1, 2, 3, 4})
		if _, err := New(bad.Bytes()); !errors.Is(err, ErrInvalidBlock) {
			t.Fatalf("short SPB: %v", err)
		}
		if _, err := NewFromReaderAt(bytes.NewReader(bad.Bytes()), int64(bad.Len())); !errors.Is(err, ErrInvalidBlock) {
			t.Fatalf("short ReaderAt SPB: %v", err)
		}
	}
}

type readAtFunc func([]byte, int64) (int, error)

func (f readAtFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

func TestPacketSeqFromReaderAt(t *testing.T) {
	frames := [][]byte{{1, 2, 3, 4, 5}, {6, 7, 8}}
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		for _, format := range []string{"PCAP", "PcapNG"} {
			t.Run(format+"/"+order.String(), func(t *testing.T) {
				var raw []byte
				if format == "PCAP" {
					raw = buildClassicPCAP(order, true, LinkTypeEthernet, 65535, frames)
				} else {
					buf := bytes.NewBuffer(buildPCAPNGFixture(order, []byte("secret"), frames))
					body := make([]byte, 4)
					order.PutUint32(body, 5)
					appendPCAPNGBlock(buf, order, BlockTypeSimplePacket, append(body, frames[0]...))
					raw = buf.Bytes()
				}
				c, err := New(raw)
				if err != nil {
					t.Fatal(err)
				}
				want, err := c.Packets(raw)
				if err != nil {
					t.Fatal(err)
				}
				src := bytes.NewReader(raw)
				limit := int64(len(raw))
				injected := errors.New("next record read")
				r := readAtFunc(func(p []byte, off int64) (int, error) {
					if off+int64(len(p)) > limit {
						return 0, injected
					}
					for _, pkt := range want {
						n := pkt.PayloadLength
						if format == "PcapNG" {
							n = (n + 3) &^ 3
						}
						if off < pkt.PayloadOffset+n && off+int64(len(p)) > pkt.PayloadOffset {
							t.Fatalf("read [%d,%d) intersects packet %d", off, off+int64(len(p)), pkt.Index)
						}
					}
					return src.ReadAt(p, off)
				})
				meta, err := NewFromReaderAt(r, int64(len(raw)))
				if err != nil || !reflect.DeepEqual(c, meta) {
					t.Fatalf("metadata mismatch: got %+v, want %+v (err %v)", meta, c, err)
				}
				got, err := meta.PacketsFromReaderAt(r)
				if err != nil || !slices.Equal(got, want) {
					t.Fatalf("packets = %+v, want %+v (err %v)", got, want, err)
				}
				limit = want[1].PayloadOffset - pcapPacketHeaderSize
				if format == "PcapNG" {
					limit = want[1].PayloadOffset - 28
				}
				var first []PacketRecord
				for pkt, err := range meta.PacketSeqFromReaderAt(r) {
					if err != nil {
						t.Fatal(err)
					}
					first = append(first, pkt)
					break
				}
				if !slices.Equal(first, want[:1]) {
					t.Fatalf("first = %+v", first)
				}
				var prefix []PacketRecord
				var errs []error
				for pkt, err := range meta.PacketSeqFromReaderAt(r) {
					if err != nil {
						errs = append(errs, err)
					} else {
						prefix = append(prefix, pkt)
					}
				}
				if !slices.Equal(prefix, want[:1]) || len(errs) != 1 || !errors.Is(errs[0], injected) {
					t.Fatalf("prefix = %+v, errors = %v", prefix, errs)
				}
				if got, err := meta.PacketsFromReaderAt(r); got != nil || !errors.Is(err, injected) {
					t.Fatalf("collector = %+v, %v", got, err)
				}
			})
		}
	}
}

func TestReaderAtMalformedPacketParity(t *testing.T) {
	order := binary.LittleEndian
	base := buildPCAPNGFixture(order, nil, nil)
	raw := buildPCAPNGFixture(order, nil, [][]byte{{1, 2, 3}})
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
		want   error
	}{
		{"interface", 8, 2, ErrInvalidPacket},
		{"capture length", 20, 1024, ErrInvalidBlock},
		{"option length", 32, 0xffff0001, ErrOptionLimit},
		{"trailer", len(raw) - len(base) - 4, 12, ErrInvalidBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Clone(raw)
			order.PutUint32(data[len(base)+tc.offset:], tc.value)
			_, sliceErr := New(data)
			_, readerErr := NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
			if !errors.Is(sliceErr, tc.want) || !errors.Is(readerErr, tc.want) {
				t.Fatalf("slice %v, reader %v, want %v", sliceErr, readerErr, tc.want)
			}
		})
	}
	// A truncated block can declare a size larger than the metadata buffer limit.
	huge := bytes.Clone(raw)
	order.PutUint32(huge[len(base)+4:], 0xfffffffc)
	slice, err := New(huge)
	if err != nil || !slice.InputTruncated() {
		t.Fatalf("slice = %+v, %v", slice, err)
	}
	reader, err := NewFromReaderAt(bytes.NewReader(huge), int64(len(huge)))
	if err != nil || !reflect.DeepEqual(slice, reader) {
		t.Fatalf("oversized truncated block: got %+v, want %+v (err %v)", reader, slice, err)
	}
	for n := len(base); n < len(raw); n++ {
		c, err := New(raw[:n])
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewFromReaderAt(bytes.NewReader(raw[:n]), int64(n))
		if err != nil || !reflect.DeepEqual(c, got) {
			t.Fatalf("cut at %d: got %+v, want %+v (err %v)", n, got, c, err)
		}
	}
}

type descriptorReader struct{ io.ReaderAt }

func (descriptorReader) Fd() uintptr { panic("a scan must not access the descriptor") }

// Use 64 KiB classic PCAP records so 1,024 complete records exactly consume
// the 64 MiB read budget. The virtual capture stores one physical record.
func TestReaderAtScanReadBudget(t *testing.T) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	const recordBytes = 64 << 10
	const records = MaxReaderAtScanBytes/recordBytes + 1
	for _, proto := range []string{"DNS", "TLS", "QUIC", "flows"} {
		t.Run(proto, func(t *testing.T) {
			frames := [][]byte{
				buildEthernetIPv4UDPFrame(src, dst, 1234, 5678, make([]byte, recordBytes-16-42)),
				buildEthernetIPv4UDPFrame(src, dst, 1234, 53, make([]byte, recordBytes-16-42)),
			}
			if proto == "TLS" {
				payload := make([]byte, recordBytes-16-54)
				// Fill the capture with separate candidate handshake flights.
				for off := 0; off+5 <= len(payload); {
					n := min(16384, len(payload)-off-5)
					payload[off], payload[off+1], payload[off+2] = TLSRecordHandshake, 3, 3
					binary.BigEndian.PutUint16(payload[off+3:], uint16(n))
					if n > 0 {
						payload[off+5] = TLSHandshakeCertificate
					}
					off += 5 + n
				}
				frames[1] = buildEthernetIPv4TCPFrame(src, dst, 1234, 443, 1, 0, TCPFlagACK, payload)
			}
			if proto == "flows" {
				// ICMP flow accounting reads the entire declared datagram.
				frames[1][23] = IPProtoICMP
			}
			if proto == "QUIC" {
				frames[1][42] = 0xc0
			}
			// Put one real record after the first 64 MiB of sparse traffic.
			var last []byte
			switch proto {
			case "DNS":
				last = buildEthernetIPv4UDPFrame(src, dst, 1234, 53, buildDNSQueryResponsePacket())
			case "TLS":
				last = buildEthernetIPv4TCPFrame(src, dst, 1234, 8443, 1, 0, TCPFlagACK, buildTLS13ClientHelloRecord("last.example", "h2"))
			case "QUIC":
				hello := buildTLS13ClientHelloRecord("last.example", "h3")
				packet := buildEncryptedQUICInitialDatagram(t, QUICVersion2, []byte{1, 2, 3, 4}, nil, nil, 1, 0, hello[5:])
				last = buildEthernetIPv4UDPFrame(src, dst, 1234, 4443, packet)
			}
			for i, frame := range frames {
				raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame})
				const size = int64(pcapGlobalHeaderSize + records*recordBytes)
				var calls, read int64
				r := readAtFunc(func(p []byte, off int64) (int, error) {
					if off < 0 || off+int64(len(p)) > size {
						return 0, io.EOF
					}
					pos := off
					if pos >= pcapGlobalHeaderSize {
						pos = pcapGlobalHeaderSize + (pos-pcapGlobalHeaderSize)%recordBytes
					}
					n := copy(p, raw[pos:])
					if proto == "TLS" && i == 1 && pos == pcapGlobalHeaderSize+16 && len(p) >= 38 {
						binary.BigEndian.PutUint16(p[34:], uint16(1234+(off-pcapGlobalHeaderSize)/recordBytes))
					}
					if i == 0 && off == size-recordBytes+16 {
						copy(p, last)
					}
					if n != len(p) {
						t.Fatal("read crossed a record boundary")
					}
					calls++
					read += int64(n)
					return n, nil
				})
				c, err := NewFromReaderAt(r, size)
				if err != nil || c.PacketCount != records {
					t.Fatalf("open: %v", err)
				}
				calls, read = 0, 0
				// Advertise the same capability as a file-backed reader. A scan
				// beyond the budget must preserve exact sparse access.
				disk := descriptorReader{r}
				var count int
				switch proto {
				case "flows":
					results, e := c.FlowsFromReaderAt(disk)
					count, err = len(results), e
				case "DNS":
					results, e := c.DNSFromReaderAt(disk)
					count, err = len(results), e
				case "TLS":
					results, e := c.TLSFromReaderAt(disk)
					count, err = len(results), e
				case "QUIC":
					results, e := c.QUICFromReaderAt(disk)
					count, err = len(results), e
				}
				if i == 0 {
					if err != nil || count != 1 || calls != 2*records || read != records*(16+256) {
						t.Fatalf("selective scan: %d records, %v, %d reads, %d bytes", count, err, calls, read)
					}
				} else if proto == "TLS" {
					if !errors.Is(err, ErrPacketLimit) || count != 0 || read > MaxReaderAtScanBytes || read <= MaxReaderAtScanBytes-recordBytes {
						t.Fatalf("TLS budget: %d records, %v, %d reads, %d bytes", count, err, calls, read)
					}
				} else if !errors.Is(err, ErrPacketLimit) || count != 0 || read != MaxReaderAtScanBytes || calls != 3*(records-1) {
					t.Fatalf("exhausted scan: %d records, %v, %d reads, %d bytes", count, err, calls, read)
				}
			}
		})
	}
}

func checkReaderParity[T any](t *testing.T, raw []byte, slice func([]byte) ([]T, error), reader func(io.ReaderAt) ([]T, error)) []T {
	t.Helper()
	want, err := slice(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReaderAt = %+v, %v; slice = %+v", got, err, want)
	}
	return want
}

func TestReaderAtProtocolErrors(t *testing.T) {
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 1234, 53, buildDNSQueryResponsePacket())})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	injected := errors.New("reader stopped")
	checkProtocolErrors(t, c.DNS, c.DNSFromReaderAt, bad, injected)
	checkProtocolErrors(t, c.TLS, c.TLSFromReaderAt, bad, injected)
	checkProtocolErrors(t, c.QUIC, c.QUICFromReaderAt, bad, injected)
	checkProtocolErrors(t, c.HTTP1RequestEvidence, c.HTTP1RequestEvidenceFromReaderAt, bad, injected)
}

func checkProtocolErrors[T any](t *testing.T, slice func([]byte) ([]T, error), reader func(io.ReaderAt) ([]T, error), bad []byte, injected error) {
	t.Helper()
	want, se := slice(bad)
	got, re := reader(bytes.NewReader(bad))
	if want != nil || got != nil || !errors.Is(se, ErrInvalidBlock) || !errors.Is(re, ErrInvalidBlock) {
		t.Fatalf("corrupt trailer: slice %v, reader %v", se, re)
	}
	if got, err := reader(readAtFunc(func([]byte, int64) (int, error) { return 0, injected })); got != nil || !errors.Is(err, injected) {
		t.Fatalf("read failure: %v", err)
	}
	if got, err := reader(nil); got != nil || !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("nil reader: %v", err)
	}
}

func tempCaptureFile(t testing.TB, data []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "capture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileWindow(t *testing.T) {
	raw := make([]byte, 3*fileWindowSize)
	for i := range raw {
		raw[i] = byte(i % 251)
	}
	f := tempCaptureFile(t, raw)
	r := &measuredFile{File: f}
	const extent = 2*fileWindowSize + 9
	w := fileWindow(r, extent, fileWindowSize+7)
	defer w.release()
	check := func(off, length int, wantCalls, wantBytes int64, wantErr error) {
		t.Helper()
		buf := make([]byte, length)
		n, err := w.ReadAt(buf, int64(off))
		if !errors.Is(err, wantErr) || !bytes.Equal(buf[:n], raw[off:min(extent, off+length)]) || r.calls != wantCalls || r.bytesRead != wantBytes {
			t.Fatalf("read at %d length %d: n=%d err=%v, calls=%d bytes=%d", off, length, n, err, r.calls, r.bytesRead)
		}
	}
	check(0, 1, 1, 1, nil)
	check(0, 1, 2, fileWindowSize+1, nil)
	check(100, 3, 2, fileWindowSize+1, nil)
	// Eight speculative bytes remain. Cross the window boundary, then seek back.
	check(fileWindowSize-2, 5, 3, fileWindowSize+12, nil)
	check(fileWindowSize, 11, 3, fileWindowSize+12, nil)
	check(0, 1, 4, fileWindowSize+13, nil)
	check(extent-2, 5, 5, fileWindowSize+15, io.EOF)
}

func TestFileReaderAtParity(t *testing.T) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	noise := buildEthernetIPv4UDPFrame(src, dst, 1234, 5678, make([]byte, 1400))
	frames := make([][]byte, 120)
	for i := range frames {
		frames[i] = noise
	}
	hello := buildTLS13ClientHelloRecord("window.example", "h2")
	dgram := buildEncryptedQUICInitialDatagram(t, QUICVersion1, []byte{1, 2, 3, 4}, nil, nil, 1, 0, hello[5:])
	frames = append(frames, buildEthernetIPv4UDPFrame(src, dst, 1234, 53, buildDNSQueryResponsePacket()), buildEthernetIPv4TCPFrame(src, dst, 1234, 443, 1, 0, TCPFlagACK, hello), buildEthernetIPv4UDPFrame(src, dst, 1234, 443, dgram))
	for _, raw := range [][]byte{buildClassicPCAP(binary.BigEndian, true, LinkTypeEthernet, 65535, frames), buildPCAPNGFixture(binary.LittleEndian, []byte("embedded secret"), frames)} {
		f := tempCaptureFile(t, raw)
		r := &measuredFile{File: f}
		want, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewFromReaderAt(r, int64(len(raw)))
		if err != nil || !reflect.DeepEqual(got, want) || r.calls > 12 {
			t.Fatalf("open: %d reads, %v; metadata equal %t", r.calls, err, reflect.DeepEqual(got, want))
		}
		checkFileScan(t, raw, r, want.Packets, got.PacketsFromReaderAt)
		checkFileScan(t, raw, r, want.Flows, got.FlowsFromReaderAt)
		checkFileScan(t, raw, r, want.DNS, got.DNSFromReaderAt)
		checkFileScan(t, raw, r, want.TLS, got.TLSFromReaderAt)
		checkFileScan(t, raw, r, want.QUIC, got.QUICFromReaderAt)
		r.calls, r.bytesRead = 0, 0
		count := 0
		for pkt, e := range got.PacketSeqFromReaderAt(r) {
			if e != nil || pkt.Index != 0 {
				t.Fatalf("first packet: %v, %v", pkt, e)
			}
			count++
			break
		}
		wantCalls, wantBytes := int64(1), int64(pcapPacketHeaderSize)
		if got.Format == FormatPCAPNG {
			wantCalls, wantBytes = 2, 8+fileWindowSize
		}
		if count != 1 || r.calls != wantCalls || r.bytesRead != wantBytes {
			t.Fatalf("early stop: records=%d calls=%d bytes=%d", count, r.calls, r.bytesRead)
		}
	}
}

func checkFileScan[T any](t *testing.T, raw []byte, r *measuredFile, slice func([]byte) ([]T, error), file func(io.ReaderAt) ([]T, error)) {
	t.Helper()
	r.calls, r.bytesRead = 0, 0
	want, err := slice(raw)
	if err != nil || len(want) == 0 {
		t.Fatalf("slice: %d records, %v", len(want), err)
	}
	got, err := file(r)
	if err != nil || !reflect.DeepEqual(got, want) || r.calls > 12 || r.bytesRead > MaxReaderAtScanBytes {
		t.Fatalf("file: %d records, %v, %d reads, %d bytes", len(got), err, r.calls, r.bytesRead)
	}
}

func TestFilePrefetchPartialRead(t *testing.T) {
	injected := errors.New("file read failed")
	data := []byte("prefix")
	r := descriptorReader{readAtFunc(func(p []byte, off int64) (int, error) {
		if off >= int64(len(data)) {
			return 0, injected
		}
		return copy(p, data[off:]), injected
	})}
	w := fileWindow(r, 100, 100)
	defer w.release()
	var buf [8]byte
	if err := readExactAt(w, buf[:1], 0, 100); err != nil {
		t.Fatal(err)
	}
	if n, err := w.ReadAt(buf[:2], 0); n != 2 || err != nil || !bytes.Equal(buf[:2], data[:2]) {
		t.Fatalf("valid prefix: %d, %v", n, err)
	}
	if n, err := w.ReadAt(buf[:], 2); n != 4 || !errors.Is(err, injected) || !bytes.Equal(buf[:4], data[2:]) {
		t.Fatalf("partial read: %d, %v", n, err)
	}
}

func TestFilePrefetchNearProtocolBudget(t *testing.T) {
	frame := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 1234, 53, buildDNSQueryResponsePacket())
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{frame})
	f := tempCaptureFile(t, raw)
	// An unknown block makes the file sparse. Its body requires no reads.
	// PcapNG has only eleven bytes of speculative allowance at this size.
	const size = 3*MaxReaderAtScanBytes/4 - 8
	blockLen := uint32(size - len(raw))
	header := binary.LittleEndian.AppendUint32(nil, 0x12345678)
	header = binary.LittleEndian.AppendUint32(header, blockLen)
	if _, err := f.Write(header); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(header[4:8], size-4); err != nil {
		t.Fatal(err)
	}
	c, err := NewFromReaderAt(f, size)
	if err != nil {
		t.Fatal(err)
	}
	r := &measuredFile{File: f}
	want, err := c.DNSFromReaderAt(struct{ io.ReaderAt }{r})
	if err != nil || len(want) != 1 {
		t.Fatalf("exact scan: %d records, %v", len(want), err)
	}
	exact := r.bytesRead
	r.calls, r.bytesRead = 0, 0
	got, err := c.DNSFromReaderAt(r)
	if err != nil || !reflect.DeepEqual(got, want) || r.bytesRead > exact+c.scanReadAhead() || r.bytesRead > MaxReaderAtScanBytes {
		t.Fatalf("prefetch: %v, %d exact bytes, %d file bytes, %d spare", err, exact, r.bytesRead, c.scanReadAhead())
	}
}
