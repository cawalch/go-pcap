package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

func TestExtractFlowPacketsPCAPNG(t *testing.T) {
	le, be := binary.LittleEndian, binary.BigEndian
	a, b := [4]byte{192, 0, 2, 7}, [4]byte{192, 0, 2, 8}
	other := buildEthernetIPv4UDPFrame(a, b, 40001, 53, []byte("unrelated-packet-marker"))
	request := buildEthernetIPv4UDPFrame(a, b, 40000, 53, []byte("original-application-bytes!"))
	reply := buildEthernetIPv4UDPFrame(b, a, 53, 40000, []byte("reply"))[14:]
	var raw, expected bytes.Buffer
	base := buildPCAPNGFixture(be, nil, [][]byte{other}) // An entire unused section.
	raw.Write(base)
	w, err := NewPCAPNGWriter(&raw, PCAPNGWriterOptions{Hardware: "hardware-marker", OS: "section-os-marker", UserApplication: "app-marker", InterfaceName: "unused-if-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, []byte("decryption-marker")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteNameResolution([]NameResolutionRecord{{Addr: netip.AddrFrom4(a), Names: []string{"hostname-marker"}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteInterfaceStats(InterfaceStatistics{InterfaceID: 0, HasPacketsDropped: true, PacketsDropped: 23}); err != nil {
		t.Fatal(err)
	}
	process := le.AppendUint32(nil, 1337)
	var processBody bytes.Buffer
	processBody.Write(process)
	appendPCAPNGOption(&processBody, le, optDPEBProcessName, []byte("process-name-marker"))
	appendPCAPNGBlock(&raw, le, BlockTypeDarwinProcessEvent, processBody.Bytes())
	appendPCAPNGBlock(&raw, le, 0x40000bad, []byte("unknown-block-marker"))

	var shb [16]byte
	le.PutUint32(shb[:4], PCAPNGByteOrderMagic)
	le.PutUint16(shb[4:6], 1)
	le.PutUint64(shb[8:], ^uint64(0))
	appendPCAPNGBlock(&expected, le, BlockTypeSectionHeader, shb[:])
	var idb [8]byte
	le.PutUint16(idb[:2], uint16(LinkTypeEthernet))
	le.PutUint32(idb[4:], 65535)
	var iface bytes.Buffer
	iface.Write(idb[:])
	appendPCAPNGOption(&iface, le, optIDBTsResol, []byte{0x80 | 12})
	offsetSec := int64(-2)
	appendPCAPNGOption(&iface, le, optIDBTsOffset, le.AppendUint64(nil, uint64(offsetSec)))
	appendPCAPNGOption(&iface, le, optIDBFCSLen, []byte{32})
	appendPCAPNGOption(&iface, le, optEndOfOpt, nil)
	appendPCAPNGBlock(&expected, le, BlockTypeInterfaceDesc, iface.Bytes())
	iface.Truncate(iface.Len() - 4)
	copy(iface.Bytes()[2:4], "RV")    // Nonzero reserved interface bytes.
	copy(iface.Bytes()[13:16], "PAD") // Nonzero option padding.
	appendPCAPNGOption(&iface, le, optIDBName, []byte("interface-marker"))
	appendPCAPNGOption(&iface, le, optIDBDescription, []byte("description-marker"))
	appendPCAPNGOption(&iface, le, optIDBOS, []byte("interface-os-marker"))
	appendPCAPNGOption(&iface, le, optComment, []byte("interface-comment-marker"))
	appendPCAPNGOption(&iface, le, 2468, []byte("unknown-interface-option"))
	appendPCAPNGOption(&iface, le, optEndOfOpt, nil)
	iface.WriteString("after-interface-end-marker")
	appendPCAPNGBlock(&raw, le, BlockTypeInterfaceDesc, iface.Bytes())

	const fcsFlags = 4 << 5
	pb := legacyPacketBody(le, 0, 0xffff, 1234, request)
	le.PutUint32(pb[16:], uint32(len(request)+23))
	var packet bytes.Buffer
	packet.Write(pb)
	appendPCAPNGOption(&packet, le, optEPBFlags, le.AppendUint32(nil, fcsFlags))
	appendPCAPNGOption(&packet, le, optEndOfOpt, nil)
	appendPCAPNGBlock(&expected, le, blockTypeLegacyPacket, packet.Bytes())
	packet.Reset()
	le.PutUint16(pb[:2], 1)
	le.PutUint16(pb[2:4], 701)
	for i := 20 + len(request); i < len(pb); i++ {
		pb[i] = 0xe7
	}
	packet.Write(pb)
	appendPCAPNGOption(&packet, le, optEPBFlags, le.AppendUint32(nil, fcsFlags|0x8002_0001))
	appendPCAPNGOption(&packet, le, optComment, []byte("legacy-packet-comment-marker"))
	appendPCAPNGOption(&packet, le, optEndOfOpt, nil)
	appendPCAPNGBlock(&raw, le, blockTypeLegacyPacket, packet.Bytes())

	packet.Reset()
	ep := legacyPacketBody(le, 0, 0, 42, request)
	packet.Write(ep)
	appendPCAPNGBlock(&expected, le, BlockTypeEnhancedPacket, packet.Bytes())
	packet.Reset()
	le.PutUint32(ep[:4], 1)
	packet.Write(ep)
	appendPCAPNGOption(&packet, le, optComment, []byte("go-pcap:process-args=command-marker"))
	appendPCAPNGOption(&packet, le, optEPBDarwinProcessIndex, le.AppendUint32(nil, 0))
	appendPCAPNGOption(&packet, le, optEPBDropCount, le.AppendUint64(nil, 44332211))
	for range 2 { // Exercise the bounded large-options path.
		appendPCAPNGOption(&packet, le, 12345, bytes.Repeat([]byte{'Z'}, MaxOptionStringBytes))
	}
	appendPCAPNGOption(&packet, le, optEndOfOpt, nil)
	packet.WriteString("after-packet-end-marker")
	appendPCAPNGBlock(&raw, le, BlockTypeEnhancedPacket, packet.Bytes())

	be.PutUint32(shb[:4], PCAPNGByteOrderMagic)
	be.PutUint16(shb[4:6], 1)
	appendPCAPNGBlock(&expected, be, BlockTypeSectionHeader, shb[:])
	be.PutUint64(shb[8:], 64)
	var section bytes.Buffer
	section.Write(shb[:])
	appendPCAPNGOption(&section, be, optComment, []byte("section-comment-marker"))
	appendPCAPNGBlock(&raw, be, BlockTypeSectionHeader, section.Bytes())
	be.PutUint16(idb[:2], uint16(LinkTypeRaw))
	be.PutUint32(idb[4:], uint32(len(reply)))
	for _, buf := range []*bytes.Buffer{&raw, &expected} {
		appendPCAPNGBlock(buf, be, BlockTypeInterfaceDesc, idb[:])
	}
	spb := append(be.AppendUint32(nil, uint32(len(reply)+40)), reply...)
	appendPCAPNGBlock(&expected, be, BlockTypeSimplePacket, spb)
	appendPCAPNGBlock(&raw, be, BlockTypeSimplePacket, append(spb, []byte("after-spb-payload-marker")...))

	c, sourcePackets := readWrittenPackets(t, raw.Bytes())
	r := bytes.NewReader(raw.Bytes())
	file, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	var slice, reader bytes.Buffer
	if err := c.ExtractFlowPacketsPCAPNG(raw.Bytes(), &slice, 1); err != nil {
		t.Fatal(err)
	}
	if err := file.ExtractFlowPacketsPCAPNGFromReaderAt(r, &reader, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slice.Bytes(), expected.Bytes()) || !bytes.Equal(reader.Bytes(), expected.Bytes()) {
		t.Fatalf("packet-only bytes\nslice  %x\nfile   %x\nwanted %x", slice.Bytes(), reader.Bytes(), expected.Bytes())
	}
	output, selected := readWrittenPackets(t, slice.Bytes())
	if len(selected) != 3 || len(output.Interfaces) != 2 || len(output.NameRecords)+len(output.Processes)+len(output.Secrets)+len(output.InterfaceStats) != 0 {
		t.Fatalf("output capture = %+v, packets = %+v", output, selected)
	}
	for i, want := range sourcePackets[1:] {
		got := selected[i]
		if got.TimestampNs != want.TimestampNs || got.CaptureLen != want.CaptureLen || got.OriginalLen != want.OriginalLen || got.LinkType != want.LinkType {
			t.Fatalf("packet %d = %+v, source = %+v", i, got, want)
		}
		src, _ := c.PacketPayload(raw.Bytes(), want)
		dst, _ := output.PacketPayload(slice.Bytes(), got)
		if !bytes.Equal(src, dst) || got.HasProcessID || got.ProcessName != "" || got.ProcessArgs != "" || got.DropCount != 0 {
			t.Fatalf("packet %d payload or metadata = %x %+v", i, dst, got)
		}
	}
	if selected[0].Flags != fcsFlags || selected[1].Flags != 0 || selected[2].TimestampNs != 0 {
		t.Fatal(selected)
	}
	var missing bytes.Buffer
	if err := c.ExtractFlowPacketsPCAPNG(raw.Bytes(), &missing, 2); !errors.Is(err, ErrOutOfBounds) || missing.Len() != 0 {
		t.Fatalf("missing slice flow: %v, wrote %d", err, missing.Len())
	}
	if err := file.ExtractFlowPacketsPCAPNGFromReaderAt(r, &missing, 2); !errors.Is(err, ErrOutOfBounds) || missing.Len() != 0 {
		t.Fatalf("missing file flow: %v, wrote %d", err, missing.Len())
	}
}

func TestExtractFlowPacketsClassicLengths(t *testing.T) {
	order := binary.BigEndian
	packet := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 123, 53, []byte{1, 2, 3, 4})
	raw := buildClassicPCAP(order, false, LinkTypeEthernet, 1, [][]byte{packet})
	order.PutUint32(raw[20:], uint32(LinkTypeEthernet)|1<<26|2<<28)
	order.PutUint32(raw[36:], 0)
	c, src := readWrittenPackets(t, raw)
	var out, fromFile bytes.Buffer
	if err := c.ExtractFlowPacketsPCAPNG(raw, &out, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.ExtractFlowPacketsPCAPNGFromReaderAt(bytes.NewReader(raw), &fromFile, 0); err != nil || !bytes.Equal(out.Bytes(), fromFile.Bytes()) {
		t.Fatalf("classic parity: %v", err)
	}
	got, selected := readWrittenPackets(t, out.Bytes())
	if !got.BigEndian || got.SnapLen != 1 || len(selected) != 1 {
		t.Fatal(got, selected)
	}
	want := src[0]
	want.PayloadOffset = selected[0].PayloadOffset
	if selected[0] != want {
		t.Fatalf("packet = %+v, want %+v", selected[0], want)
	}
	payload, err := got.PacketPayload(out.Bytes(), selected[0])
	if err != nil || !bytes.Equal(payload, packet) {
		t.Fatalf("payload = %x, %v", payload, err)
	}
	start := pcapngSHBMinSize + 16
	if fcs := out.Bytes()[start : start+8]; !bytes.Equal(fcs, []byte{0, 13, 0, 1, 32, 0, 0, 0}) {
		t.Fatalf("converted FCS option = %x", fcs)
	}
}

func TestFilePacketOnlyExportBudget(t *testing.T) {
	order := binary.LittleEndian
	frame := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 123, 53, nil)
	header := buildPCAPNGFixture(order, nil, nil)
	f := tempCaptureFile(t, header)
	const packetSize = 1 << 20
	const blockSize = packetSize + pcapngPacketBlockMinSize
	var block [28]byte
	order.PutUint32(block[:4], BlockTypeEnhancedPacket)
	order.PutUint32(block[4:8], blockSize)
	order.PutUint32(block[20:24], packetSize)
	order.PutUint32(block[24:28], packetSize)
	prefix := append(block[:], frame...)
	trailer := order.AppendUint32(nil, blockSize)
	size := int64(len(header))
	for range MaxReaderAtScanBytes / packetSize {
		if _, err := f.WriteAt(prefix, size); err != nil {
			t.Fatal(err)
		}
		size += blockSize
		if _, err := f.WriteAt(trailer, size-4); err != nil {
			t.Fatal(err)
		}
	}
	r := &measuredFile{File: f}
	c, err := NewFromReaderAt(r, size)
	if err != nil {
		t.Fatal(err)
	}
	r.bytesRead = 0
	if err := c.ExtractFlowPacketsPCAPNGFromReaderAt(r, io.Discard, 0); !errors.Is(err, ErrPacketLimit) || r.bytesRead > MaxReaderAtScanBytes || r.bytesRead < MaxReaderAtScanBytes-32<<10 {
		t.Fatalf("budget: %v, read %d", err, r.bytesRead)
	}
}
