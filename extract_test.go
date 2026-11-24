package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
)

func TestExtractFlowPCAPNG(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	request := buildEthernetIPv4TCPFrame(a, b, 40000, 443, 1, 0, TCPFlagSYN, nil)
	reply := buildEthernetIPv4TCPFrame(b, a, 443, 40000, 10, 2, TCPFlagSYN|TCPFlagACK, nil)
	other := buildEthernetIPv4UDPFrame(a, b, 40000, 443, nil)
	var input bytes.Buffer
	w, err := NewPCAPNGWriter(&input, PCAPNGWriterOptions{InterfaceName: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := w.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeEthernet, InterfaceName: "eth1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WritePacket(PacketRecord{InterfaceID: 0}, other); err != nil {
		t.Fatal(err)
	}
	if err = w.WritePacket(PacketRecord{InterfaceID: id, TimestampNs: 123456789, ProcessName: "sample", HasUserID: true, UserID: 7, OriginalLen: 99}, request); err != nil {
		t.Fatal(err)
	}
	// Insert an unrecognized option before the selected EPB's option terminator.
	epbLength := int(binary.LittleEndian.Uint32(input.Bytes()[input.Len()-4:]))
	epbStart := input.Len() - epbLength
	input.Truncate(input.Len() - 8)
	appendPCAPNGOption(&input, binary.LittleEndian, 21111, []byte("retained-option"))
	appendPCAPNGOption(&input, binary.LittleEndian, optEndOfOpt, nil)
	length := uint32(input.Len() - epbStart + 4)
	binary.LittleEndian.PutUint32(input.Bytes()[epbStart+4:], length)
	input.Write(binary.LittleEndian.AppendUint32(nil, length))
	if err = w.WriteNameResolution([]NameResolutionRecord{{Addr: netip.AddrFrom4(a), Names: []string{"one", "two"}}}); err != nil {
		t.Fatal(err)
	}
	if err = w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, []byte("fixture")); err != nil {
		t.Fatal(err)
	}

	// Another section reuses interface 0, in the opposite byte order. Its
	// selected SPB implicitly uses that interface and has no timestamp.
	second := buildPCAPNGFixture(binary.BigEndian, []byte("second"), [][]byte{other})
	var buf bytes.Buffer
	buf.Write(second)
	appendPCAPNGBlock(&buf, binary.BigEndian, BlockTypeSimplePacket, append(binary.BigEndian.AppendUint32(nil, uint32(len(reply))), reply...))
	second = buf.Bytes()
	binary.BigEndian.PutUint64(second[16:], uint64(len(second))-uint64(binary.BigEndian.Uint32(second[4:])))
	input.Write(second)
	raw := input.Bytes()
	c, src := readWrittenPackets(t, raw)
	r := bytes.NewReader(raw)
	rc, err := NewFromReaderAt(r, r.Size())
	if err != nil {
		t.Fatal(err)
	}
	checkReaderParity(t, raw, c.Flows, rc.FlowsFromReaderAt)
	var result, again bytes.Buffer
	if err := c.ExtractFlowPCAPNG(raw, &result, 1); err != nil {
		t.Fatal(err)
	}
	if err := rc.ExtractFlowPCAPNGFromReaderAt(r, &again, 1); err != nil || !bytes.Equal(result.Bytes(), again.Bytes()) || !bytes.Contains(again.Bytes(), []byte("retained-option")) {
		t.Fatalf("source reader parity: %v", err)
	}
	got, pkts := readWrittenPackets(t, result.Bytes())
	if len(pkts) != 2 || len(got.Interfaces) != 2 || len(got.Secrets) != 2 ||
		!reflect.DeepEqual(got.NameRecords, c.NameRecords) || !reflect.DeepEqual(got.Processes, c.Processes) {
		t.Fatal(got)
	}
	for i, n := range []int{1, 3} {
		want := src[n]
		iface := c.Interfaces[want.InterfaceID]
		iface.ID = uint32(i)
		if iface != got.Interfaces[i] {
			t.Fatal(iface, got.Interfaces[i])
		}
		want.Index, want.PayloadOffset, want.InterfaceID = i, pkts[i].PayloadOffset, uint32(i)
		if want != pkts[i] {
			t.Fatal(want, pkts[i])
		}
		in, _ := c.PacketPayload(raw, src[n])
		out, _ := got.PacketPayload(result.Bytes(), pkts[i])
		if !bytes.Equal(in, out) || got.Secrets[i].SecretsType != c.Secrets[i].SecretsType || !bytes.Equal(got.Secrets[i].Data, c.Secrets[i].Data) {
			t.Fatal("content mismatch", i)
		}
	}
	for _, n := range []int{-1, 2, MaxFlows} {
		var out bytes.Buffer
		if err := c.ExtractFlowPCAPNG(raw, &out, n); !errors.Is(err, ErrOutOfBounds) || out.Len() != 0 {
			t.Fatal(n, err, out.Len())
		}
		if err := rc.ExtractFlowPCAPNGFromReaderAt(r, &out, n); !errors.Is(err, ErrOutOfBounds) || out.Len() != 0 {
			t.Fatal(n, err, out.Len())
		}
	}
	if err := c.ExtractFlowPCAPNG(raw, &incompleteCaptureWrite{failAt: 2}, 1); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := rc.ExtractFlowPCAPNGFromReaderAt(r, &incompleteCaptureWrite{failAt: 2}, 1); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	injected := errors.New("source read failed")
	bad := readAtFunc(func([]byte, int64) (int, error) { return 0, injected })
	if err := rc.ExtractFlowPCAPNGFromReaderAt(bad, io.Discard, 1); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	// Fail while copying the retained EPB, after the remapped header was written.
	late := readAtFunc(func(p []byte, off int64) (int, error) {
		if off == int64(epbStart+12) {
			return 0, injected
		}
		return r.ReadAt(p, off)
	})
	var partial bytes.Buffer
	if err := rc.ExtractFlowPCAPNGFromReaderAt(late, &partial, 1); !errors.Is(err, injected) || partial.Len() == 0 {
		t.Fatalf("late source failure: %v, wrote %d bytes", err, partial.Len())
	}
}

func TestExtractClassicFlow(t *testing.T) {
	frame := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 50001, 53, nil)
	// LINKTYPE_NULL uses a four-byte host-order address family. Snaplen zero
	// must survive conversion without taking the public writer defaults.
	null := append([]byte{2, 0, 0, 0}, frame[14:]...)
	raw := buildClassicPCAP(binary.BigEndian, false, LinkTypeNull, 0, [][]byte{nil, null})
	c, src := readWrittenPackets(t, raw)
	var out bytes.Buffer
	if err := c.ExtractFlowPCAPNG(raw, &out, 0); err != nil {
		t.Fatal(err)
	}
	var fromFile bytes.Buffer
	if err := c.ExtractFlowPCAPNGFromReaderAt(bytes.NewReader(raw), &fromFile, 0); err != nil || !bytes.Equal(out.Bytes(), fromFile.Bytes()) {
		t.Fatalf("classic export parity: %v", err)
	}
	got, p := readWrittenPackets(t, out.Bytes())
	if got.Format != FormatPCAPNG || got.LinkType != LinkTypeNull || got.SnapLen != 0 || len(p) != 1 || p[0].TimestampNs != src[1].TimestampNs {
		t.Fatal(got, p)
	}
}

func sparseExportFixture() []byte {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	large := buildEthernetIPv4UDPFrame(a, b, 12345, 9999, make([]byte, 60<<10))
	frames := make([][]byte, 129)
	for i := range frames {
		frames[i] = large
	}
	frames[64] = buildEthernetIPv4UDPFrame(a, b, 12345, 53, nil)
	return buildPCAPNGFixture(binary.LittleEndian, nil, frames)
}

func TestFileFlowExportReads(t *testing.T) {
	raw := sparseExportFixture()
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	c, err := NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var want, got bytes.Buffer
	if err := c.ExtractFlowPCAPNG(raw, &want, 1); err != nil {
		t.Fatal(err)
	}
	r.calls, r.bytesRead = 0, 0
	if err := c.ExtractFlowPCAPNGFromReaderAt(r, &got, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) || r.bytesRead > 64<<10 {
		t.Fatalf("read %d bytes in %d calls, output equal %v", r.bytesRead, r.calls, bytes.Equal(want.Bytes(), got.Bytes()))
	}
}

func TestFileFlowExportLargeSelectedPacket(t *testing.T) {
	payload := make([]byte, 60<<10)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	frame := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 123, 53, payload)
	frames := [][]byte{frame}
	for _, raw := range [][]byte{
		buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, frames),
		buildPCAPNGFixture(binary.BigEndian, nil, frames),
	} {
		r := bytes.NewReader(raw)
		c, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			t.Fatal(err)
		}
		var want, got bytes.Buffer
		if err := c.ExtractFlowPCAPNG(raw, &want, 0); err != nil {
			t.Fatal(err)
		}
		if err := c.ExtractFlowPCAPNGFromReaderAt(r, &got, 0); err != nil || !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("%s large packet parity: %v", c.Format, err)
		}
	}
}

func TestFileFlowExportBudget(t *testing.T) {
	frame := buildEthernetIPv4UDPFrame([4]byte{1}, [4]byte{2}, 123, 53, nil)
	raw := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{frame})
	f := tempCaptureFile(t, raw)
	// A valid section with a large sparse padding region after its end option.
	const length = MaxReaderAtScanBytes
	shb := bytes.Clone(raw[:binary.LittleEndian.Uint32(raw[4:])-4])
	binary.LittleEndian.PutUint32(shb[4:], length)
	if _, err := f.Write(shb); err != nil {
		t.Fatal(err)
	}
	size := int64(len(raw)) + length
	if _, err := f.WriteAt(binary.LittleEndian.AppendUint32(nil, length), size-4); err != nil {
		t.Fatal(err)
	}
	r := &measuredFile{File: f}
	c, err := NewFromReaderAt(r, size)
	if err != nil {
		t.Fatal(err)
	}
	r.bytesRead = 0
	if err := c.ExtractFlowPCAPNGFromReaderAt(r, io.Discard, 0); !errors.Is(err, ErrPacketLimit) || r.bytesRead > MaxReaderAtScanBytes {
		t.Fatalf("budget: %v, read %d", err, r.bytesRead)
	}
}

func BenchmarkFileFlowExport(b *testing.B) {
	raw := sparseExportFixture()
	f := tempCaptureFile(b, raw)
	size := int64(len(raw))
	c, err := NewFromReaderAt(f, size)
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"materialize", "reader-at"} {
		b.Run(mode, func(b *testing.B) {
			r := &measuredFile{File: f}
			b.ReportAllocs()
			for b.Loop() {
				if mode == "materialize" {
					data := make([]byte, size)
					if _, err = r.ReadAt(data, 0); err == nil {
						err = c.ExtractFlowPCAPNG(data, io.Discard, 1)
					}
				} else {
					err = c.ExtractFlowPCAPNGFromReaderAt(r, io.Discard, 1)
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
