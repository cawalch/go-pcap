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
	if err := rc.ExtractFlowPCAPNG(raw, &again, 1); err != nil || !bytes.Equal(result.Bytes(), again.Bytes()) {
		t.Fatalf("source reader parity: %v", err)
	}
	got, pkts := readWrittenPackets(t, result.Bytes())
	if len(pkts) != 2 || len(got.Interfaces) != 2 || len(got.Secrets) != 2 || !reflect.DeepEqual(got.NameRecords, c.NameRecords) {
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
	}
	if err := c.ExtractFlowPCAPNG(raw, &incompleteCaptureWrite{failAt: 2}, 1); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
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
	got, p := readWrittenPackets(t, out.Bytes())
	if got.Format != FormatPCAPNG || got.LinkType != LinkTypeNull || got.SnapLen != 0 || len(p) != 1 || p[0].TimestampNs != src[1].TimestampNs {
		t.Fatal(got, p)
	}
}
