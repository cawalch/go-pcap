package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"iter"
	"math"
	"testing"
)

func legacyPacketBody(order binary.ByteOrder, iface, drops uint16, ticks uint64, payload []byte) []byte {
	body := make([]byte, 20+((len(payload)+3)&^3))
	order.PutUint16(body[0:2], iface)
	order.PutUint16(body[2:4], drops)
	order.PutUint32(body[4:8], uint32(ticks>>32))
	order.PutUint32(body[8:12], uint32(ticks))
	order.PutUint32(body[12:16], uint32(len(payload)))
	order.PutUint32(body[16:20], uint32(len(payload)))
	copy(body[20:], payload)
	return body
}

func TestPCAPNGLegacyPacketBlocks(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	other := buildEthernetIPv4UDPFrame(a, b, 40000, 443, nil)
	target := buildEthernetIPv4UDPFrame(a, b, 40001, 443, []byte{1})[14:]

	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		t.Run(order.String(), func(t *testing.T) {
			first := buildPCAPNGFixture(binary.LittleEndian, nil, [][]byte{nil})
			second := bytes.NewBuffer(buildPCAPNGFixture(order, nil, [][]byte{other}))
			var idb [8]byte
			order.PutUint16(idb[:2], uint16(LinkTypeRaw))
			order.PutUint32(idb[4:], 65535)
			appendPCAPNGBlock(second, order, BlockTypeInterfaceDesc, idb[:])

			var flags [4]byte
			order.PutUint32(flags[:], 2)
			pb := bytes.NewBuffer(legacyPacketBody(order, 1, 7, 1<<32+12, target))
			appendPCAPNGOption(pb, order, optEPBFlags, flags[:])
			appendPCAPNGOption(pb, order, optEPBDropCount, []byte("retained"))
			appendPCAPNGOption(pb, order, optComment, []byte("go-pcap:thread-id=17"))
			// Exercise ReaderAt's large-option path while keeping each option bounded.
			for range 2 {
				appendPCAPNGOption(pb, order, 1000, make([]byte, MaxOptionStringBytes))
			}
			appendPCAPNGOption(pb, order, optEndOfOpt, nil)
			appendPCAPNGBlock(second, order, blockTypeLegacyPacket, pb.Bytes())

			var spb [4]byte
			order.PutUint32(spb[:], uint32(len(other)))
			appendPCAPNGBlock(second, order, BlockTypeSimplePacket, append(spb[:], other...))
			epb := legacyPacketBody(order, 1, 0, 12, target)
			order.PutUint32(epb[:4], 1) // EPB uses a 32-bit interface ID.
			appendPCAPNGBlock(second, order, BlockTypeEnhancedPacket, epb)
			appendPCAPNGBlock(second, order, blockTypeLegacyPacket, legacyPacketBody(order, 1, math.MaxUint16, 13, target))

			raw := append(first, second.Bytes()...)
			c, packets := readWrittenPackets(t, raw)
			r := bytes.NewReader(raw)
			cr, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			if c.PacketCount != 6 || cr.PacketCount != 6 || len(packets) != 6 {
				t.Fatalf("packet counts = %d (slice), %d (ReaderAt), %d (collected)", c.PacketCount, cr.PacketCount, len(packets))
			}
			checkMetadataWalk(t, raw, r, c.Packets, cr.PacketsFromReaderAt)
			for i, pkt := range packets {
				if pkt.Index != i {
					t.Fatalf("packet %d: index = %d", i, pkt.Index)
				}
			}
			for _, seq := range []iter.Seq2[PacketRecord, error]{c.PacketSeq(raw), cr.PacketSeqFromReaderAt(r)} {
				i := 0
				for pkt, err := range seq {
					if err != nil || i >= len(packets) || pkt != packets[i] {
						t.Fatalf("packet iteration at index %d = %+v, %v", i, pkt, err)
					}
					i++
				}
				if i != len(packets) {
					t.Fatalf("iterator returned %d packets, want %d", i, len(packets))
				}
			}
			pkt := packets[2]
			if pkt.InterfaceID != 2 || pkt.LinkType != LinkTypeRaw || pkt.TimestampNs != (1<<32+12)*1000 ||
				pkt.Flags != 2 || pkt.DropCount != 7 || pkt.HasThreadID ||
				pkt.CaptureLen != uint32(len(target)) || pkt.OriginalLen != uint32(len(target)) {
				t.Fatalf("legacy packet = %+v", pkt)
			}
			if packets[5].DropCount != 0 {
				t.Fatalf("unavailable drop count = %d", packets[5].DropCount)
			}
			for _, capture := range []*Capture{c, cr} {
				if capture.Anomalies().Any() {
					t.Fatalf("anomalies = %+v", capture.Anomalies())
				}
			}
			payload, err := cr.PacketPayloadFromReaderAt(r, pkt)
			if err != nil || !bytes.Equal(payload, target) {
				t.Fatalf("legacy payload = %x, %v, want %x", payload, err, target)
			}

			var out, fileOut bytes.Buffer
			if err := c.ExtractFlowPCAPNG(raw, &out, 1); err != nil {
				t.Fatal(err)
			}
			if err := cr.ExtractFlowPCAPNGFromReaderAt(r, &fileOut, 1); err != nil || !bytes.Equal(out.Bytes(), fileOut.Bytes()) {
				t.Fatalf("export parity: %v", err)
			}
			exported, exportedPackets := readWrittenPackets(t, out.Bytes())
			if len(exported.Interfaces) != 1 || len(exportedPackets) != 3 {
				t.Fatalf("exported %d interfaces and %d packets", len(exported.Interfaces), len(exportedPackets))
			}
			for i, index := range []int{2, 4, 5} {
				got := exportedPackets[i]
				want := packets[index]
				want.Index, want.InterfaceID, want.PayloadOffset = i, 0, got.PayloadOffset
				if got != want {
					t.Fatalf("exported packet %d = %+v, want %+v", i, got, want)
				}
			}
			// Check the rewritten interface ID and preservation of the rest of the block.
			order.PutUint16(pb.Bytes()[:2], 0)
			if !bytes.Contains(out.Bytes(), pb.Bytes()) {
				t.Fatal("export dropped or changed legacy packet options")
			}
		})
	}
}

func TestPCAPNGLegacyPacketBlockBounds(t *testing.T) {
	order := binary.LittleEndian
	base := buildPCAPNGFixture(order, nil, nil)
	valid := legacyPacketBody(order, 0, 0, 0, []byte{1, 2, 3})
	for _, tc := range []struct {
		name    string
		edit    func([]byte) []byte
		trailer bool
		want    error
	}{
		{"short-header", func(p []byte) []byte { return p[:16] }, false, ErrInvalidBlock},
		{"unknown-interface", func(p []byte) []byte { order.PutUint16(p[:2], 1); return p }, false, ErrInvalidPacket},
		{"oversized-capture", func(p []byte) []byte { order.PutUint32(p[12:16], MaxSnapLen+1); return p }, false, ErrInvalidPacket},
		{"missing-payload", func(p []byte) []byte { return p[:20] }, false, ErrInvalidBlock},
		{"missing-option-value", func(p []byte) []byte { return append(p, 2, 0, 4, 0) }, false, ErrInvalidBlock},
		{"too-many-options", func(p []byte) []byte {
			for range MaxOptionsPerBlock + 1 {
				p = append(p, 2, 0, 0, 0)
			}
			return p
		}, false, ErrOptionLimit},
		{"mismatched-trailer", func(p []byte) []byte { return p }, true, ErrInvalidBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.NewBuffer(bytes.Clone(base))
			appendPCAPNGBlock(raw, order, blockTypeLegacyPacket, tc.edit(bytes.Clone(valid)))
			if tc.trailer {
				raw.Bytes()[raw.Len()-1] ^= 1
			}
			if _, err := New(raw.Bytes()); !errors.Is(err, tc.want) {
				t.Fatalf("slice open = %v, want %v", err, tc.want)
			}
			if _, err := NewFromReaderAt(bytes.NewReader(raw.Bytes()), int64(raw.Len())); !errors.Is(err, tc.want) {
				t.Fatalf("ReaderAt open = %v, want %v", err, tc.want)
			}
		})
	}
}
