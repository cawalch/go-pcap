package pcap

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestPCAPNGTimestampResolution(t *testing.T) {
	for _, tc := range []struct {
		name  string
		resol byte
		ticks uint64
		off   int64
		scale uint64
		want  int64
	}{
		{"decimal-microseconds", 6, 123, 0, 1000, 123_000},
		{"decimal-fine", 10, 10_000_000_019, 0, 0, 1_000_000_001},
		{"decimal-fine-negative", 10, 9_999_999_999, -1, 0, -1},
		{"decimal-28", 28, math.MaxUint64, 0, 0, 1},
		{"decimal-29", 29, math.MaxUint64, 0, 0, 0},
		{"decimal-127", 127, math.MaxUint64, 1, 0, 1_000_000_000},
		{"binary-63", 0x80 + 63, math.MaxUint64, 0, 0, 1_999_999_999},
		{"binary-64", 0x80 + 64, math.MaxUint64, 0, 0, 999_999_999},
		{"binary-93", 0x80 + 93, math.MaxUint64, 0, 0, 1},
		{"binary-94", 0x80 + 94, math.MaxUint64, 0, 0, 0},
		{"binary-127", 0x80 + 127, math.MaxUint64, -1, 0, -1_000_000_000},
		{"wide-cancellation", 0, 1 << 63, math.MinInt64, 1_000_000_000, 0},
		{"wide-binary-cancellation", 0x80 + 1, 1 << 63, -1 << 62, 0, 0},
		{"wide-negative-remainder", 9, math.MaxUint64, -18_446_744_074, 1, -290_448_385},
		{"near-max", 9, 854_775_806, 9_223_372_036, 1, math.MaxInt64 - 1},
		{"near-min", 9, 145_224_193, -9_223_372_037, 1, math.MinInt64 + 1},
		{"saturates-positive", 0, math.MaxUint64, math.MaxInt64, 1_000_000_000, math.MaxInt64},
		{"saturates-negative", 9, 145_224_191, -9_223_372_037, 1, math.MinInt64},
	} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			t.Run(tc.name+"/"+order.String(), func(t *testing.T) {
				base := buildPCAPNGFixture(order, nil, nil)
				shb := base[:order.Uint32(base[4:])]
				var raw, idb, isb bytes.Buffer
				raw.Write(shb)
				idb.Write(make([]byte, 8))
				appendPCAPNGOption(&idb, order, optIDBTsResol, []byte{tc.resol})
				var offset [8]byte
				order.PutUint64(offset[:], uint64(tc.off))
				appendPCAPNGOption(&idb, order, optIDBTsOffset, offset[:])
				appendPCAPNGOption(&idb, order, optEndOfOpt, nil)
				appendPCAPNGBlock(&raw, order, BlockTypeInterfaceDesc, idb.Bytes())

				var ts [8]byte
				order.PutUint32(ts[:4], uint32(tc.ticks>>32))
				order.PutUint32(ts[4:], uint32(tc.ticks))
				var epb [20]byte
				copy(epb[4:12], ts[:])
				appendPCAPNGBlock(&raw, order, BlockTypeEnhancedPacket, epb[:])

				isb.Write(make([]byte, 4))
				isb.Write(ts[:])
				appendPCAPNGOption(&isb, order, optISBStartTime, ts[:])
				appendPCAPNGOption(&isb, order, optISBEndTime, ts[:])
				appendPCAPNGOption(&isb, order, optEndOfOpt, nil)
				appendPCAPNGBlock(&raw, order, BlockTypeInterfaceStats, isb.Bytes())

				c, packets := readWrittenPackets(t, raw.Bytes())
				r := bytes.NewReader(raw.Bytes())
				cr, err := NewFromReaderAt(r, r.Size())
				if err != nil {
					t.Fatal(err)
				}
				checkMetadataWalk(t, raw.Bytes(), r, c.Packets, cr.PacketsFromReaderAt)
				if len(packets) != 1 || packets[0].TimestampNs != tc.want {
					t.Fatalf("packets = %+v, want one timestamp of %d", packets, tc.want)
				}
				for _, capture := range []*Capture{c, cr} {
					want := InterfaceStatistics{
						TimestampNs: tc.want, StartTimeNs: tc.want, EndTimeNs: tc.want,
						HasStartTime: true, HasEndTime: true,
					}
					if len(capture.InterfaceStats) != 1 || capture.InterfaceStats[0] != want {
						t.Fatalf("interface statistics = %+v, want %+v", capture.InterfaceStats, want)
					}
					iface := capture.Interfaces[0]
					if capture.Anomalies().InvalidTimestampResolution ||
						iface.TimestampBinary != (tc.resol&0x80 != 0) ||
						iface.TimestampExponent != tc.resol&0x7f ||
						iface.TimestampOffsetSec != tc.off ||
						(!iface.TimestampBinary && iface.TimestampScaleNs != tc.scale) {
						t.Fatalf("interface = %+v, anomalies = %+v", iface, capture.Anomalies())
					}
				}
			})
		}
	}
}
