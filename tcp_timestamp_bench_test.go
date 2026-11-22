package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func handshakeFrame(port uint16, flags uint8, opts []byte) []byte {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	sport, dport := port, uint16(443)
	if flags&TCPFlagSYN != 0 && flags&TCPFlagACK != 0 {
		src, dst = dst, src
		sport, dport = dport, sport
	}
	frame := buildEthernetIPv4TCPFrame(src, dst, sport, dport, 1, 0, flags, opts)
	frame[46] = byte(5+len(opts)/4) << 4
	return frame
}

// Each scan observes both handshake directions for 128 distinct flows.
func BenchmarkFlowHandshakeTimestamps(b *testing.B) {
	for _, tc := range []struct {
		name string
		opts []byte
	}{
		{"Absent", nil}, {"Present", []byte{1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8}},
	} {
		var frames [][]byte
		for i := range 128 {
			for _, flags := range []uint8{TCPFlagSYN, TCPFlagSYN | TCPFlagACK} {
				frames = append(frames, handshakeFrame(uint16(12000+i), flags, tc.opts))
			}
		}
		data := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		r := bytes.NewReader(data)
		c, err := New(data)
		if err != nil {
			b.Fatal(err)
		}
		rc, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			b.Fatal(err)
		}
		for _, path := range []string{"Slice", "ReaderAt"} {
			b.Run(tc.name+"/"+path, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var flows []FlowSummary
					var err error
					if path == "Slice" {
						flows, err = c.Flows(data)
					} else {
						flows, err = rc.FlowsFromReaderAt(r)
					}
					if err != nil || len(flows) != 128 {
						b.Fatalf("%d flows, %v", len(flows), err)
					}
				}
			})
		}
	}
}
