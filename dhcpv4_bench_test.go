package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func BenchmarkDHCPv4MostlyUnrelated(b *testing.B) {
	background := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 10000, 10001, make([]byte, 1400))
	msg := make([]byte, 240)
	msg[0], msg[1], msg[2] = 2, 1, 6
	binary.BigEndian.PutUint32(msg[236:], 0x63825363)
	msg = append(msg, 53, 1, 5, 255)
	ack := buildEthernetIPv4UDPFrame([4]byte{10, 0, 0, 2}, [4]byte{255, 255, 255, 255}, 67, 68, msg)
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i] = background
		if i%128 == 0 {
			frames[i] = ack
		}
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	for _, op := range []string{"flows", "dhcp"} {
		b.Run(op, func(b *testing.B) {
			r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
			b.ReportAllocs()
			for b.Loop() {
				if op == "flows" {
					_, err = c.FlowsFromReaderAt(r)
				} else {
					_, err = c.DHCPv4FromReaderAt(r)
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
