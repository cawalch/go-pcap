package pcap_test

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cawalch/go-pcap"
)

func ExampleNew() {
	// Build a minimal classic PCAP buffer containing one Ethernet/IPv4/UDP packet.
	buf := make([]byte, 24+16+14+20+8+4)
	binary.LittleEndian.PutUint32(buf[0:4], pcap.PCAPMagicMicroLE)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 65535)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(pcap.LinkTypeEthernet))

	pktLen := uint32(14 + 20 + 8 + 4)
	binary.LittleEndian.PutUint32(buf[24:28], 1700000000)
	binary.LittleEndian.PutUint32(buf[32:36], pktLen)
	binary.LittleEndian.PutUint32(buf[36:40], pktLen)

	frame := buf[40:]
	binary.BigEndian.PutUint16(frame[12:14], pcap.EtherTypeIPv4)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20+8+4)
	ip[8] = 64
	ip[9] = pcap.IPProtoUDP
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 51, 100, 53})

	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 55000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(frame[42:], []byte("ping"))

	capture, err := pcap.New(buf)
	if err != nil {
		log.Fatal(err)
	}
	flows, err := capture.Flows(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("format=%s packets=%d flow=%s:%d->%s:%d bytes=%d\n",
		capture.Format, capture.PacketCount,
		flows[0].SrcAddr, flows[0].SrcPort,
		flows[0].DstAddr, flows[0].DstPort,
		flows[0].ClientBytes)
	// Output:
	// format=pcap packets=1 flow=192.0.2.10:55000->198.51.100.53:53 bytes=4
}
