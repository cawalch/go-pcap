package pcap_test

import (
	"fmt"
	"net/netip"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleDecodeFrame_esp() {
	data := []byte{
		0x45, 0, 0, 32, 0, 0, 0, 0, 64, pcap.IPProtoESP, 0, 0,
		192, 0, 2, 1, 198, 51, 100, 2,
		0x10, 0x20, 0x30, 0x40, 0, 0, 0, 7, // SPI and sequence number.
		0xde, 0xad, 0xbe, 0xef, // Opaque bytes.
	}
	frame, err := pcap.DecodeFrame(data, pcap.LinkTypeIPv4)
	if err != nil {
		panic(err)
	}
	for _, layer := range frame.LayerSlices() {
		if layer.Proto == pcap.LayerESP {
			fmt.Printf("%s header at byte %d, %d opaque bytes\n", layer.Proto, layer.Offset, frame.PayloadLength)
		}
	}
	// Output:
	// esp header at byte 20, 4 opaque bytes
}

func ExampleVerifyUDPChecksum() {
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("198.51.100.2")
	datagram := []byte{0x30, 0x39, 0x27, 0x0f, 0, 13, 0x78, 0x82, 'h', 'e', 'l', 'l', 'o'}
	valid, likelyOffload := pcap.VerifyUDPChecksum(src, dst, datagram)
	fmt.Println(valid, likelyOffload)
	// Output:
	// true false
}

func ExampleClassifyL7() {
	payload := []byte("GET /health HTTP/1.1\r\nHost: service.example\r\n\r\n")
	if pcap.ClassifyL7(payload, pcap.IPProtoTCP, 50321, 8081) == pcap.L7HTTP1 {
		fmt.Println("HTTP/1 candidate")
	}
	// Output:
	// HTTP/1 candidate
}
