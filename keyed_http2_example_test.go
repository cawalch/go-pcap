package pcap_test

import (
	"fmt"
	"log"
	"os"

	"github.com/cawalch/go-pcap"
)

func ExampleCapture_KeyedHTTP2Transactions() {
	raw, err := os.ReadFile("testdata/keyed-http2.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(raw)
	if err != nil {
		log.Fatal(err)
	}
	// The fixture contains its test keys in a PcapNG Decryption Secrets Block.
	rows, err := c.KeyedHTTP2Transactions(raw, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		if row.Request.Path == "/one" && row.Response != nil && row.Response.BodyState == pcap.HTTPBodyComplete {
			fmt.Printf("stream %d, %s %s, status %d, body %q\n", row.ID.StreamID, row.Request.Method, row.Request.Path, row.StatusCode, row.Response.Body)
			fmt.Printf("request frame ranges %v, original packets %v\n", row.RequestRanges, row.PacketIndices)
		}
	}
	// Output:
	// stream 1, POST /one, status 200, body "download"
	// request frame ranges [{33 56} {74 89}], original packets [7 8 9 10 11 12 13]
}

func ExampleCapture_KeyedHTTP2TransactionsFromReaderAt() {
	f, err := os.Open("testdata/keyed-http2.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		log.Fatal(err)
	}
	rows, err := c.KeyedHTTP2TransactionsFromReaderAt(f, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		fmt.Printf("stream %d, offset within record %d, shared packet %t\n", row.ID.StreamID, row.ID.OffsetInRecord, row.SharedPackets)
	}
	// Output:
	// stream 1, offset within record 0, shared packet true
	// stream 3, offset within record 23, shared packet true
}
