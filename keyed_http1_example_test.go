package pcap_test

import (
	"fmt"
	"log"
	"os"

	"github.com/cawalch/go-pcap"
)

func ExampleCapture_KeyedHTTP1Transactions() {
	raw, err := os.ReadFile("testdata/keyed-http1.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.New(raw)
	if err != nil {
		log.Fatal(err)
	}
	// The fixture embeds its test keys. Supply NSS key log bytes as the
	// second argument for captures with external keys.
	rows, err := c.KeyedHTTP1Transactions(raw, nil)
	if err != nil {
		log.Fatal(err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		if row.Pairing != pcap.HTTP1ResponseConfirmed {
			continue
		}
		p := packets[row.RequestRecords[0].PacketIndices[0]]
		fmt.Printf("%s %d, record offset %d, packet %d time %d, evidence %v\n", row.Request.Target, row.Response.StatusCode,
			row.ID.OffsetInRecord, p.Index, p.TimestampNs, row.PacketIndices)
	}
	// Output:
	// /first 204, record offset 0, packet 5 time 1700000000005000000, evidence [5 6]
	// /second 201, record offset 46, packet 5 time 1700000000005000000, evidence [5 7 8 9 10]
}

func ExampleCapture_KeyedHTTP1TransactionsFromReaderAt() {
	reader, err := os.Open("testdata/keyed-http1.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	info, err := reader.Stat()
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.NewFromReaderAt(reader, info.Size())
	if err != nil {
		log.Fatal(err)
	}
	rows, err := c.KeyedHTTP1TransactionsFromReaderAt(reader, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		if row.Request.Target == "/second" && row.Response != nil && row.Response.BodyState == pcap.HTTPBodyComplete {
			fmt.Println(string(row.Response.Body))
		}
	}
	// Output: reply
}
