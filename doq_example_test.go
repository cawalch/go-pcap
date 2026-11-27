package pcap_test

import (
	"bytes"
	"fmt"
	"os"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleCapture_DoQTransactionsFromReaderAt() {
	data, err := os.ReadFile("testdata/doq-exchanges.pcap")
	if err != nil {
		panic(err)
	}
	keys, err := os.ReadFile("testdata/doq-exchanges.keys")
	if err != nil {
		panic(err)
	}
	r := bytes.NewReader(data)
	c, err := pcap.NewFromReaderAt(r, r.Size())
	if err != nil {
		panic(err)
	}
	rows, err := c.DoQTransactionsFromReaderAt(r, keys)
	if err != nil {
		panic(err)
	}
	for _, row := range rows {
		if row.Query.State != pcap.DoQComplete || row.Reply.State != pcap.DoQComplete ||
			len(row.Reply.DNS.Answers) == 0 {
			continue
		}
		fmt.Printf("%s -> %s, stream %d, packets %v and %v\n", row.Query.DNS.Questions[0].Name,
			row.Reply.DNS.Answers[0].Address, row.StreamID, row.Query.PacketIndices, row.Reply.PacketIndices)
	}
	// Output:
	// one.example -> 192.0.2.10, stream 0, packets [5] and [8]
	// two.example -> 192.0.2.11, stream 4, packets [6] and [7]
}
