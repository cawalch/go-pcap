package pcap_test

import (
	"fmt"
	"os"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleCapture_AnalyzeDNSOverTLSFromReaderAt() {
	file, err := os.Open("testdata/dot-exchanges.pcap")
	if err != nil {
		panic(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	keys, err := os.ReadFile("testdata/dot-exchanges.keys")
	if err != nil {
		panic(err)
	}
	c, err := pcap.NewFromReaderAt(file, info.Size())
	if err != nil {
		panic(err)
	}
	result, err := c.AnalyzeDNSOverTLSFromReaderAt(file, keys)
	if err != nil {
		panic(err)
	}
	for _, row := range result.Transactions {
		if row.Pairing != pcap.DNSPaired || len(row.Reply.Message.Answers) == 0 {
			continue
		}
		fmt.Printf("%s -> %s, TCP opening %d, packets %v and %v\n", row.Query.Message.Questions[0].Name,
			row.Reply.Message.Answers[0].Address, row.OpeningPacket, row.Query.PacketIndices, row.Reply.PacketIndices)
	}
	// Output:
	// one.example -> 192.0.2.10, TCP opening 0, packets [6 7 8] and [10]
	// two.example -> 192.0.2.11, TCP opening 0, packets [7 8] and [9]
}
