package consumer_test

import (
	"bytes"
	"os"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func BenchmarkClientDNS(b *testing.B) {
	for _, name := range []string{"dns-address", "dns-https"} {
		raw, err := os.ReadFile("testdata/" + name + ".pcap")
		if err != nil {
			b.Fatal(err)
		}
		r := bytes.NewReader(raw)
		c, err := pcap.New(raw)
		if err != nil {
			b.Fatal(err)
		}
		for _, input := range []string{"bytes", "reader"} {
			b.Run(name+"/"+input, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var records []pcap.DNSRecord
					var err error
					if input == "bytes" {
						records, err = c.DNS(raw)
					} else {
						records, err = c.DNSFromReaderAt(r)
					}
					if err != nil || len(records) != 32 {
						b.Fatalf("DNS records = %d, error = %v", len(records), err)
					}
				}
			})
		}
	}
}
