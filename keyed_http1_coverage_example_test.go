package pcap_test

import (
	"bytes"
	"fmt"
	"os"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleCapture_AnalyzeKeyedHTTP1() {
	raw, err := os.ReadFile("testdata/keyed-http1-tls13.pcapng")
	if err != nil {
		panic(err)
	}
	c, err := pcap.New(raw)
	if err != nil {
		panic(err)
	}
	observed, err := c.AnalyzeKeyedHTTP1(raw, nil)
	if err != nil {
		panic(err)
	}
	keyless := *c
	keyless.Secrets = nil
	opaque, err := keyless.AnalyzeKeyedHTTP1(raw, nil)
	if err != nil {
		panic(err)
	}
	classify := func(a pcap.KeyedHTTP1Analysis, marker []byte) {
		for _, row := range a.Transactions {
			if row.Request.Target != "/second" || row.Response == nil ||
				row.Response.BodyState != pcap.HTTPBodyComplete || row.Response.BodyLimitExceeded {
				continue
			}
			fmt.Printf("complete response, marker match=%t, packets=%v\n", bytes.Contains(row.Response.Body, marker), row.PacketIndices)
			return
		}
		for _, opening := range a.Openings {
			if opening.ClientCoverage.End.Reason == pcap.TLSCoverageMissingKey {
				fmt.Printf("unknown, missing key at opening packet %d\n", opening.OpeningPacket)
				return
			}
		}
		fmt.Println("unknown, complete response unavailable")
	}
	classify(observed, []byte("reply"))
	classify(observed, []byte("absent"))
	classify(opaque, []byte("reply"))
	// Output:
	// complete response, marker match=true, packets=[5 7 8 9 10]
	// complete response, marker match=false, packets=[5 7 8 9 10]
	// unknown, missing key at opening packet 0
}
