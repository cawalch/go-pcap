package pcap_test

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/cawalch/go-pcap"
)

func ExampleTenantCapture_DNSHTTP1Links() {
	data, err := os.ReadFile("testdata/framing/tenant-dns-http.pcapng")
	if err != nil {
		panic(err)
	}
	capture, err := pcap.New(data)
	if err != nil {
		panic(err)
	}
	view, err := capture.SelectTenant(pcap.TenantScope{VXLAN: &pcap.VXLANScope{
		VNI: 201, EndpointA: netip.MustParseAddr("203.0.113.1"), EndpointB: netip.MustParseAddr("203.0.113.2"),
	}})
	if err != nil {
		panic(err)
	}
	evidence, err := view.DNSHTTP1Links(data, "mirror-A", 10*time.Second)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s VNI %d\n", evidence.CaptureID, evidence.Scope.VXLAN.VNI)
	for _, link := range evidence.Links {
		switch link.Status {
		case pcap.DNSHTTP1CandidateObserved:
			answer := link.Candidates[0]
			fmt.Printf("request %d: %s at reply packet %d\n", link.RequestID.PacketIndex, answer.Name, answer.ReplyPacket)
		case pcap.DNSHTTP1Ambiguous:
			fmt.Printf("request %d: ambiguous\n", link.RequestID.PacketIndex)
		default:
			fmt.Printf("request %d: unresolved\n", link.RequestID.PacketIndex)
		}
	}
	// Output:
	// mirror-A VNI 201
	// request 11: first.example at reply packet 1
	// request 18: ambiguous
	// request 25: unresolved
}
