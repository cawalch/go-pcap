package pcap_test

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleCapture_SelectTenant() {
	const maxFixtureBytes = 1 << 20
	source, err := os.Open("testdata/framing/tenant-scope.pcapng")
	if err != nil {
		panic(err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		panic(err)
	}
	if info.Size() > maxFixtureBytes {
		panic("mirror fixture exceeds the input limit")
	}
	c, err := pcap.NewFromReaderAt(source, info.Size())
	if err != nil {
		panic(err)
	}
	if len(c.Interfaces) != 1 || c.Interfaces[0].LinkType != pcap.LinkTypeEthernet {
		panic("expected one Ethernet mirror")
	}
	data, err := io.ReadAll(io.NewSectionReader(source, 0, info.Size()))
	if err != nil {
		panic(err)
	}
	c.SeparateTCPInterfaces = true
	c.SeparateIPFragmentInterfaces = true
	streams, err := c.Streams(data)
	if err != nil || len(streams) != 2 {
		panic("expected HTTP and TLS TCP tuples")
	}
	mixedDNS, err := c.DNSFromReaderAt(source)
	if err != nil {
		panic(err)
	}
	fmt.Printf("mirror: HTTP stream conflict=%t, DNS records=%d\n",
		streams[0].Client.Anomalies.OverlapConflict, len(mixedDNS))

	allFlows, err := c.FlowsFromReaderAt(source)
	if err != nil {
		panic(err)
	}
	sliceFlows, err := c.Flows(data)
	if err != nil || !slices.Equal(allFlows, sliceFlows) {
		panic("mirror flow order differs by input path")
	}
	fmt.Printf("mirror flow %d: %s\n", streams[0].FlowIndex, allFlows[streams[0].FlowIndex].CommunityID(0))
	outerA, outerB := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	for _, tenant := range []struct {
		name  string
		scope pcap.TenantScope
	}{
		{"plain", pcap.TenantScope{}},
		{"vlan11", pcap.TenantScope{VLANs: []uint16{100, 11}}},
		{"vlan12", pcap.TenantScope{VLANs: []uint16{100, 12}}},
		{"vni201", pcap.TenantScope{VXLAN: &pcap.VXLANScope{VNI: 201, EndpointA: outerA, EndpointB: outerB}}},
		{"vni202", pcap.TenantScope{VXLAN: &pcap.VXLANScope{VNI: 202, EndpointA: outerA, EndpointB: outerB}}},
	} {
		view, err := c.SelectTenant(tenant.scope)
		if err != nil {
			panic(err)
		}
		tx, err := view.HTTP1TransactionsFromReaderAt(source)
		if err != nil || len(tx) != 1 || tx[0].Response == nil {
			panic("expected one HTTP exchange")
		}
		sliceTX, err := view.HTTP1Transactions(data)
		if err != nil || !reflect.DeepEqual(tx, sliceTX) {
			panic("HTTP evidence differs by input path")
		}
		dns, err := view.DNSFromReaderAt(source)
		if err != nil || len(dns) == 0 || dns[0].Message.IsResponse || len(dns[0].Message.Questions) != 1 {
			panic("expected one reassembled DNS question")
		}
		sliceDNS, err := view.DNS(data)
		if err != nil || !reflect.DeepEqual(dns, sliceDNS) {
			panic("DNS evidence differs by input path")
		}
		dnsTransactions, err := view.DNSTransactionsFromReaderAt(source)
		if err != nil || len(dnsTransactions) != 1 {
			panic("expected one DNS transaction row")
		}
		hellos, err := view.TLSHandshakeEvidenceFromReaderAt(source, nil)
		if err != nil || len(hellos) != 1 {
			panic("expected one TLS opening")
		}
		fmt.Printf("%s DNS paired=%t; TLS hello packets %v/%v\n", tenant.name,
			dnsTransactions[0].Pairing == pcap.DNSPaired, hellos[0].ClientHello.PacketIndices, hellos[0].ServerHello.PacketIndices)
		flows, err := view.FlowsFromReaderAt(source)
		if err != nil {
			panic(err)
		}
		sliceFlows, err := view.Flows(data)
		if err != nil || !slices.Equal(flows, sliceFlows) {
			panic("tenant flow order differs by input path")
		}
		req, rsp := tx[0].Request, tx[0].Response
		if flows[req.FlowIndex].Protocol != pcap.IPProtoTCP || flows[dns[0].FlowIndex].Protocol != pcap.IPProtoUDP {
			panic("tenant evidence index points to the wrong flow")
		}
		fmt.Printf("%s HTTP %s %d %q packets %d,%d; DNS %s packet %d; %s\n",
			tenant.name, req.Target, rsp.StatusCode, rsp.Body, req.PacketIndex, rsp.PacketIndex,
			dns[0].Message.Questions[0].Name, dns[0].PacketIndex, flows[req.FlowIndex].CommunityID(0))
	}
	// Output:
	// mirror: HTTP stream conflict=true, DNS records=2
	// mirror flow 0: 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// plain DNS paired=true; TLS hello packets [58 63]/[73]
	// plain HTTP /plain 200 "plain" packets 15,20; DNS plain.mirror.example packet 30; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vlan11 DNS paired=true; TLS hello packets [59 64]/[74]
	// vlan11 HTTP /vlan11 200 "vlan11" packets 16,21; DNS vlan11.mirror.example packet 31; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vlan12 DNS paired=true; TLS hello packets [60 65]/[75]
	// vlan12 HTTP /vlan12 200 "vlan12" packets 17,22; DNS vlan12.mirror.example packet 32; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vni201 DNS paired=true; TLS hello packets [61 66]/[76]
	// vni201 HTTP /vni201 200 "vni201" packets 18,23; DNS vni201.mirror.example packet 33; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vni202 DNS paired=false; TLS hello packets [62 67]/[]
	// vni202 HTTP /vni202 200 "vni202" packets 19,24; DNS vni202.mirror.example packet 34; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
}
