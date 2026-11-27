package pcap_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"

	pcap "github.com/cawalch/go-pcap"
)

type mirrorTenant struct {
	name  string
	vlans []uint16
	vni   uint32
}

func (t mirrorTenant) matches(frame *pcap.Frame, packet []byte) bool {
	if frame.Anomalies.TruncatedLayer || frame.Anomalies.VLANDepthExceeded ||
		!slices.Equal(frame.VLANTags[:frame.VLANCount], t.vlans) {
		return false
	}
	var vni uint32
	var found bool
	for _, layer := range frame.LayerSlices() {
		if layer.Proto != pcap.LayerVXLAN {
			continue
		}
		offset := int(layer.Offset)
		if found || layer.Length != 8 || offset > len(packet)-8 {
			return false
		}
		found = true
		vni = uint32(packet[offset+4])<<16 | uint32(packet[offset+5])<<8 | uint32(packet[offset+6])
	}
	return found == (t.vni != 0) && vni == t.vni
}

// selectMirrorTenant preserves the fixture's wire bytes and a map from the
// new capture's zero-based packet index to the original Ethernet mirror.
func selectMirrorTenant(c *pcap.Capture, source io.ReaderAt, tenant mirrorTenant) ([]byte, []int, error) {
	var selected bytes.Buffer
	var original []int
	writer, err := pcap.NewPCAPNGWriter(&selected, pcap.PCAPNGWriterOptions{
		LinkType: pcap.LinkTypeEthernet, SnapLen: c.Interfaces[0].SnapLen, InterfaceName: tenant.name,
	})
	if err != nil {
		return nil, nil, err
	}
	for packet, err := range c.PacketSeqFromReaderAt(source) {
		if err != nil {
			return nil, nil, err
		}
		payload, err := c.PacketPayloadFromReaderAt(source, packet)
		if err != nil {
			return nil, nil, err
		}
		frame, err := pcap.DecodeFrame(payload, packet.LinkType)
		if err != nil {
			return nil, nil, err
		}
		if tenant.matches(&frame, payload) {
			if err := writer.WritePacket(pcap.PacketRecord{
				TimestampNs: packet.TimestampNs, OriginalLen: packet.OriginalLen,
			}, payload); err != nil {
				return nil, nil, err
			}
			original = append(original, packet.Index)
		}
	}
	return selected.Bytes(), original, nil
}

func ExampleCapture_HTTP1Transactions_tenantScope() {
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
	if err != nil || len(streams) != 1 {
		panic("expected one shared TCP tuple")
	}
	mixedDNS, err := c.DNSFromReaderAt(source)
	if err != nil {
		panic(err)
	}
	fmt.Printf("mirror: one TCP stream, conflict=%t, DNS records=%d\n",
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
	for _, tenant := range []mirrorTenant{
		{name: "plain"}, {name: "vlan11", vlans: []uint16{100, 11}}, {name: "vlan12", vlans: []uint16{100, 12}},
		{name: "vni201", vni: 201}, {name: "vni202", vni: 202},
	} {
		selection, original, err := selectMirrorTenant(c, source, tenant)
		if err != nil {
			panic(err)
		}
		r := bytes.NewReader(selection)
		subset, err := pcap.NewFromReaderAt(r, r.Size())
		if err != nil {
			panic(err)
		}
		tx, err := subset.HTTP1TransactionsFromReaderAt(r)
		if err != nil || len(tx) != 1 || tx[0].Response == nil {
			panic("expected one HTTP exchange")
		}
		dns, err := subset.DNSFromReaderAt(r)
		if err != nil || len(dns) != 1 || len(dns[0].Message.Questions) != 1 {
			panic("expected one reassembled DNS question")
		}
		flows, err := subset.FlowsFromReaderAt(r)
		if err != nil {
			panic(err)
		}
		req, rsp := tx[0].Request, tx[0].Response
		fmt.Printf("%s HTTP %s %d %q packets %d,%d; DNS %s packet %d; %s\n",
			tenant.name, req.Target, rsp.StatusCode, rsp.Body, original[req.PacketIndex], original[rsp.PacketIndex],
			dns[0].Message.Questions[0].Name, original[dns[0].PacketIndex], flows[req.FlowIndex].CommunityID(0))
	}
	// Output:
	// mirror: one TCP stream, conflict=true, DNS records=1
	// mirror flow 0: 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// plain HTTP /plain 200 "plain" packets 15,20; DNS plain.mirror.example packet 30; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vlan11 HTTP /vlan11 200 "vlan11" packets 16,21; DNS vlan11.mirror.example packet 31; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vlan12 HTTP /vlan12 200 "vlan12" packets 17,22; DNS vlan12.mirror.example packet 32; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vni201 HTTP /vni201 200 "vni201" packets 18,23; DNS vni201.mirror.example packet 33; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
	// vni202 HTTP /vni202 200 "vni202" packets 19,24; DNS vni202.mirror.example packet 34; 1:sOt0+JmdXpF66uyTH/7eX/9XeD4=
}
