package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestTenantDNSHTTP1Links(t *testing.T) {
	const fixture = "testdata/framing/tenant-dns-http.pcapng"
	file, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	fromReader, err := NewFromReaderAt(file, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	vx := VXLANScope{VNI: 201, EndpointA: netip.MustParseAddr("203.0.113.1"), EndpointB: netip.MustParseAddr("203.0.113.2")}
	other := vx
	other.VNI = 202
	type expectedLink struct {
		opening, request int
		status           DNSHTTP1LinkStatus
		replies          []int
	}
	for _, tc := range []struct {
		name  string
		scope TenantScope
		want  []expectedLink
	}{
		{"vxlan201", TenantScope{VXLAN: &vx}, []expectedLink{
			{8, 11, DNSHTTP1CandidateObserved, []int{1}},
			{15, 18, DNSHTTP1Ambiguous, []int{1, 14}},
			{22, 25, DNSHTTP1Unresolved, nil},
		}},
		{"vxlan202", TenantScope{VXLAN: &other}, []expectedLink{{3, 6, DNSHTTP1Unresolved, nil}}},
		{"tcp-dns", TenantScope{}, []expectedLink{
			{32, 35, DNSHTTP1Unresolved, nil},
			{38, 41, DNSHTTP1CandidateObserved, []int{37}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view, err := c.SelectTenant(tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			readerView, err := fromReader.SelectTenant(tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			got, err := view.DNSHTTP1Links(raw, "mirror-A", 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			for _, reader := range []io.ReaderAt{bytes.NewReader(raw), file} {
				at, err := readerView.DNSHTTP1LinksFromReaderAt(reader, "mirror-A", 10*time.Second)
				if err != nil || !reflect.DeepEqual(got, at) {
					t.Fatalf("slice = %+v, reader = %+v, %v", got, at, err)
				}
			}
			if got.CaptureID != "mirror-A" || !reflect.DeepEqual(got.Scope, tc.scope) || len(got.Links) != len(tc.want) {
				t.Fatalf("scope or count = %+v", got)
			}
			for i, link := range got.Links {
				want := tc.want[i]
				if link.OpeningPacket != want.opening || link.RequestID != (HTTP1TransactionID{PacketIndex: want.request}) ||
					link.Status != want.status || len(link.Candidates) != len(want.replies) {
					t.Fatalf("link %d = %+v, want %+v", i, link, want)
				}
				if link.Client != netip.MustParseAddrPort("192.0.2.10:43000") || link.RequestTimestampNs != dnsHTTPFixtureTime(want.request) {
					t.Fatalf("request evidence = %+v", link)
				}
				destination := netip.MustParseAddrPort("198.51.100.20:80")
				if want.request == 25 {
					destination = netip.MustParseAddrPort("198.51.100.22:80")
				} else if link.CommunityID(0) != "1:sOt0+JmdXpF66uyTH/7eX/9XeD4=" {
					t.Fatalf("Community ID = %q", link.CommunityID(0))
				}
				if link.Destination != destination {
					t.Fatalf("destination = %v, want %v", link.Destination, destination)
				}
				for j, candidate := range link.Candidates {
					reply := want.replies[j]
					query := reply - 1
					name, ttl := "first.example", uint32(60)
					switch reply {
					case 14:
						name = "second.example"
					case 37:
						query = 30
						name, ttl = "tcp.example", 300
					}
					if candidate.QueryPacket != query || candidate.ReplyPacket != reply ||
						candidate.QueryTimestampNs != dnsHTTPFixtureTime(query) || candidate.ReplyTimestampNs != dnsHTTPFixtureTime(reply) ||
						candidate.Name != name || candidate.TTL != ttl || candidate.TransactionID != 0x1020 {
						t.Fatalf("DNS evidence = %+v", candidate)
					}
				}
			}
			if got.Scope.VXLAN != nil {
				got.Scope.VXLAN.VNI = 999
				again, err := view.DNSHTTP1Links(raw, "mirror-A", 3*time.Second)
				if err != nil || again.Scope.VXLAN.VNI != tc.scope.VXLAN.VNI {
					t.Fatalf("scope mutation affected the view: %+v, %v", again.Scope, err)
				}
				if tc.scope.VXLAN.VNI == 201 && (again.Links[0].Status != DNSHTTP1CandidateObserved || again.Links[1].Status != DNSHTTP1CandidateObserved) {
					t.Fatalf("maximum age window = %+v", again.Links)
				}
			}
		})
	}
}

func TestTenantDNSHTTP1ReadBudget(t *testing.T) {
	raw, err := os.ReadFile("testdata/framing/tenant-dns-http.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	view, err := c.SelectTenant(TenantScope{})
	if err != nil {
		t.Fatal(err)
	}
	budget := &scanReadBudget{r: bytes.NewReader(raw), remaining: int64(len(raw))}
	dns, http := c.dnsTransactionReaderAt(budget), c.tcpReaderAt(budget)
	dns.scope, http.scope = &view.scope, &view.scope
	got, err := view.scanDNSHTTP1(dns, http, "mirror-A", 10*time.Second)
	if !errors.Is(err, ErrPacketLimit) || got.CaptureID != "" || len(got.Links) != 0 {
		t.Fatalf("limited scan = %+v, %v", got, err)
	}
	if _, err := view.DNSHTTP1Links(raw, "", time.Second); !errors.Is(err, ErrInvalidDNSHTTP1Options) {
		t.Fatalf("empty capture identity = %v", err)
	}
	if _, err := view.DNSHTTP1LinksFromReaderAt(bytes.NewReader(raw), "mirror-A", 0); !errors.Is(err, ErrInvalidDNSHTTP1Options) {
		t.Fatalf("nonpositive max age = %v", err)
	}
}

func dnsHTTPFixtureTime(packet int) int64 {
	return 1_700_000_000_000_000_000 + int64(packet+1)*int64(300*time.Millisecond)
}

func TestTenantDNSHTTP1DirectAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, question, owner string
		kind, flags           uint16
		address               netip.Addr
		want                  bool
	}{
		{"compressed AAAA", "\x01A\x01b\x00", "\x01a\xc0\x0e", DNSTypeAAAA, 0x8180, netip.MustParseAddr("2001:db8::42"), true},
		{"different label boundary", "\x01a\x01b\x00", "\x03a.b\x00", DNSTypeA, 0x8180, netip.MustParseAddr("192.0.2.42"), false},
		{"truncated reply", "\x01a\x01b\x00", "\xc0\x0c", DNSTypeA, 0x8380, netip.MustParseAddr("192.0.2.42"), false},
		{"negative reply", "\x01a\x01b\x00", "\xc0\x0c", DNSTypeA, 0x8183, netip.MustParseAddr("192.0.2.42"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := make([]byte, 12)
			binary.BigEndian.PutUint16(wire[2:4], tc.flags)
			binary.BigEndian.PutUint16(wire[4:6], 1)
			binary.BigEndian.PutUint16(wire[6:8], 1)
			wire = append(wire, tc.question...)
			wire = binary.BigEndian.AppendUint16(wire, tc.kind)
			wire = binary.BigEndian.AppendUint16(wire, 1)
			wire = append(wire, tc.owner...)
			wire = binary.BigEndian.AppendUint16(wire, tc.kind)
			wire = binary.BigEndian.AppendUint16(wire, 1)
			wire = binary.BigEndian.AppendUint32(wire, 60)
			wire = binary.BigEndian.AppendUint16(wire, uint16(tc.address.BitLen()/8))
			wire = append(wire, tc.address.AsSlice()...)
			m, err := ParseDNS(wire)
			if err != nil {
				t.Fatal(err)
			}
			got := retainDirectDNSAnswers(&m, wire, dnsPairingName(wire[12:]))
			if tc.want && (len(got) != 1 || got[0].Address != tc.address) || !tc.want && len(got) != 0 {
				t.Fatalf("direct answers = %+v", got)
			}
		})
	}
	wire := buildDNSQueryResponsePacket()
	m, err := ParseDNS(wire)
	if err != nil || len(retainDirectDNSAnswers(&m, wire, dnsPairingName(wire[12:]))) != 0 {
		t.Fatalf("alias result = %+v, %v", m, err)
	}
}

func TestTenantDNSHTTP1TimingAndLimits(t *testing.T) {
	reply := DNSHTTP1AnswerEvidence{QueryPacket: 3, ReplyPacket: 4, QueryTimestampNs: 1, ReplyTimestampNs: int64(time.Second), TTL: 2}
	for _, tc := range []struct {
		name      string
		reply     DNSHTTP1AnswerEvidence
		requestNs int64
		maxAge    time.Duration
		want      DNSHTTP1LinkStatus
	}{
		{"maximum age boundary", reply, int64(2 * time.Second), time.Second, DNSHTTP1CandidateObserved},
		{"TTL boundary", reply, int64(3 * time.Second), 4 * time.Second, DNSHTTP1Unresolved},
		{"missing request time", reply, 0, time.Second, DNSHTTP1Unresolved},
		{"request clock moved backward", reply, 1, time.Second, DNSHTTP1Unresolved},
		{"reply completes after request", DNSHTTP1AnswerEvidence{QueryPacket: 3, ReplyPacket: 6, QueryTimestampNs: 1, ReplyTimestampNs: 2, TTL: 2}, 3, time.Second, DNSHTTP1Unresolved},
		{"missing query time", DNSHTTP1AnswerEvidence{QueryPacket: 3, ReplyPacket: 4, ReplyTimestampNs: 2, TTL: 2}, 3, time.Second, DNSHTTP1Unresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := DNSHTTP1Link{RequestID: HTTP1TransactionID{PacketIndex: 5}, RequestTimestampNs: tc.requestNs}
			checks := 1
			if err := link.selectCandidates([]DNSHTTP1AnswerEvidence{tc.reply}, tc.maxAge, &checks); err != nil || link.Status != tc.want {
				t.Fatalf("link = %+v, %v", link, err)
			}
		})
	}
	link := DNSHTTP1Link{RequestID: HTTP1TransactionID{PacketIndex: 7}, RequestTimestampNs: int64(2 * time.Second)}
	uncertain := reply
	uncertain.QueryTimestampNs, uncertain.ReplyPacket = reply.ReplyTimestampNs+1, 6
	checks := 2
	if err := link.selectCandidates([]DNSHTTP1AnswerEvidence{reply, uncertain}, time.Second, &checks); err != nil ||
		link.Status != DNSHTTP1Unresolved || !slices.Equal(link.Candidates, []DNSHTTP1AnswerEvidence{reply}) {
		t.Fatalf("competing indeterminate link = %+v, %v", link, err)
	}
	if err := link.selectCandidates([]DNSHTTP1AnswerEvidence{reply}, time.Second, &checks); !errors.Is(err, ErrDNSHTTP1Limit) {
		t.Fatalf("work limit = %v", err)
	}
}

func TestTenantDNSHTTP1AnswerIndex(t *testing.T) {
	client, origin, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	query := &DNSRecord{SrcAddr: client, Message: DNSMessage{Questions: []DNSQuestion{{Name: "trace.example"}}}}
	rows := []DNSTransaction{
		{Pairing: DNSPaired, Query: query, Reply: &DNSRecord{PacketIndex: 7, Message: DNSMessage{
			Answers: []DNSResourceRecord{{Address: origin, TTL: 40}, {Address: origin, TTL: 80}, {Address: other, TTL: 1 << 31}},
		}}},
		{Pairing: DNSPaired, Query: query, Reply: &DNSRecord{PacketIndex: 6, Message: DNSMessage{
			Answers: []DNSResourceRecord{{Address: origin, TTL: 60}, {Address: other, TTL: 0}, {Address: other, TTL: 100}},
		}}},
	}
	index, err := indexDNSHTTP1Answers(rows)
	if err != nil {
		t.Fatal(err)
	}
	got := index[dnsHTTP1Key{client, origin}]
	if len(index) != 1 || len(got) != 2 || got[0].ReplyPacket != 6 || got[0].TTL != 60 || got[1].ReplyPacket != 7 || got[1].TTL != 40 {
		t.Fatalf("answer index = %+v", index)
	}
}
