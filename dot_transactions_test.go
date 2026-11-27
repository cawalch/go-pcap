package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestAnalyzeDNSOverTLSIndependent(t *testing.T) {
	raw, err := os.ReadFile("testdata/dot-exchanges.pcap")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/dot-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	out := dotAnalysisParity(t, raw, keys)
	if len(out.Openings) != 1 || len(out.Transactions) != 2 {
		t.Fatalf("got %d openings and %d transactions", len(out.Openings), len(out.Transactions))
	}
	opening := out.Openings[0]
	if opening.OpeningPacket != 0 || opening.FlowIndex != 0 || opening.EarlyDataOffered ||
		opening.ClientIncompleteFrame || opening.ServerIncompleteFrame ||
		opening.ClientCoverage.End.Reason != TLSCoverageCapturedEnd || opening.ServerCoverage.End.Reason != TLSCoverageCapturedEnd {
		t.Fatalf("opening = %+v", opening)
	}
	for i, want := range []struct {
		name    string
		address string
		query   []int
		reply   int
		records int
	}{
		{"one.example", "192.0.2.10", []int{6, 7, 8}, 10, 2},
		{"two.example", "192.0.2.11", []int{7, 8}, 9, 1},
	} {
		row := out.Transactions[i]
		if row.OpeningPacket != 0 || row.Pairing != DNSPaired || row.Query == nil || row.Reply == nil {
			t.Fatalf("row %d = %+v", i, row)
		}
		if row.Query.Message.Questions[0].Name != want.name ||
			row.Reply.Message.Answers[0].Address != netip.MustParseAddr(want.address) ||
			len(row.Query.Records) != want.records ||
			!slices.Equal(row.Query.PacketIndices, want.query) || !slices.Equal(row.Reply.PacketIndices, []int{want.reply}) ||
			row.Query.PacketIndex != 8 || row.Reply.PacketIndex != want.reply {
			t.Fatalf("row %d query/reply = %+v / %+v", i, row.Query, row.Reply)
		}
	}
	first, second := out.Transactions[0].Query, out.Transactions[1].Query
	if record := first.Records[0]; record.PlaintextStart != 0 || record.PlaintextEnd != 1 ||
		!slices.Equal(record.PacketIndices, []int{6}) {
		t.Fatalf("first framing byte record = %+v", record)
	}
	if !slices.Equal(first.Records[1].PacketIndices, []int{7, 8}) {
		t.Fatalf("split TLS record = %+v", first.Records[1])
	}
	first.Records[1].PacketIndices[0] = -1
	if second.Records[0].PacketIndices[0] != 7 || first.PacketIndices[1] != 7 {
		t.Fatal("returned packet slices alias")
	}

	keyless := dotAnalysisParity(t, raw, nil)
	if len(keyless.Transactions) != 0 || len(keyless.Openings) != 1 ||
		keyless.Openings[0].ClientCoverage.End.Reason != TLSCoverageMissingKey ||
		keyless.Openings[0].ServerCoverage.End.Reason != TLSCoverageMissingKey {
		t.Fatalf("keyless result = %+v", keyless)
	}
}

func dotFrameDNS(wire []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
}

type dotTestConnection struct {
	frames     [][]byte
	keys       []byte
	clientKey  [32]byte
	nextClient uint32
}

func newDotTestConnection(t *testing.T, isn uint32, marker byte, clientData, serverData, clientExtensions []byte) dotTestConnection {
	t.Helper()
	random, clientKey, serverKey := [32]byte{marker}, [32]byte{marker + 1}, [32]byte{marker + 2}
	client := testKeyShareHello(false, random, clientExtensions)
	server := testKeyShareHello(true, [32]byte{marker + 3}, testTLSExtension(TLSExtSupportedVersions, []byte{3, 4}))
	if len(clientData) != 0 {
		client = append(client, encryptTLS13AppDataRecord(t, clientKey[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, clientData)...)
	}
	if len(serverData) != 0 {
		server = append(server, encryptTLS13AppDataRecord(t, serverKey[:], TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, serverData)...)
	}
	frames := [][]byte{
		dotTestClientFrame(isn, TCPFlagSYN, nil),
		dotTestClientFrame(isn+1, TCPFlagACK, client),
		buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 2}, [4]byte{192, 0, 2, 1}, 853, 53000,
			isn+500, isn+1+uint32(len(client)), TCPFlagACK, server),
	}
	return dotTestConnection{
		frames: frames, clientKey: clientKey, nextClient: isn + 1 + uint32(len(client)),
		keys: fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, clientKey, random, serverKey),
	}
}

func dotTestClientFrame(seq uint32, flags uint8, payload []byte) []byte {
	return buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53000, 853, seq, 0, flags, payload)
}

func TestAnalyzeDNSOverTLSOpeningIsolation(t *testing.T) {
	query := dotFrameDNS([]byte(dohTestQuery))
	reply := dotFrameDNS(buildDNSQueryResponsePacket())
	first := newDotTestConnection(t, 100, 10, query, nil, nil)
	second := newDotTestConnection(t, 1000, 20, nil, reply, nil)
	raw := buildPCAPNGFixture(binary.LittleEndian, append(first.keys, second.keys...), append(first.frames, second.frames...))
	out := dotAnalysisParity(t, raw, nil)
	if len(out.Openings) != 2 || len(out.Transactions) != 2 {
		t.Fatalf("result = %+v", out)
	}
	if row := out.Transactions[0]; row.OpeningPacket != 0 || row.Pairing != DNSNoReplyObserved || row.Query == nil || row.Reply != nil {
		t.Fatalf("first opening = %+v", row)
	}
	if row := out.Transactions[1]; row.OpeningPacket != 3 || row.Pairing != DNSNoQueryObserved || row.Query != nil || row.Reply == nil {
		t.Fatalf("reused opening = %+v", row)
	}
	if out.Openings[0].FlowIndex != 0 || out.Openings[1].FlowIndex != 0 {
		t.Fatalf("capture-wide flow indices = %+v", out.Openings)
	}
}

func TestAnalyzeDNSOverTLSAmbiguityAndCoverage(t *testing.T) {
	query := dotFrameDNS([]byte(dohTestQuery))
	reply := dotFrameDNS(buildDNSQueryResponsePacket())
	t.Run("overlapping queries", func(t *testing.T) {
		conn := newDotTestConnection(t, 100, 10, append(bytes.Clone(query), query...), reply, nil)
		out := dotAnalysisParity(t, buildPCAPNGFixture(binary.LittleEndian, conn.keys, conn.frames), nil)
		if len(out.Transactions) != 3 {
			t.Fatalf("got %d ambiguous observations", len(out.Transactions))
		}
		for _, row := range out.Transactions {
			if row.Pairing != DNSAmbiguous {
				t.Fatalf("row = %+v", row)
			}
		}
	})
	t.Run("gap after authenticated query", func(t *testing.T) {
		conn := newDotTestConnection(t, 100, 10, query, reply, nil)
		tail := encryptTLS13AppDataRecord(t, conn.clientKey[:], TLS_AES_128_GCM_SHA256, 1, TLSRecordApplicationData, query)
		frames := append(conn.frames, dotTestClientFrame(conn.nextClient+5, TCPFlagACK, tail))
		out := dotAnalysisParity(t, buildPCAPNGFixture(binary.LittleEndian, conn.keys, frames), nil)
		if len(out.Transactions) != 1 || out.Transactions[0].Pairing != DNSPaired ||
			out.Openings[0].ClientCoverage.End.Reason != TLSCoverageTCPGap || out.Openings[0].ClientIncompleteFrame {
			t.Fatalf("gap = %+v", out)
		}
	})
	t.Run("partial DNS frame", func(t *testing.T) {
		conn := newDotTestConnection(t, 100, 10, append(bytes.Clone(query), query[:3]...), nil, nil)
		out := dotAnalysisParity(t, buildPCAPNGFixture(binary.LittleEndian, conn.keys, conn.frames), nil)
		if len(out.Transactions) != 1 || !out.Openings[0].ClientIncompleteFrame ||
			out.Openings[0].ClientCoverage.End.Reason != TLSCoverageCapturedEnd {
			t.Fatalf("incomplete frame = %+v", out)
		}
	})
	t.Run("early data offer", func(t *testing.T) {
		conn := newDotTestConnection(t, 100, 10, query, reply, testTLSExtension(0x002a, nil))
		out := dotAnalysisParity(t, buildPCAPNGFixture(binary.LittleEndian, conn.keys, conn.frames), nil)
		if len(out.Transactions) != 0 || len(out.Openings) != 1 || !out.Openings[0].EarlyDataOffered {
			t.Fatalf("0-RTT = %+v", out)
		}
	})
}

func TestAnalyzeDNSOverTLSUnsupportedQuestions(t *testing.T) {
	query := []byte(dohTestQuery)
	noQuestion := append(bytes.Clone(query[:2]), 0x81, 0x80)
	noQuestion = append(noQuestion, make([]byte, 8)...)
	ixfr, axfr := bytes.Clone(query), bytes.Clone(query)
	binary.BigEndian.PutUint16(ixfr[len(ixfr)-4:], 251)
	binary.BigEndian.PutUint16(axfr[len(axfr)-4:], 252)
	transfers := append(dotFrameDNS(ixfr), dotFrameDNS(axfr)...)
	conn := newDotTestConnection(t, 100, 10, transfers, dotFrameDNS(noQuestion), nil)
	out := dotAnalysisParity(t, buildPCAPNGFixture(binary.LittleEndian, conn.keys, conn.frames), nil)
	if len(out.Transactions) != 3 {
		t.Fatalf("result = %+v", out)
	}
	for _, row := range out.Transactions {
		if row.Pairing != DNSUnsupported {
			t.Fatalf("row = %+v", row)
		}
	}
}

func TestAnalyzeDNSOverTLSLimits(t *testing.T) {
	query := []byte(dohTestQuery)
	manyQuestions := bytes.Clone(query)
	binary.BigEndian.PutUint16(manyQuestions[4:], MaxDNSQuestions+1)
	conn := newDotTestConnection(t, 100, 10, append(dotFrameDNS(query), dotFrameDNS(manyQuestions)...), nil, nil)
	raw := buildPCAPNGFixture(binary.LittleEndian, conn.keys, conn.frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := c.AnalyzeDNSOverTLS(raw, nil); !errors.Is(err, ErrDNSLimit) || out.Openings != nil || out.Transactions != nil {
		t.Fatalf("DNS limit: result = %+v, err = %v", out, err)
	}

	// Two DNS frames reuse one TLS record. Charge references for each
	// returned message, even when the underlying authenticated record is shared.
	framed := dotFrameDNS(query)
	data := append(bytes.Clone(framed), framed...)
	direction := tlsDirectionProvenance{records: []tlsApplicationRecord{
		{plainEnd: len(data), wireEnd: len(data) + 22, packets: []int{4, 5}},
	}}
	opening := DNSOverTLSOpeningCoverage{
		Client: netip.MustParseAddrPort("192.0.2.1:53000"), Server: netip.MustParseAddrPort("192.0.2.2:853"),
	}
	for _, budget := range []dnsOverTLSBudget{
		{messages: 1, records: 2, references: 6},
		{messages: 2, records: 1, references: 6},
		{messages: 2, records: 2, references: 3},
	} {
		scan := dnsOverTLSOpeningScan{messages: make(map[*DNSRecord]*DNSOverTLSMessage)}
		if _, err := scan.read(&opening, false, data, &direction, &budget); !errors.Is(err, ErrDNSLimit) ||
			len(scan.observations) != 1 {
			t.Fatalf("aggregate limit: got %d observations, err=%v", len(scan.observations), err)
		}
	}
}

func dotAnalysisParity(t *testing.T, raw, keys []byte) DNSOverTLSAnalysis {
	t.Helper()
	sliceCapture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.NewReader(raw)
	atCapture, err := NewFromReaderAt(source, source.Size())
	if err != nil {
		t.Fatal(err)
	}
	want, err := sliceCapture.AnalyzeDNSOverTLS(raw, keys)
	if err != nil {
		t.Fatal(err)
	}
	got, err := atCapture.AnalyzeDNSOverTLSFromReaderAt(source, keys)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReaderAt = %+v, %v, slice = %+v", got, err, want)
	}
	return want
}
