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
	"strings"
	"testing"
)

func TestKeyedQUICProtectionCoverage(t *testing.T) {
	aes, err := os.ReadFile("testdata/doq-exchanges.pcap")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/doq-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	chacha, err := os.ReadFile("testdata/doq-chacha20.pcap")
	if err != nil {
		t.Fatal(err)
	}
	chachaKeys, err := os.ReadFile("testdata/doq-chacha20.keys")
	if err != nil {
		t.Fatal(err)
	}
	frames := keyedQUICFrames(t, aes)
	subset := func(frames [][]byte) []byte {
		return buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, frames)
	}
	withoutServer := subset(slices.Concat(frames[:1], frames[2:]))
	longHeadersOnly := subset(frames[:2])
	withoutInitial := subset(frames[3:])
	var wrongKeys strings.Builder
	for line := range strings.SplitSeq(string(keys), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			wrongKeys.WriteString(fields[0] + " " + fields[1] + " " + strings.Repeat("0", len(fields[2])) + "\n")
		}
	}
	var serverKeys strings.Builder
	for line := range strings.SplitSeq(string(keys), "\n") {
		if strings.HasPrefix(line, "SERVER_") {
			serverKeys.WriteString(line + "\n")
		}
	}

	const (
		accepted    = QUICProtectionAuthenticated
		unknown     = QUICProtectionUnknown
		missing     = QUICProtectionMissingKey
		unsupported = QUICProtectionUnsupported
		failed      = QUICProtectionAuthenticationFailed
		noHandshake = QUICProtectionHandshakeUnavailable
		aesSuite    = TLS_AES_128_GCM_SHA256
	)
	for _, tc := range []struct {
		name      string
		raw, keys []byte
		suite     uint16
		states    [3]QUICProtectionState
		indices   [3]int
		doqRows   int
	}{
		{"AES", aes, keys, aesSuite, [3]QUICProtectionState{accepted, accepted, accepted}, [3]int{2, 3, 1}, 2},
		{"ChaCha20", chacha, chachaKeys, 0x1303, [3]QUICProtectionState{unsupported, unsupported, unsupported}, [3]int{-1, -1, -1}, 0},
		{"keyless", aes, nil, aesSuite, [3]QUICProtectionState{missing, missing, missing}, [3]int{-1, -1, -1}, 0},
		{"server keys", aes, []byte(serverKeys.String()), aesSuite, [3]QUICProtectionState{missing, accepted, accepted}, [3]int{-1, 3, 1}, 2},
		{"wrong keys", aes, []byte(wrongKeys.String()), aesSuite, [3]QUICProtectionState{failed, failed, failed}, [3]int{2, 3, 1}, 0},
		{"no 1-RTT", longHeadersOnly, keys, aesSuite, [3]QUICProtectionState{unknown, unknown, accepted}, [3]int{-1, -1, 1}, 0},
		{"no ServerHello", withoutServer, keys, 0, [3]QUICProtectionState{noHandshake, noHandshake, noHandshake}, [3]int{-1, -1, -1}, 0},
		{"no ClientHello", withoutInitial, keys, 0, [3]QUICProtectionState{}, [3]int{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.AnalyzeKeyedQUIC(tc.raw, tc.keys)
			if err != nil {
				t.Fatal(err)
			}
			for _, reader := range []io.ReaderAt{bytes.NewReader(tc.raw), tempCaptureFile(t, tc.raw)} {
				observed, err := c.AnalyzeKeyedQUICFromReaderAt(reader, tc.keys)
				if err != nil || !reflect.DeepEqual(observed, got) {
					t.Fatalf("%T coverage differs: %+v, %v", reader, observed, err)
				}
			}
			original, err := c.KeyedQUICWithALPN(tc.raw, tc.keys)
			if err != nil || !reflect.DeepEqual(got.records, original) {
				t.Fatalf("keyed records changed: %+v, %v", got.records, err)
			}
			rows, err := got.DoQTransactions()
			if err != nil || len(rows) != tc.doqRows {
				t.Fatalf("DoQ rows: %+v, %v", rows, err)
			}
			want, err := c.DoQTransactions(tc.raw, tc.keys)
			if err != nil || !reflect.DeepEqual(rows, want) {
				t.Fatalf("DoQ rows changed: %+v, %v", want, err)
			}
			if tc.name == "no ClientHello" {
				if !reflect.DeepEqual(got, KeyedQUICAnalysis{}) {
					t.Fatalf("unidentified packets yielded %+v", got)
				}
				return
			}
			if len(got.Connections) != 1 {
				t.Fatalf("expected one observed exchange: %+v", got.Connections)
			}
			conn := got.Connections[0]
			recordIndex := -1
			if len(original) != 0 {
				recordIndex = 0
			}
			if conn.InitialPacketIndex != 0 || conn.FlowIndex != 0 || conn.RecordIndex != recordIndex ||
				conn.Version != QUICVersion1 || conn.CipherSuite != tc.suite ||
				conn.Client.Addr() != netip.MustParseAddr("192.0.2.1") || conn.Server.Addr() != netip.MustParseAddr("192.0.2.2") {
				t.Fatalf("unexpected exchange identity: %+v", conn)
			}
			for i, observed := range [3]QUICProtectionObservation{conn.Client1RTT, conn.Server1RTT, conn.ServerHandshake} {
				want := QUICProtectionObservation{State: tc.states[i], PacketIndex: tc.indices[i]}
				if observed != want {
					t.Errorf("coverage %d = %+v, want %+v", i, observed, want)
				}
			}
		})
	}

	// Unsupported exchanges retain their positions, including when they share
	// a tuple with a different Initial exchange that produced a keyed row.
	chachaFrames := keyedQUICFrames(t, chacha)
	raw := subset(slices.Concat(chachaFrames, frames))
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.AnalyzeKeyedQUICFromReaderAt(bytes.NewReader(raw), slices.Concat(chachaKeys, keys))
	if err != nil || len(a.Connections) != 2 || a.Connections[0].RecordIndex != -1 || a.Connections[1].RecordIndex != 0 ||
		a.Connections[0].InitialPacketIndex != 0 || a.Connections[1].InitialPacketIndex != len(chachaFrames) ||
		a.Connections[0].FlowIndex != a.Connections[1].FlowIndex ||
		a.Connections[1].Client1RTT.PacketIndex != len(chachaFrames)+2 {
		t.Fatalf("mixed coverage = %+v, %v", a.Connections, err)
	}
}

func TestKeyedQUICAnalysisHTTP3AndDoH(t *testing.T) {
	raw, err := os.ReadFile("testdata/doh-exchanges.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile("testdata/doh-exchanges.keys")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.AnalyzeKeyedQUICFromReaderAt(bytes.NewReader(raw), keys)
	if err != nil || len(a.Connections) != 1 || a.Connections[0].RecordIndex != 0 {
		t.Fatalf("QUIC analysis: %+v, %v", a, err)
	}
	got, err := a.HTTP3Transactions()
	if err != nil || len(got) != 5 {
		t.Fatalf("HTTP/3 transactions: %+v, %v", got, err)
	}
	want, err := c.KeyedHTTP3Transactions(raw, keys)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTP/3 transaction parity: %+v, %v", want, err)
	}
	doh, err := a.DoHTransactions()
	if err != nil || len(doh) != 4 {
		t.Fatalf("DoH transactions: %+v, %v", doh, err)
	}
	all, err := c.DoHTransactions(raw, keys)
	if err != nil || len(all) != 8 || !reflect.DeepEqual(doh, all[4:]) {
		t.Fatalf("HTTP/3 DoH parity: %+v, %v", all, err)
	}
	a, err = c.AnalyzeKeyedQUIC(raw, nil)
	if err != nil || len(a.Connections) != 1 || a.Connections[0].ServerHandshake.State != QUICProtectionMissingKey {
		t.Fatalf("keyless DoH coverage: %+v, %v", a, err)
	}
	if rows, err := a.HTTP3Transactions(); len(rows) != 0 || err != nil {
		t.Fatalf("keyless HTTP/3 transactions: %+v, %v", rows, err)
	}
	if rows, err := a.DoHTransactions(); len(rows) != 0 || err != nil {
		t.Fatalf("keyless DoH transactions: %+v, %v", rows, err)
	}
}

func TestKeyedQUICAnalysisLimits(t *testing.T) {
	raw, keys := keyedQUICFixture(t, 1)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := measuredReaderAt{Reader: bytes.NewReader(raw)}
	if _, err := c.QUICFromReaderAt(&m); err != nil {
		t.Fatal(err)
	}
	budget := scanReadBudget{r: bytes.NewReader(raw), remaining: m.bytesRead}
	if a, err := c.AnalyzeKeyedQUICFromReaderAt(&budget, keys); !errors.Is(err, ErrPacketLimit) ||
		!reflect.DeepEqual(a, KeyedQUICAnalysis{}) || budget.remaining != 0 {
		t.Fatalf("limited analysis = %+v, %v, remaining %d", a, err, budget.remaining)
	}

	frames := keyedQUICFrames(t, raw)
	// Repeat a standalone 1-RTT packet until the keyed probe cap is reached.
	repeated := append(slices.Clone(frames), slices.Repeat(frames[4:5], MaxKeyedQUICProbes)...)
	raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeRaw, 65535, repeated)
	c, err = New(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, analyze := range []func() (KeyedQUICAnalysis, error){
		func() (KeyedQUICAnalysis, error) { return c.AnalyzeKeyedQUIC(raw, keys) },
		func() (KeyedQUICAnalysis, error) { return c.AnalyzeKeyedQUICFromReaderAt(bytes.NewReader(raw), keys) },
	} {
		if a, err := analyze(); !errors.Is(err, ErrQUICLimit) || !reflect.DeepEqual(a, KeyedQUICAnalysis{}) {
			t.Fatalf("probe-limited analysis = %+v, %v", a, err)
		}
	}
}
