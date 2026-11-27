package pcap

import (
	"bytes"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestKeyedHTTP1Analysis(t *testing.T) {
	f := newKeyedFixture(t, TLSVersion13)
	f.pipeline()
	for _, name := range []string{"empty", "keyless", "gap", "authentication", "complete"} {
		t.Run(name, func(t *testing.T) {
			keys, frames := f.keys, slices.Clone(f.packets)
			switch name {
			case "empty":
				keys, frames = nil, nil
			case "keyless":
				keys = nil
			case "gap":
				frames = slices.Delete(frames, 8, 9)
			case "authentication":
				frames[9] = bytes.Clone(frames[9])
				frames[9][len(frames[9])-1] ^= 1
			}
			raw := keyedCapture(t, keys, frames)
			c, err := New(raw)
			if err != nil {
				t.Fatal(err)
			}
			a, err := c.AnalyzeKeyedHTTP1(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(raw)
			cFile, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			b, err := cFile.AnalyzeKeyedHTTP1FromReaderAt(r, nil)
			if err != nil || !reflect.DeepEqual(a, b) {
				t.Fatalf("ReaderAt coverage differs: %v", err)
			}
			rows, err := c.KeyedHTTP1Transactions(raw, nil)
			if err != nil || !reflect.DeepEqual(rows, a.Transactions) {
				t.Fatalf("transaction selection differs: %v", err)
			}
			if name == "empty" {
				if len(a.Openings) != 0 || len(rows) != 0 {
					t.Fatal("empty capture reported evidence")
				}
				return
			}
			if len(a.Openings) != 1 || a.Openings[0].OpeningPacket != 0 {
				t.Fatalf("got openings %+v", a.Openings)
			}
			opening := a.Openings[0]
			client, server := opening.ClientCoverage, opening.ServerCoverage
			want := TLSCoverageCapturedEnd
			switch name {
			case "keyless":
				want = TLSCoverageMissingKey
				if len(rows) != 0 || client.Bytes != 0 || client.End.Reason != want {
					t.Fatalf("keyless client coverage %+v, rows %d", client, len(rows))
				}
			case "gap":
				want = TLSCoverageTCPGap
			case "authentication":
				want = TLSCoverageAuthenticationFailed
			}
			if server.End.Reason != want || server.End.WireOffset < 0 || server.AuthenticatedClose {
				t.Fatalf("expected coverage reason %d, got %+v", want, server)
			}
			if name != "keyless" && (client.Bytes == 0 || client.End.Reason != TLSCoverageCapturedEnd) {
				t.Fatalf("client lost complete records: %+v", client)
			}
		})
	}
}

func TestTLSCoverageReasonLimit(t *testing.T) {
	d := tlsDirectionProvenance{stop: tlsProvenanceBoundary{wireOffset: 25, reason: tlsStopLimit}}
	state := annotatedTLSCoverage(&d, 9)
	if state.Bytes != 9 || state.End != (TLSCoverageBoundary{WireOffset: 25, Reason: TLSCoverageLimit}) ||
		state.Before != (TLSCoverageBoundary{WireOffset: -1, Reason: TLSCoverageUnknown}) {
		t.Fatalf("coverage %+v", state)
	}
}

func BenchmarkKeyedHTTP1OpeningCoverage(b *testing.B) {
	f, err := os.ReadFile("testdata/keyed-http1-tls13.pcapng")
	if err != nil {
		b.Fatal(err)
	}
	c, err := New(f)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("transaction", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := c.KeyedHTTP1Transactions(f, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("with-coverage", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := c.AnalyzeKeyedHTTP1(f, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
