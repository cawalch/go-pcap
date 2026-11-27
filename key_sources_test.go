package pcap

import (
	"bytes"
	"fmt"
	"testing"
)

func TestTLSKeyLogSelection(t *testing.T) {
	var random [32]byte
	embedded := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %064x\n", random, 1)
	external := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %064x\nSERVER_TRAFFIC_SECRET_0 %x %064x\n", random, 2, random, 3)
	raw := keyedCapture(t, append(embedded, embedded...), nil)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	local, err := c.TLSKeyLog(nil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := c.TLSKeyLog(external)
	if err != nil {
		t.Fatal(err)
	}
	a, b := local.Entries[random], merged.Entries[random]
	if len(a.ClientTrafficSecret0) != 32 || len(a.ServerTrafficSecret0) != 0 ||
		len(b.ClientTrafficSecret0) != 32 || len(b.ServerTrafficSecret0) != 32 ||
		a.ClientTrafficSecret0[31] != 1 || b.ClientTrafficSecret0[31] != 2 || b.ServerTrafficSecret0[31] != 3 {
		t.Fatal("unexpected key selection")
	}
	without := *c
	without.Secrets = nil
	empty, err := without.TLSKeyLog(nil)
	if err != nil || len(empty.Entries) != 0 {
		t.Fatal("passive view retained keys", err)
	}
}

func TestTLSKeyLogCaptureModes(t *testing.T) {
	tls := newKeyedFixture(t, TLSVersion13)
	tls.pipeline()
	quic, quicKeys := keyedQUICFixture(t, 1)
	var buf bytes.Buffer
	w, err := NewPCAPNGWriter(&buf, PCAPNGWriterOptions{LinkType: LinkTypeRaw})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(SecretsTypeTLSKeyLog, quicKeys); err != nil {
		t.Fatal(err)
	}
	for _, frame := range keyedQUICFrames(t, quic) {
		if err := w.WritePacket(PacketRecord{}, frame); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		keys []byte
		scan func(*Capture, []byte, []byte) (int, error)
	}{
		{"TLS", keyedCapture(t, tls.keys, tls.packets), tls.keys, func(c *Capture, raw, keys []byte) (int, error) {
			rows, err := c.KeyedHTTP1Transactions(raw, keys)
			return len(rows), err
		}},
		{"QUIC", buf.Bytes(), quicKeys, func(c *Capture, raw, keys []byte) (int, error) {
			rows, err := c.KeyedQUIC(raw, keys)
			return len(rows), err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			passive := *c
			passive.Secrets = nil
			for _, mode := range []struct {
				name string
				view *Capture
				keys []byte
				want bool
			}{
				{"passive", &passive, nil, false},
				{"embedded", c, nil, true},
				{"external", &passive, tc.keys, true},
				{"combined", c, tc.keys, true},
			} {
				t.Run(mode.name, func(t *testing.T) {
					t.Parallel()
					n, err := tc.scan(mode.view, tc.raw, mode.keys)
					if err != nil || (n > 0) != mode.want {
						t.Fatalf("got %d evidence rows, err=%v", n, err)
					}
				})
			}

			var export bytes.Buffer
			if err := c.ExtractFlowPacketsPCAPNG(tc.raw, &export, 0); err != nil {
				t.Fatal(err)
			}
			output, err := New(export.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if len(output.Secrets) != 0 {
				t.Fatal("packet-only export retained secrets")
			}
			n, err := tc.scan(output, export.Bytes(), nil)
			if err != nil || n != 0 {
				t.Fatalf("keyless export got %d rows, err=%v", n, err)
			}
			n, err = tc.scan(output, export.Bytes(), tc.keys)
			if err != nil || n == 0 {
				t.Fatalf("export with external keys got %d rows, err=%v", n, err)
			}
		})
	}
}
