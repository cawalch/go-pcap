package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"testing"
)

func gzipTestBytes(t testing.TB, data []byte, repeats int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	for range repeats {
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecompressCapture(t *testing.T) {
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 12345, 443, 1, 0, TCPFlagACK, nil)
	for _, raw := range [][]byte{buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{frame}), buildPCAPNGFixture(binary.BigEndian, nil, [][]byte{frame})} {
		plain, err := DecompressCapture(raw)
		if err != nil || &plain[0] != &raw[0] {
			t.Fatal("plain input ownership", err)
		}
		packed := gzipTestBytes(t, raw, 1)
		members := append(gzipTestBytes(t, raw[:8], 1), gzipTestBytes(t, raw[8:], 1)...)
		for _, input := range [][]byte{packed, members} {
			data, err := DecompressCapture(input)
			if err != nil || !bytes.Equal(data, raw) {
				t.Fatal("capture bytes differ", err)
			}
			c, err := New(data)
			if err != nil {
				t.Fatal(err)
			}
			records, err := c.Packets(data)
			if err != nil || len(records) != 1 {
				t.Fatal(len(records), err)
			}
			payload, err := c.PacketPayload(data, records[0])
			if err != nil || !bytes.Equal(payload, frame) {
				t.Fatal("wrong packet offset", err)
			}
		}
	}
}

func TestDecompressCaptureBounds(t *testing.T) {
	empty, err := DecompressCapture(nil)
	if err != nil || empty != nil {
		t.Fatal(empty, err)
	}
	good := gzipTestBytes(t, []byte("ok"), 1)
	bad := bytes.Clone(good)
	bad[len(bad)-8] ^= 1
	for _, input := range [][]byte{{0x1f, 0x8b}, {0x1f, 0x8b, 7}, good[:len(good)-1], bad, append(bytes.Clone(good), bad...)} {
		if out, err := DecompressCapture(input); err == nil || out != nil {
			t.Fatal("accepted invalid gzip")
		}
	}
	block := make([]byte, 64<<10)
	limit := gzipTestBytes(t, block, MaxDecompressedCaptureBytes/len(block))
	if out, err := DecompressCapture(limit); err != nil || len(out) != MaxDecompressedCaptureBytes {
		t.Fatal(len(out), err)
	}
	if out, err := DecompressCapture(append(limit, gzipTestBytes(t, []byte{1}, 1)...)); !errors.Is(err, ErrPacketLimit) || out != nil {
		t.Fatal("combined limit", err)
	}
}

func BenchmarkCaptureGzip(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 12345, 443, 1, 0, TCPFlagACK, make([]byte, 128))
	frames := make([][]byte, 256)
	for i := range frames {
		frames[i] = frame
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	compressed := gzipTestBytes(b, raw, 1)
	for _, tc := range []struct {
		name  string
		input []byte
	}{{"Plain", raw}, {"Gzip", compressed}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				data, err := DecompressCapture(tc.input)
				if err != nil {
					b.Fatal(err)
				}
				c, err := New(data)
				if err != nil || c.PacketCount != len(frames) {
					b.Fatal("capture indexing failed", err)
				}
			}
		})
	}
}
