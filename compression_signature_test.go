package pcap

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureCompressionSignatures(t *testing.T) {
	xz := []byte("\xfd\x37\x7a\x58\x5a\x00")
	for _, tc := range []struct {
		name  string
		input []byte
		want  error
	}{
		{"zstd", []byte("\x28\xb5\x2f\xfd"), ErrUnsupportedZstd},
		{"xz", xz, ErrUnsupportedXZ},
		{"short xz", xz[:5], ErrInvalidMagic},
		{"wrong xz suffix", []byte("\xfd\x37\x7a\x58\x5a\x01"), ErrInvalidMagic},
		{"skippable frame", []byte("\x50\x2a\x4d\x18\x00\x00\x00\x00"), ErrInvalidMagic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(api string, c *Capture, err error) {
				t.Helper()
				if c != nil || !errors.Is(err, tc.want) ||
					!errors.Is(err, ErrNotPCAP) || !errors.Is(err, ErrInvalidMagic) ||
					errors.Is(err, ErrUnsupportedZstd) != errors.Is(tc.want, ErrUnsupportedZstd) ||
					errors.Is(err, ErrUnsupportedXZ) != errors.Is(tc.want, ErrUnsupportedXZ) {
					t.Fatalf("%s returned (%v, %v), want nil capture and %v", api, c, err, tc.want)
				}
			}

			c, err := New(tc.input)
			check("New", c, err)
			c, err = NewWithLength(tc.input, int64(len(tc.input))+16)
			check("NewWithLength", c, err)
			c, err = NewFromReaderAt(bytes.NewReader(tc.input), int64(len(tc.input)))
			check("NewFromReaderAt", c, err)
			path := filepath.Join(t.TempDir(), "capture")
			if err := os.WriteFile(path, tc.input, 0o600); err != nil {
				t.Fatal(err)
			}
			c, err = Open(path)
			check("Open", c, err)

			out, err := DecompressCapture(tc.input)
			if err != nil || len(out) != len(tc.input) || &out[0] != &tc.input[0] {
				t.Fatalf("DecompressCapture returned (%x, %v), want the original input", out, err)
			}
		})
	}
}

func TestReaderAtXZSignatureRead(t *testing.T) {
	readErr := errors.New("suffix read failed")
	var reads int
	r := readAtFunc(func(p []byte, off int64) (int, error) {
		reads++
		switch {
		case off == 0 && len(p) == 4:
			return copy(p, "\xfd\x37\x7a\x58"), nil
		case off == 4 && len(p) == 2:
			return 0, readErr
		default:
			t.Fatalf("unexpected read of %d bytes at %d", len(p), off)
			return 0, readErr
		}
	})

	c, err := NewFromReaderAt(r, 5)
	if reads != 1 || c != nil || !errors.Is(err, ErrInvalidMagic) || errors.Is(err, ErrUnsupportedXZ) {
		t.Fatalf("short ReaderAt returned (%v, %v) after %d reads", c, err, reads)
	}
	reads = 0
	c, err = NewFromReaderAt(r, 6)
	if reads != 2 || c != nil || !errors.Is(err, readErr) || !errors.Is(err, ErrNotPCAP) ||
		!errors.Is(err, ErrInvalidMagic) || errors.Is(err, ErrUnsupportedXZ) {
		t.Fatalf("failing ReaderAt returned (%v, %v) after %d reads", c, err, reads)
	}
}
