package captureinput

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/cawalch/go-pcap"
)

func TestStageBudgetAndCleanup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TEMP", dir)
	t.Setenv("TMP", dir)

	var raw bytes.Buffer
	writer, err := pcap.NewPCAPWriter(&raw, pcap.LinkTypeEthernet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(1234, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	data := raw.Bytes()
	size := int64(len(data))
	for _, tc := range []struct {
		name  string
		data  []byte
		limit int64
		want  error
	}{
		{"exact-limit", data, size, nil},
		{"over-limit", data, size - 1, pcap.ErrPacketLimit},
		{"truncated", data[:size-1], size, io.ErrUnexpectedEOF},
		{"zstd-signature", []byte("\x28\xb5\x2f\xfd"), size, pcap.ErrUnsupportedZstd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, err := stage(bytes.NewReader(tc.data), tc.limit)
			if in.File != nil {
				if err := in.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(err, tc.want) || (in.File == nil) != (tc.want != nil) {
				t.Fatalf("stage returned %v, %v, want %v", in, err, tc.want)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("temporary files after staging: %v, %v", files, err)
			}
		})
	}
}
