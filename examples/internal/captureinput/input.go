// Package captureinput opens inputs for the capture example commands.
package captureinput

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cawalch/go-pcap"
)

const maxStagedBytes = 128 << 20

// Input keeps the uncompressed source available until Close.
type Input struct {
	File      *os.File
	Capture   *pcap.Capture
	temporary bool
}

// Open reads a regular capture file directly. It stages stdin (path "-"),
// named pipes, and paths ending in .gz to disk before parsing.
func Open(path string, stdin io.Reader) (Input, error) {
	if path == "-" {
		return stage(stdin, maxStagedBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return Input{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return Input{}, err
	}
	if info.Mode()&os.ModeNamedPipe != 0 || strings.HasSuffix(path, ".gz") {
		defer func() { _ = file.Close() }()
		return stage(file, maxStagedBytes)
	}
	capture, err := pcap.NewFromReaderAt(file, info.Size())
	if err != nil {
		_ = file.Close()
		return Input{}, err
	}
	return Input{File: file, Capture: capture}, nil
}

// Close closes the source and removes its temporary file, if present.
func (in *Input) Close() error {
	err := in.File.Close()
	if in.temporary {
		return errors.Join(err, os.Remove(in.File.Name()))
	}
	return err
}

func stage(source io.Reader, limit int64) (_ Input, err error) {
	buffer := bufio.NewReader(source)
	magic, err := buffer.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return Input{}, err
	}
	var reader io.Reader = buffer
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffer)
		if err != nil {
			return Input{}, err
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	}

	file, err := os.CreateTemp("", "go-pcap-capture-*")
	if err != nil {
		return Input{}, err
	}
	input := Input{File: file, temporary: true}
	defer func() {
		if err != nil {
			_ = input.Close()
		}
	}()

	size, err := io.Copy(file, io.LimitReader(reader, limit+1))
	if err != nil {
		return Input{}, err
	}
	if size > limit {
		return Input{}, fmt.Errorf("%w: staged capture exceeds %d bytes", pcap.ErrPacketLimit, limit)
	}
	input.Capture, err = pcap.NewFromReaderAt(file, size)
	if err != nil {
		return Input{}, err
	}
	if input.Capture.InputTruncated() {
		return Input{}, io.ErrUnexpectedEOF
	}
	return input, nil
}
