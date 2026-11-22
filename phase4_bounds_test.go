package pcap

import (
	"bytes"
	"errors"
	"testing"
)

func TestPhase4BoundsAndErrorPaths(t *testing.T) {
	// 1. ReaderAt bounds checks.
	if _, err := NewFromReaderAt(nil, 100); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewFromReaderAt(nil) err = %v, want ErrInvalidHeader", err)
	}
	if _, err := NewFromReaderAt(bytes.NewReader([]byte{1, 2}), 2); !errors.Is(err, ErrNotPCAP) {
		t.Fatalf("NewFromReaderAt(2B) err = %v, want ErrNotPCAP", err)
	}

	// 2. PCAPNGWriter nil and oversize checks.
	if _, err := NewPCAPNGWriter(nil, PCAPNGWriterOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewPCAPNGWriter(nil) err = %v, want ErrInvalidHeader", err)
	}
	if _, err := NewPCAPNGWriter(&bytes.Buffer{}, PCAPNGWriterOptions{SnapLen: MaxSnapLen + 1}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewPCAPNGWriter(oversize snaplen) err = %v, want ErrInvalidHeader", err)
	}

	// 3. ParseBPFBuffer bounds checks.
	var badBPF [18]byte
	badBPF[16] = 10 // hdrLen = 10 < 18
	if _, err := ParseBPFBuffer(badBPF[:], LinkTypeEthernet); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("ParseBPFBuffer(hdrLen < 18) err = %v, want ErrInvalidPacket", err)
	}

	// 4. OpenLive validation checks.
	if _, err := OpenLive("", LiveOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("OpenLive(\"\") err = %v, want ErrInvalidHeader", err)
	}
	if _, err := OpenLive("lo0", LiveOptions{SnapLen: MaxSnapLen + 1}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("OpenLive(oversize snaplen) err = %v, want ErrInvalidHeader", err)
	}

	// 5. SMB2 and NTLM bounds checks.
	if _, err := ParseSMB2Message([]byte("short")); !errors.Is(err, ErrInvalidSMB) {
		t.Fatalf("ParseSMB2Message(short) err = %v, want ErrInvalidSMB", err)
	}
	if _, err := ParseNTLMSSP([]byte("NOT_NTLM_12345")); !errors.Is(err, ErrInvalidSMB) {
		t.Fatalf("ParseNTLMSSP(bad sig) err = %v, want ErrInvalidSMB", err)
	}
}
