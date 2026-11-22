package pcap

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestQUICBoundsAndMalformedPackets(t *testing.T) {
	if _, _, ok := ReadQUICVarint(nil); ok {
		t.Fatal("ReadQUICVarint(nil) = true, want false")
	}
	if _, _, ok := ReadQUICVarint([]byte{0x40}); ok {
		t.Fatal("ReadQUICVarint(truncated 2B) = true, want false")
	}
	if _, err := ParseQUICInitialPacket([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(short) err = %v, want ErrInvalidQUIC", err)
	}
	// Short header bit (0x40 instead of 0xc0).
	if _, err := ParseQUICInitialPacket([]byte{0x40, 0, 0, 0, 1, 0, 0}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(short header) err = %v, want ErrInvalidQUIC", err)
	}
	// Unsupported QUIC version.
	if _, err := ParseQUICInitialPacket([]byte{0xc0, 0xde, 0xad, 0xbe, 0xef, 0, 0}); !errors.Is(err, ErrInvalidQUIC) {
		t.Fatalf("ParseQUICInitialPacket(bad version) err = %v, want ErrInvalidQUIC", err)
	}
	// Too many datagrams (> MaxQUICPacketsPerFlow).
	tooMany := make([][]byte, MaxQUICPacketsPerFlow+1)
	if _, err := DecryptQUICInitial(tooMany); !errors.Is(err, ErrQUICLimit) {
		t.Fatalf("DecryptQUICInitial(tooMany) err = %v, want ErrQUICLimit", err)
	}
}

func TestHTTPBoundsAndLimits(t *testing.T) {
	if _, _, err := ParseHTTPRequest([]byte("INVALID_Method / HTTP/1.1\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPRequest(bad method) err = %v, want ErrInvalidHTTP", err)
	}
	if _, _, err := ParseHTTPRequest([]byte("GET / HTTP/2.0\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPRequest(HTTP/2.0) err = %v, want ErrInvalidHTTP", err)
	}

	// Exceed MaxHTTPHeaders.
	var hdrBomb bytes.Buffer
	hdrBomb.WriteString("GET / HTTP/1.1\r\n")
	for range MaxHTTPHeaders + 1 {
		hdrBomb.WriteString("X-Test: 1\r\n")
	}
	hdrBomb.WriteString("\r\n")
	if _, _, err := ParseHTTPRequest(hdrBomb.Bytes()); !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("ParseHTTPRequest(header bomb) err = %v, want ErrHTTPLimit", err)
	}

	if _, _, err := ParseHTTPResponse([]byte("HTTP/1.1 999 Bad\r\n\r\n")); !errors.Is(err, ErrInvalidHTTP) {
		t.Fatalf("ParseHTTPResponse(status 999) err = %v, want ErrInvalidHTTP", err)
	}
}

func TestSSHBoundsAndMalformedInputs(t *testing.T) {
	if _, err := ParseSSHHandshake([]byte("NOT_SSH\r\n"), nil); !errors.Is(err, ErrInvalidSSH) {
		t.Fatalf("ParseSSHHandshake(non-SSH) err = %v, want ErrInvalidSSH", err)
	}
	longBanner := "SSH-2.0-" + strings.Repeat("A", MaxSSHBannerBytes+10) + "\r\n"
	if _, err := ParseSSHHandshake([]byte(longBanner), nil); !errors.Is(err, ErrInvalidSSH) {
		t.Fatalf("ParseSSHHandshake(oversize banner) err = %v, want ErrInvalidSSH", err)
	}
}
