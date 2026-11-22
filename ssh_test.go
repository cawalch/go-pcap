package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func buildSSHKexStream(banner string, kex, hostKey, enc, mac, comp string) []byte {
	var payload bytes.Buffer
	payload.WriteByte(sshMsgKexInit)
	payload.Write(bytes.Repeat([]byte{0x11}, 16))
	lists := [10]string{kex, hostKey, enc, enc, mac, mac, comp, comp, "", ""}
	for _, s := range lists {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		payload.Write(l[:])
		payload.WriteString(s)
	}
	payload.WriteByte(0)
	payload.Write([]byte{0, 0, 0, 0})

	padLen := 8 - ((5 + payload.Len()) % 8)
	if padLen < 4 {
		padLen += 8
	}
	pktLen := 1 + payload.Len() + padLen

	var stream bytes.Buffer
	stream.WriteString(banner + "\r\n")
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(pktLen))
	hdr[4] = byte(padLen)
	stream.Write(hdr[:])
	stream.Write(payload.Bytes())
	stream.Write(make([]byte, padLen))
	return stream.Bytes()
}

func TestSSHHandshakeAndHASSH(t *testing.T) {
	cStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6",
		"curve25519-sha256",
		"ssh-ed25519",
		"chacha20-poly1305@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)
	sStream := buildSSHKexStream(
		"SSH-2.0-OpenSSH_9.6p1",
		"curve25519-sha256",
		"ssh-ed25519",
		"aes128-gcm@openssh.com",
		"umac-128-etm@openssh.com",
		"none",
	)

	hs, err := ParseSSHHandshake(cStream, sStream)
	if err != nil {
		t.Fatalf("ParseSSHHandshake() error = %v", err)
	}
	if hs.ClientBanner != "SSH-2.0-OpenSSH_9.6" || hs.ServerBanner != "SSH-2.0-OpenSSH_9.6p1" {
		t.Fatalf("Banners = (%q, %q)", hs.ClientBanner, hs.ServerBanner)
	}
	const wantHASSH = "8663e68f847e5181dd867c4a2a1965d8"
	const wantHASSHServer = "a50b379f2b9cfcd7139b986d901f42c2"
	if hs.HASSH != wantHASSH || hs.HASSHServer != wantHASSHServer {
		t.Fatalf("HASSH = (%q, %q), want (%q, %q)", hs.HASSH, hs.HASSHServer, wantHASSH, wantHASSHServer)
	}

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 52222, 22, 1, 1, TCPFlagPSH|TCPFlagACK, cStream)
	p2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 22, 52222, 1, 1+uint32(len(cStream)), TCPFlagPSH|TCPFlagACK, sStream)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{p1, p2})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	sshRecords, err := cap.SSH(rawPCAP)
	if err != nil || len(sshRecords) != 1 || sshRecords[0].Handshake.HASSH != wantHASSH {
		t.Fatalf("cap.SSH() = (%+v, %v)", sshRecords, err)
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
