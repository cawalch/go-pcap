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

	// Loopback SSH flow (identical src/dst IP, distinct ports) must classify server packets separately for JA4SSH.
	lp1 := buildEthernetIPv4TCPFrame([4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 52222, 22, 1, 1, TCPFlagPSH|TCPFlagACK, cStream)
	lp2 := buildEthernetIPv4TCPFrame([4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 22, 52222, 1, 1+uint32(len(cStream)), TCPFlagPSH|TCPFlagACK, sStream)
	loopPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{lp1, lp2})
	loopCap, err := New(loopPCAP)
	if err != nil {
		t.Fatalf("New(loopback) error = %v", err)
	}
	loopRecords, err := loopCap.SSH(loopPCAP)
	if err != nil || len(loopRecords) != 1 {
		t.Fatalf("loopCap.SSH() = (%+v, %v)", loopRecords, err)
	}
	if loopRecords[0].JA4SSH != sshRecords[0].JA4SSH {
		t.Fatalf("loopback JA4SSH = %q, want %q", loopRecords[0].JA4SSH, sshRecords[0].JA4SSH)
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

func TestSSHJA4SSHCrossesSegmentBoundary(t *testing.T) {
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

	// Build a session with > MaxSegmentsPerFlow total packets across both directions
	// (2,100 per direction stays within per-direction MaxSegmentsPerFlow for Streams(),
	// while total packets = 4,200 > 4,096).
	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{10, 0, 0, 2}
	cSeq := uint32(1)
	sSeq := uint32(1)
	frames := make([][]byte, 0, 4210)
	frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, 52222, 22, cSeq, sSeq, TCPFlagPSH|TCPFlagACK, cStream))
	cSeq += uint32(len(cStream))
	frames = append(frames, buildEthernetIPv4TCPFrame(dst, src, 22, 52222, sSeq, cSeq, TCPFlagPSH|TCPFlagACK, sStream))
	sSeq += uint32(len(sStream))

	// 2,050 bare ACKs in each direction (4,100 bare ACKs total, pushing past 4,096 packets).
	for range 2050 {
		frames = append(frames,
			buildEthernetIPv4TCPFrame(src, dst, 52222, 22, cSeq, sSeq, TCPFlagACK, nil),
			buildEthernetIPv4TCPFrame(dst, src, 22, 52222, sSeq, cSeq, TCPFlagACK, nil),
		)
	}
	// Trailing data packets past packet 4,096 that establish new modal lengths (36 client, 52 server).
	cData := make([]byte, 36)
	sData := make([]byte, 52)
	for range 5 {
		frames = append(frames, buildEthernetIPv4TCPFrame(src, dst, 52222, 22, cSeq, sSeq, TCPFlagPSH|TCPFlagACK, cData))
		cSeq += uint32(len(cData))
		frames = append(frames, buildEthernetIPv4TCPFrame(dst, src, 22, 52222, sSeq, cSeq, TCPFlagPSH|TCPFlagACK, sData))
		sSeq += uint32(len(sData))
	}

	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := c.SSH(raw)
	if err != nil || len(records) != 1 {
		t.Fatalf("cap.SSH() = (%+v, %v)", records, err)
	}
	const want = "c36s52_c6s6_c2050s2050"
	if records[0].JA4SSH != want {
		t.Fatalf("JA4SSH = %q, want %q", records[0].JA4SSH, want)
	}
}
