package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"
)

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], v)
	}
	return out
}

func buildSMB2SessionSetupNTLMChallenge() []byte {
	targetUTF16 := encodeUTF16LE("CORP")
	var av bytes.Buffer
	writeAv := func(id uint16, s string) {
		b := encodeUTF16LE(s)
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(b)))
		av.Write(hdr[:])
		av.Write(b)
	}
	writeAv(ntlmAvNbDomainName, "CORP")
	writeAv(ntlmAvNbComputerName, "DC01")
	writeAv(ntlmAvDNSDomainName, "corp.example.com")
	writeAv(ntlmAvDNSComputerName, "dc01.corp.example.com")
	av.Write([]byte{0, 0, 0, 0})

	targetOff := 56
	avOff := targetOff + len(targetUTF16)
	token := make([]byte, avOff+av.Len())
	copy(token[0:8], ntlmsspSig)
	binary.LittleEndian.PutUint32(token[8:12], NTLMChallengeMessage)
	binary.LittleEndian.PutUint16(token[12:14], uint16(len(targetUTF16)))
	binary.LittleEndian.PutUint16(token[14:16], uint16(len(targetUTF16)))
	binary.LittleEndian.PutUint32(token[16:20], uint32(targetOff))
	binary.LittleEndian.PutUint32(token[20:24], 0x00000001)
	copy(token[24:32], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	binary.LittleEndian.PutUint16(token[40:42], uint16(av.Len()))
	binary.LittleEndian.PutUint16(token[42:44], uint16(av.Len()))
	binary.LittleEndian.PutUint32(token[44:48], uint32(avOff))
	copy(token[targetOff:], targetUTF16)
	copy(token[avOff:], av.Bytes())

	smbLen := 64 + 8 + len(token)
	pkt := make([]byte, 4+smbLen)
	pkt[0] = 0x00
	pkt[1] = byte(smbLen >> 16)
	pkt[2] = byte(smbLen >> 8)
	pkt[3] = byte(smbLen)

	smb := pkt[4:]
	copy(smb[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(smb[4:6], 64)
	binary.LittleEndian.PutUint32(smb[8:12], 0xc0000016)
	binary.LittleEndian.PutUint16(smb[12:14], SMB2CommandSessionSetup)
	binary.LittleEndian.PutUint32(smb[16:20], 0x00000001)
	binary.LittleEndian.PutUint64(smb[24:32], 1)
	binary.LittleEndian.PutUint64(smb[40:48], 0xdeadbeef)
	copy(smb[64+8:], token)
	return pkt
}

func TestSMB2AndNTLMSSPDissector(t *testing.T) {
	pkt := buildSMB2SessionSetupNTLMChallenge()
	msg, err := ParseSMB2Message(pkt)
	if err != nil {
		t.Fatalf("ParseSMB2Message() error = %v", err)
	}
	if !msg.IsResponse || msg.Command != SMB2CommandSessionSetup || !msg.HasNTLM {
		t.Fatalf("SMB2Message = %+v", msg)
	}
	ntlm := msg.NTLM
	if ntlm.MessageType != NTLMChallengeMessage ||
		ntlm.ServerChallenge != "1122334455667788" ||
		ntlm.TargetName != "CORP" ||
		ntlm.NetBIOSComputerName != "DC01" ||
		ntlm.DNSComputerName != "dc01.corp.example.com" ||
		ntlm.DNSDomainName != "corp.example.com" {
		t.Fatalf("NTLMInfo = %+v", ntlm)
	}

	p1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 1}, 445, 51000, 1, 1, TCPFlagPSH|TCPFlagACK, pkt)
	rawPCAP := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{p1})
	cap, err := New(rawPCAP)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := cap.SMB(rawPCAP)
	if err != nil || len(records) != 1 || !records[0].Message.HasNTLM {
		t.Fatalf("cap.SMB() = (%+v, %v)", records, err)
	}
}

func TestSMB2AndNTLMBounds(t *testing.T) {
	if _, err := ParseSMB2Message([]byte("short")); !errors.Is(err, ErrInvalidSMB) {
		t.Fatalf("ParseSMB2Message(short) err = %v, want ErrInvalidSMB", err)
	}
	if _, err := ParseNTLMSSP([]byte("NOT_NTLM_12345")); !errors.Is(err, ErrInvalidSMB) {
		t.Fatalf("ParseNTLMSSP(bad sig) err = %v, want ErrInvalidSMB", err)
	}
}
