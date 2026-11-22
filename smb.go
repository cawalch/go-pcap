package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"unicode/utf16"
)

var (
	smb2Magic  = []byte{0xfe, 'S', 'M', 'B'}
	ntlmsspSig = []byte("NTLMSSP\x00")
)

// NTLM A/V pair IDs (MS-NLMP §2.2.2.1).
const (
	ntlmAvEOL             uint16 = 0x0000
	ntlmAvNbComputerName  uint16 = 0x0001
	ntlmAvNbDomainName    uint16 = 0x0002
	ntlmAvDNSComputerName uint16 = 0x0003
	ntlmAvDNSDomainName   uint16 = 0x0004
	ntlmAvDNSTreeName     uint16 = 0x0005
)

// NTLMInfo contains metadata extracted from an NTLMSSP Negotiate (Type 1),
// Challenge (Type 2), or Authenticate (Type 3) security token.
type NTLMInfo struct {
	MessageType         uint32
	NegotiateFlags      uint32
	ServerChallenge     string
	TargetName          string
	DomainName          string
	UserName            string
	Workstation         string
	NetBIOSComputerName string
	NetBIOSDomainName   string
	DNSComputerName     string
	DNSDomainName       string
	DNSTreeName         string
}

// SMB2Message contains metadata parsed from an SMB2/3 Negotiate or Session
// Setup packet and any embedded NTLMSSP authentication token.
type SMB2Message struct {
	Command         uint16
	Status          uint32
	IsResponse      bool
	MessageID       uint64
	SessionID       uint64
	DialectRevision uint16
	SecurityMode    uint16
	SigningEnabled  bool
	SigningRequired bool
	HasNTLM         bool
	NTLM            NTLMInfo
}

// SMB2Record associates a parsed [SMB2Message] with its 5-tuple TCP flow in a
// [Capture].
type SMB2Record struct {
	FlowIndex int
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Message   SMB2Message
}

// ParseSMB2Message parses an SMB2/3 message (with or without a 4-byte NetBIOS
// Session Service header) and extracts dialect, signing, and embedded NTLMSSP
// challenge/authentication metadata.
func ParseSMB2Message(buf []byte) (SMB2Message, error) {
	if len(buf) >= 4 && buf[0] == 0x00 && !bytes.HasPrefix(buf, smb2Magic) {
		nbLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if nbLen > MaxSMB2PacketBytes {
			return SMB2Message{}, fmt.Errorf("%w: NetBIOS frame length %d exceeds %d", ErrSMBLimit, nbLen, MaxSMB2PacketBytes)
		}
		if 4+nbLen <= len(buf) {
			buf = buf[4 : 4+nbLen]
		} else {
			buf = buf[4:]
		}
	}

	if len(buf) < 64 || !bytes.HasPrefix(buf, smb2Magic) {
		return SMB2Message{}, fmt.Errorf("%w: missing 64-byte SMB2 header", ErrInvalidSMB)
	}
	structSize := binary.LittleEndian.Uint16(buf[4:6])
	if structSize != 64 {
		return SMB2Message{}, fmt.Errorf("%w: invalid SMB2 header structure size %d", ErrInvalidSMB, structSize)
	}

	status := binary.LittleEndian.Uint32(buf[8:12])
	command := binary.LittleEndian.Uint16(buf[12:14])
	flags := binary.LittleEndian.Uint32(buf[16:20])
	msgID := binary.LittleEndian.Uint64(buf[24:32])
	sessionID := binary.LittleEndian.Uint64(buf[40:48])
	isResp := (flags & 0x00000001) != 0

	msg := SMB2Message{
		Command:    command,
		Status:     status,
		IsResponse: isResp,
		MessageID:  msgID,
		SessionID:  sessionID,
	}

	body := buf[64:]
	switch command {
	case SMB2CommandNegotiate:
		if isResp && len(body) >= 64 {
			msg.SecurityMode = binary.LittleEndian.Uint16(body[2:4])
			msg.DialectRevision = binary.LittleEndian.Uint16(body[4:6])
		} else if !isResp && len(body) >= 36 {
			dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
			msg.SecurityMode = binary.LittleEndian.Uint16(body[4:6])
			if dialectCount > 0 && 36+dialectCount*2 <= len(body) {
				msg.DialectRevision = binary.LittleEndian.Uint16(body[36+(dialectCount-1)*2 : 36+dialectCount*2])
			}
		}
		msg.SigningEnabled = (msg.SecurityMode & 0x0001) != 0
		msg.SigningRequired = (msg.SecurityMode & 0x0002) != 0

	case SMB2CommandSessionSetup:
		if !isResp && len(body) >= 24 {
			msg.SecurityMode = uint16(body[3])
			msg.SigningEnabled = (msg.SecurityMode & 0x0001) != 0
			msg.SigningRequired = (msg.SecurityMode & 0x0002) != 0
		}
	}

	if ntlmIdx := bytes.Index(body, ntlmsspSig); ntlmIdx >= 0 {
		if ntlm, err := ParseNTLMSSP(body[ntlmIdx:]); err == nil {
			msg.NTLM = ntlm
			msg.HasNTLM = true
		}
	}

	return msg, nil
}

// ParseNTLMSSP parses a raw NTLMSSP (Type 1 Negotiate, Type 2 Challenge, or
// Type 3 Authenticate) security token.
func ParseNTLMSSP(token []byte) (NTLMInfo, error) {
	if len(token) < 12 || !bytes.HasPrefix(token, ntlmsspSig) {
		return NTLMInfo{}, fmt.Errorf("%w: missing NTLMSSP signature", ErrInvalidSMB)
	}
	if len(token) > MaxNTLMTokenBytes {
		return NTLMInfo{}, fmt.Errorf("%w: NTLM token length %d exceeds %d", ErrSMBLimit, len(token), MaxNTLMTokenBytes)
	}
	msgType := binary.LittleEndian.Uint32(token[8:12])
	info := NTLMInfo{MessageType: msgType}

	switch msgType {
	case NTLMNegotiateMessage:
		if len(token) < 16 {
			return NTLMInfo{}, fmt.Errorf("%w: truncated NTLM Type 1 token", ErrInvalidSMB)
		}
		info.NegotiateFlags = binary.LittleEndian.Uint32(token[12:16])
		unicode := (info.NegotiateFlags & 0x00000001) != 0
		if len(token) >= 32 {
			info.DomainName = readNTLMSecBufString(token, 16, unicode)
			info.Workstation = readNTLMSecBufString(token, 24, unicode)
		}

	case NTLMChallengeMessage:
		if len(token) < 32 {
			return NTLMInfo{}, fmt.Errorf("%w: truncated NTLM Type 2 token", ErrInvalidSMB)
		}
		info.NegotiateFlags = binary.LittleEndian.Uint32(token[20:24])
		unicode := (info.NegotiateFlags & 0x00000001) != 0
		info.TargetName = readNTLMSecBufString(token, 12, unicode)
		info.ServerChallenge = hex.EncodeToString(token[24:32])
		if len(token) >= 48 {
			if avBytes, ok := readNTLMSecBufSlice(token, 40); ok {
				parseNTLMAvPairs(avBytes, &info)
			}
		}

	case NTLMAuthenticateMessage:
		if len(token) < 60 {
			return NTLMInfo{}, fmt.Errorf("%w: truncated NTLM Type 3 token", ErrInvalidSMB)
		}
		if len(token) >= 64 {
			info.NegotiateFlags = binary.LittleEndian.Uint32(token[60:64])
		} else {
			info.NegotiateFlags = 0x00000001
		}
		unicode := (info.NegotiateFlags & 0x00000001) != 0
		info.DomainName = readNTLMSecBufString(token, 28, unicode)
		info.UserName = readNTLMSecBufString(token, 36, unicode)
		info.Workstation = readNTLMSecBufString(token, 44, unicode)

	default:
		return NTLMInfo{}, fmt.Errorf("%w: unrecognized NTLM message type %d", ErrInvalidSMB, msgType)
	}

	return info, nil
}

func readNTLMSecBufSlice(token []byte, descOffset int) ([]byte, bool) {
	if descOffset+8 > len(token) {
		return nil, false
	}
	length := int(binary.LittleEndian.Uint16(token[descOffset : descOffset+2]))
	offset := int(binary.LittleEndian.Uint32(token[descOffset+4 : descOffset+8]))
	if length <= 0 || offset < 12 || offset+length > len(token) {
		return nil, false
	}
	return token[offset : offset+length], true
}

func readNTLMSecBufString(token []byte, descOffset int, unicode bool) string {
	raw, ok := readNTLMSecBufSlice(token, descOffset)
	if !ok {
		return ""
	}
	if !unicode {
		return string(raw)
	}
	return decodeUTF16LE(raw)
}

func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u16 := make([]uint16, n)
	for i := range n {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func parseNTLMAvPairs(av []byte, info *NTLMInfo) {
	offset := 0
	count := 0
	for offset+4 <= len(av) && count < MaxNTLMAvPairs {
		count++
		avID := binary.LittleEndian.Uint16(av[offset : offset+2])
		avLen := int(binary.LittleEndian.Uint16(av[offset+2 : offset+4]))
		offset += 4
		if avID == ntlmAvEOL || offset+avLen > len(av) {
			break
		}
		val := av[offset : offset+avLen]
		offset += avLen
		switch avID {
		case ntlmAvNbComputerName:
			info.NetBIOSComputerName = decodeUTF16LE(val)
		case ntlmAvNbDomainName:
			info.NetBIOSDomainName = decodeUTF16LE(val)
		case ntlmAvDNSComputerName:
			info.DNSComputerName = decodeUTF16LE(val)
		case ntlmAvDNSDomainName:
			info.DNSDomainName = decodeUTF16LE(val)
		case ntlmAvDNSTreeName:
			info.DNSTreeName = decodeUTF16LE(val)
		}
	}
}

// SMB extracts SMB2/3 Negotiate and Session Setup messages (including embedded
// NTLMSSP tokens) across all reassembled TCP streams in the capture.
func (c *Capture) SMB(data []byte) ([]SMB2Record, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	var records []SMB2Record
	for i := range streams {
		st := &streams[i]
		if err := extractSMB2FromStream(st.Client.Data, st.FlowIndex, st.SrcAddr, st.DstAddr, st.SrcPort, st.DstPort, &records); err != nil {
			return nil, err
		}
		if err := extractSMB2FromStream(st.Server.Data, st.FlowIndex, st.DstAddr, st.SrcAddr, st.DstPort, st.SrcPort, &records); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func extractSMB2FromStream(
	stream []byte,
	flowIndex int,
	srcAddr, dstAddr netip.Addr,
	srcPort, dstPort uint16,
	records *[]SMB2Record,
) error {
	offset := 0
	for offset+68 <= len(stream) {
		var frame []byte
		if stream[offset] == 0x00 && bytes.Equal(stream[offset+4:offset+8], smb2Magic) {
			nbLen := int(stream[offset+1])<<16 | int(stream[offset+2])<<8 | int(stream[offset+3])
			if nbLen < 64 || nbLen > MaxSMB2PacketBytes || offset+4+nbLen > len(stream) {
				break
			}
			frame = stream[offset+4 : offset+4+nbLen]
			offset += 4 + nbLen
		} else if bytes.Equal(stream[offset:offset+4], smb2Magic) {
			frame = stream[offset:]
			offset = len(stream)
		} else {
			break
		}

		msg, err := ParseSMB2Message(frame)
		if err != nil {
			continue
		}
		if len(*records) >= MaxSMBRecordsPerScan {
			return fmt.Errorf("%w: exceeds %d SMB2 records", ErrSMBLimit, MaxSMBRecordsPerScan)
		}
		*records = append(*records, SMB2Record{
			FlowIndex: flowIndex,
			SrcAddr:   srcAddr,
			DstAddr:   dstAddr,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Message:   msg,
		})
	}
	return nil
}
