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
	smb2Magic          = []byte{0xfe, 'S', 'M', 'B'}
	smb3TransformMagic = []byte{0xfd, 'S', 'M', 'B'}
	ntlmsspSig         = []byte("NTLMSSP\x00")
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

// SMB2Message contains observed SMB2 command or SMB3 encrypted transform metadata.
// For transforms, only IsEncrypted, OriginalMessageSize and SessionID apply.
type SMB2Message struct {
	Command             uint16
	Status              uint32
	IsResponse          bool
	IsEncrypted         bool
	TreeID              uint32 // Synchronous header tree ID; zero for asynchronous headers.
	OriginalMessageSize uint32 // Plaintext size declared in a transform header.
	ShareName           string // Full UNC path from a TREE_CONNECT request.
	FileName            string // CREATE request name, including pipe names on IPC shares.
	MessageID           uint64
	SessionID           uint64
	DialectRevision     uint16
	SecurityMode        uint16
	SigningEnabled      bool
	SigningRequired     bool
	HasNTLM             bool
	NTLM                NTLMInfo
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

// ParseSMB2Message parses the first command or encrypted transform in a raw
// or NetBIOS-framed message. [Capture.SMB] emits every command in a compound.
func ParseSMB2Message(buf []byte) (SMB2Message, error) {
	frame, _, err := splitSMBFrame(buf)
	if err != nil {
		return SMB2Message{}, err
	}
	msg, _, err := parseSMBCommand(frame)
	return msg, err
}

func splitSMBFrame(buf []byte) (frame, rest []byte, err error) {
	if len(buf) >= 4 && buf[0] == 0 {
		n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if n > MaxSMB2PacketBytes {
			return nil, nil, fmt.Errorf("%w: NetBIOS frame length %d", ErrSMBLimit, n)
		}
		if n > len(buf)-4 {
			return nil, nil, fmt.Errorf("%w: truncated NetBIOS frame", ErrInvalidSMB)
		}
		return buf[4 : 4+n], buf[4+n:], nil
	}
	return buf, nil, nil
}

func parseSMBCommand(buf []byte) (SMB2Message, []byte, error) {
	if bytes.HasPrefix(buf, smb3TransformMagic) {
		if len(buf) < 52 {
			return SMB2Message{}, nil, fmt.Errorf("%w: truncated SMB3 transform header", ErrInvalidSMB)
		}
		return SMB2Message{
			IsEncrypted:         true,
			OriginalMessageSize: binary.LittleEndian.Uint32(buf[36:40]),
			SessionID:           binary.LittleEndian.Uint64(buf[44:52]),
		}, nil, nil
	}
	if len(buf) < 64 || !bytes.HasPrefix(buf, smb2Magic) {
		return SMB2Message{}, nil, fmt.Errorf("%w: missing 64-byte SMB2 header", ErrInvalidSMB)
	}
	structSize := binary.LittleEndian.Uint16(buf[4:6])
	if structSize != 64 {
		return SMB2Message{}, nil, fmt.Errorf("%w: invalid SMB2 header structure size %d", ErrInvalidSMB, structSize)
	}

	var rest []byte
	if next := binary.LittleEndian.Uint32(buf[20:24]); next != 0 {
		if next < 64 || next%8 != 0 || uint64(next)+64 > uint64(len(buf)) {
			return SMB2Message{}, nil, fmt.Errorf("%w: invalid compound command offset %d", ErrInvalidSMB, next)
		}
		rest = buf[next:]
		buf = buf[:next]
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

	if flags&2 == 0 {
		msg.TreeID = binary.LittleEndian.Uint32(buf[36:40])
	}
	body := buf[64:]
	var fields []byte
	var minOffset int
	switch command {
	case SMB2CommandNegotiate:
		if isResp && len(body) >= 64 {
			if binary.LittleEndian.Uint16(body) == 65 {
				fields, minOffset = body[56:60], 128
			}
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

	case SMB2CommandTreeConnect:
		if !isResp {
			if len(body) < 8 || binary.LittleEndian.Uint16(body) != 9 {
				return SMB2Message{}, rest, fmt.Errorf("%w: invalid TREE_CONNECT request", ErrInvalidSMB)
			}
			minOffset := 72
			if binary.LittleEndian.Uint16(body[2:4])&4 != 0 {
				minOffset += 16 // TREE_CONNECT extension prefix.
			}
			var err error
			msg.ShareName, err = smbRequestName(buf, body[4:8], minOffset)
			if err != nil {
				return SMB2Message{}, rest, err
			}
		}
	case SMB2CommandCreate:
		if !isResp {
			if len(body) < 57 || binary.LittleEndian.Uint16(body) != 57 {
				return SMB2Message{}, rest, fmt.Errorf("%w: invalid CREATE request", ErrInvalidSMB)
			}
			if binary.LittleEndian.Uint16(body[46:48]) != 0 {
				var err error
				msg.FileName, err = smbRequestName(buf, body[44:48], 120)
				if err != nil {
					return SMB2Message{}, rest, err
				}
			}
		}

	case SMB2CommandSessionSetup:
		if !isResp && len(body) >= 24 {
			if binary.LittleEndian.Uint16(body) == 25 {
				fields, minOffset = body[12:16], 88
			}
			msg.SecurityMode = uint16(body[3])
			msg.SigningEnabled = (msg.SecurityMode & 0x0001) != 0
			msg.SigningRequired = (msg.SecurityMode & 0x0002) != 0
		} else if isResp && len(body) >= 8 && binary.LittleEndian.Uint16(body) == 9 && (status == 0 || status == 0xc0000016) {
			fields, minOffset = body[4:8], 72
		}
	}

	if fields != nil && binary.LittleEndian.Uint16(fields[2:]) != 0 {
		start := int(binary.LittleEndian.Uint16(fields))
		end := start + int(binary.LittleEndian.Uint16(fields[2:]))
		if start < minOffset || end > len(buf) {
			return SMB2Message{}, rest, fmt.Errorf("%w: invalid security buffer", ErrInvalidSMB)
		}
		body = buf[start:end]
		if ntlmIdx := bytes.Index(body, ntlmsspSig); ntlmIdx >= 0 {
			if ntlm, err := ParseNTLMSSP(body[ntlmIdx:]); err == nil {
				msg.NTLM = ntlm
				msg.HasNTLM = true
			}
		}
	}

	return msg, rest, nil
}

func smbRequestName(buf, descriptor []byte, minOffset int) (string, error) {
	offset := int(binary.LittleEndian.Uint16(descriptor))
	size := int(binary.LittleEndian.Uint16(descriptor[2:]))
	if offset < minOffset || offset%2 != 0 || size == 0 || size%2 != 0 || offset+size > len(buf) {
		return "", fmt.Errorf("%w: invalid UTF-16 name range", ErrInvalidSMB)
	}
	if size > MaxOptionStringBytes {
		return "", fmt.Errorf("%w: name length %d", ErrSMBLimit, size)
	}
	return decodeUTF16LE(buf[offset : offset+size]), nil
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
	if descOffset < 0 || len(token)-descOffset < 8 {
		return nil, false
	}
	length := uint64(binary.LittleEndian.Uint16(token[descOffset : descOffset+2]))
	offset := uint64(binary.LittleEndian.Uint32(token[descOffset+4 : descOffset+8]))
	if length == 0 || offset < 12 || offset > uint64(len(token)) || length > uint64(len(token))-offset {
		return nil, false
	}
	return token[int(offset):int(offset+length)], true
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

// SMB extracts SMB2 commands, embedded NTLMSSP metadata and SMB3 encrypted
// transform headers across the reassembled TCP streams in a capture.
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
	for len(stream) >= 4 {
		var frame []byte
		switch stream[0] {
		case 0x85:
			// NetBIOS Session Keep-Alive (4-byte header, zero payload).
			if stream[1] != 0 || stream[2] != 0 || stream[3] != 0 {
				return nil
			}
			stream = stream[4:]
			continue
		case 0x00:
			n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
			if n > len(stream)-4 {
				return nil
			}
			frame = stream[4 : 4+n]
			stream = stream[4+n:]
			if n > MaxSMB2PacketBytes {
				// Skip oversized data frames (e.g. 64 KiB+ READ/WRITE) without aborting the flow.
				continue
			}
			if !bytes.HasPrefix(frame, smb2Magic) && !bytes.HasPrefix(frame, smb3TransformMagic) {
				// Skip SMB1 Negotiate (\xffSMB), SMB3 compression (\xfcSMB), etc.
				continue
			}
		default:
			if !bytes.HasPrefix(stream, smb2Magic) && !bytes.HasPrefix(stream, smb3TransformMagic) {
				return nil
			}
			frame = stream
			stream = nil
		}
		for len(frame) > 0 {
			msg, next, err := parseSMBCommand(frame)
			frame = next
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
	}
	return nil
}
