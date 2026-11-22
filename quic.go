package pcap

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// RFC 9001 §5.2 (QUIC v1) and RFC 9369 §4.3 (QUIC v2) Initial salts.
var (
	quicV1InitialSalt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2InitialSalt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

// QUICInitialHeader contains the unencrypted long-header metadata of a QUIC v1
// or QUIC v2 Initial packet.
type QUICInitialHeader struct {
	FirstByte     uint8
	Version       uint32
	DCID          []byte
	SCID          []byte
	Token         []byte
	HeaderOffset  int
	PayloadOffset int
	PayloadLength int
	PacketLength  int
}

// QUICHandshake contains the decrypted metadata and embedded TLS 1.3
// ClientHello/ServerHello (with 'q13...' JA4/JA4S) of a QUIC Initial exchange.
type QUICHandshake struct {
	Version        uint32
	DCID           []byte
	SCID           []byte
	Token          []byte
	HasClientHello bool
	HasServerHello bool
	ClientHello    TLSClientHello
	ServerHello    TLSServerHello
	Anomalies      TLSAnomalies
}

// QUICRecord associates a parsed [QUICHandshake] with its 5-tuple UDP flow in
// a [Capture].
type QUICRecord struct {
	FlowIndex int
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Handshake QUICHandshake
}

// ReadQUICVarint decodes a RFC 9000 §16 variable-length integer from buf.
// It returns (value, bytesConsumed, true) on success, or (0, 0, false) if buf
// is too short.
func ReadQUICVarint(buf []byte) (uint64, int, bool) {
	if len(buf) == 0 {
		return 0, 0, false
	}
	prefix := buf[0] >> 6
	length := 1 << prefix
	if len(buf) < length {
		return 0, 0, false
	}
	v := uint64(buf[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(buf[i])
	}
	return v, length, true
}

// ParseQUICInitialPacket parses the outer unencrypted long header of the first
// QUIC v1 or QUIC v2 Initial packet in datagram without decrypting its payload.
func ParseQUICInitialPacket(datagram []byte) (QUICInitialHeader, error) {
	if len(datagram) < 7 {
		return QUICInitialHeader{}, fmt.Errorf("%w: datagram shorter than minimum QUIC long header", ErrInvalidQUIC)
	}
	first := datagram[0]
	// Header Form bit (0x80) and Fixed Bit (0x40) must be set.
	if (first & 0xc0) != 0xc0 {
		return QUICInitialHeader{}, fmt.Errorf("%w: not a QUIC long header packet", ErrInvalidQUIC)
	}
	version := binary.BigEndian.Uint32(datagram[1:5])
	longType := (first & 0x30) >> 4
	switch version {
	case QUICVersion1:
		if longType != 0x00 {
			return QUICInitialHeader{}, fmt.Errorf("%w: QUIC v1 long packet type %d is not Initial (0)", ErrInvalidQUIC, longType)
		}
	case QUICVersion2:
		if longType != 0x01 {
			return QUICInitialHeader{}, fmt.Errorf("%w: QUIC v2 long packet type %d is not Initial (1)", ErrInvalidQUIC, longType)
		}
	default:
		return QUICInitialHeader{}, fmt.Errorf("%w: unsupported QUIC version %#08x", ErrInvalidQUIC, version)
	}

	offset := 5
	dcidLen := int(datagram[offset])
	offset++
	if dcidLen > MaxQUICConnIDBytes || offset+dcidLen+1 > len(datagram) {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid DCID length %d", ErrInvalidQUIC, dcidLen)
	}
	dcid := bytes.Clone(datagram[offset : offset+dcidLen])
	offset += dcidLen

	scidLen := int(datagram[offset])
	offset++
	if scidLen > MaxQUICConnIDBytes || offset+scidLen > len(datagram) {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid SCID length %d", ErrInvalidQUIC, scidLen)
	}
	scid := bytes.Clone(datagram[offset : offset+scidLen])
	offset += scidLen

	tokenLen, n, ok := ReadQUICVarint(datagram[offset:])
	if !ok || tokenLen > MaxQUICTokenBytes || offset+n+int(tokenLen) > len(datagram) {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid QUIC Initial token length", ErrInvalidQUIC)
	}
	offset += n
	var token []byte
	if tokenLen > 0 {
		token = bytes.Clone(datagram[offset : offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	remLen, n, ok := ReadQUICVarint(datagram[offset:])
	if !ok || remLen < 20 || offset+n+int(remLen) > len(datagram) {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid QUIC Initial payload length", ErrInvalidQUIC)
	}
	offset += n
	pktLen := offset + int(remLen)

	return QUICInitialHeader{
		FirstByte:     first,
		Version:       version,
		DCID:          dcid,
		SCID:          scid,
		Token:         token,
		HeaderOffset:  0,
		PayloadOffset: offset,
		PayloadLength: int(remLen),
		PacketLength:  pktLen,
	}, nil
}

type quicInitialKeys struct {
	aead cipher.AEAD
	hp   cipher.Block
	iv   [12]byte
}

func deriveQUICInitialKeys(dcid []byte, version uint32, isClient bool) (quicInitialKeys, error) {
	salt := quicV1InitialSalt
	keyLabel := "quic key"
	ivLabel := "quic iv"
	hpLabel := "quic hp"
	if version == QUICVersion2 {
		salt = quicV2InitialSalt
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return quicInitialKeys{}, err
	}
	dirLabel := "server in"
	if isClient {
		dirLabel = "client in"
	}
	trafficSecret, err := tls13ExpandLabelSHA256(initialSecret, dirLabel, nil, 32)
	if err != nil {
		return quicInitialKeys{}, err
	}
	key, err := tls13ExpandLabelSHA256(trafficSecret, keyLabel, nil, 16)
	if err != nil {
		return quicInitialKeys{}, err
	}
	ivSlice, err := tls13ExpandLabelSHA256(trafficSecret, ivLabel, nil, 12)
	if err != nil {
		return quicInitialKeys{}, err
	}
	hpKey, err := tls13ExpandLabelSHA256(trafficSecret, hpLabel, nil, 16)
	if err != nil {
		return quicInitialKeys{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return quicInitialKeys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return quicInitialKeys{}, err
	}
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return quicInitialKeys{}, err
	}

	var out quicInitialKeys
	out.aead = aead
	out.hp = hpBlock
	copy(out.iv[:], ivSlice)
	return out, nil
}

func tls13ExpandLabelSHA256(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// RFC 8446 §7.1 HkdfLabel structure:
	// uint16 length
	// opaque label<7..255> = "tls13 " + label
	// opaque context<0..255>
	fullLabel := "tls13 " + label
	var info [64]byte
	b := info[:0]
	b = append(b, byte(length>>8), byte(length))
	b = append(b, byte(len(fullLabel)))
	b = append(b, fullLabel...)
	b = append(b, byte(len(context)))
	b = append(b, context...)
	return hkdf.Expand(sha256.New, secret, string(b), length)
}

func decryptSingleQUICInitial(pkt []byte, hdr QUICInitialHeader, keys quicInitialKeys) ([]byte, error) {
	// Sample starts 4 bytes after the start of the Packet Number field (hdr.PayloadOffset + 4).
	sampleOffset := hdr.PayloadOffset + 4
	if sampleOffset+16 > hdr.PacketLength || hdr.PacketLength > len(pkt) {
		return nil, fmt.Errorf("%w: QUIC Initial packet too short for header protection sample", ErrInvalidQUIC)
	}

	var mask [16]byte
	keys.hp.Encrypt(mask[:], pkt[sampleOffset:sampleOffset+16])

	unmaskedFirst := hdr.FirstByte ^ (mask[0] & 0x0f)
	pnLen := int(unmaskedFirst&0x03) + 1
	if hdr.PayloadOffset+pnLen+16 > hdr.PacketLength {
		return nil, fmt.Errorf("%w: QUIC Initial payload too short for packet number and AEAD tag", ErrInvalidQUIC)
	}

	// Copy header + packet number to construct Associated Data (AAD) and unmask PN.
	aad := make([]byte, hdr.PayloadOffset+pnLen)
	copy(aad, pkt[:hdr.PayloadOffset+pnLen])
	aad[0] = unmaskedFirst
	var pn uint64
	for i := range pnLen {
		aad[hdr.PayloadOffset+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(aad[hdr.PayloadOffset+i])
	}

	nonce := keys.iv
	for i := range 8 {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}

	ciphertext := pkt[hdr.PayloadOffset+pnLen : hdr.PacketLength]
	plaintext, err := keys.aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: QUIC Initial AEAD decryption failed: %w", ErrInvalidQUIC, err)
	}
	return plaintext, nil
}

type quicCryptoChunk struct {
	offset uint64
	data   []byte
}

func extractQUICCryptoFrames(plaintext []byte, chunks *[]quicCryptoChunk) error {
	i := 0
	for i < len(plaintext) {
		frameType, n, ok := ReadQUICVarint(plaintext[i:])
		if !ok {
			return fmt.Errorf("%w: truncated QUIC frame type", ErrInvalidQUIC)
		}
		i += n

		switch frameType {
		case 0x00, 0x01:
			// PADDING (0x00) or PING (0x01): 1 byte, already consumed.
		case 0x02, 0x03:
			// ACK frame (0x02 or 0x03 with ECN counts).
			_, n1, ok1 := ReadQUICVarint(plaintext[i:])
			if !ok1 {
				return ErrInvalidQUIC
			}
			i += n1
			_, n2, ok2 := ReadQUICVarint(plaintext[i:])
			if !ok2 {
				return ErrInvalidQUIC
			}
			i += n2
			ackRangeCount, n3, ok3 := ReadQUICVarint(plaintext[i:])
			if !ok3 || ackRangeCount > 256 {
				return ErrInvalidQUIC
			}
			i += n3
			_, n4, ok4 := ReadQUICVarint(plaintext[i:])
			if !ok4 {
				return ErrInvalidQUIC
			}
			i += n4
			for range ackRangeCount {
				_, ng, okg := ReadQUICVarint(plaintext[i:])
				if !okg {
					return ErrInvalidQUIC
				}
				i += ng
				_, nr, okr := ReadQUICVarint(plaintext[i:])
				if !okr {
					return ErrInvalidQUIC
				}
				i += nr
			}
			if frameType == 0x03 {
				for range 3 {
					_, ne, oke := ReadQUICVarint(plaintext[i:])
					if !oke {
						return ErrInvalidQUIC
					}
					i += ne
				}
			}
		case 0x06:
			// CRYPTO frame: Offset (varint), Length (varint), Crypto Data.
			cryptoOff, n1, ok1 := ReadQUICVarint(plaintext[i:])
			if !ok1 {
				return ErrInvalidQUIC
			}
			i += n1
			cryptoLen, n2, ok2 := ReadQUICVarint(plaintext[i:])
			if !ok2 || cryptoOff+cryptoLen > MaxQUICCryptoBytes || i+n2+int(cryptoLen) > len(plaintext) {
				return ErrInvalidQUIC
			}
			i += n2
			*chunks = append(*chunks, quicCryptoChunk{
				offset: cryptoOff,
				data:   plaintext[i : i+int(cryptoLen)],
			})
			i += int(cryptoLen)
		case 0x1c:
			// CONNECTION_CLOSE (transport): Error Code (varint), Frame Type (varint), Reason Phrase Length (varint), Reason Phrase.
			return nil
		default:
			// Unknown or unparsed trailing frame in Initial packet; stop scanning this packet's frames.
			return nil
		}
	}
	return nil
}

func reassembleQUICCryptoChunks(chunks []quicCryptoChunk) ([]byte, bool) {
	if len(chunks) == 0 {
		return nil, false
	}
	slices.SortFunc(chunks, func(a, b quicCryptoChunk) int {
		return cmp.Compare(a.offset, b.offset)
	})

	var buf bytes.Buffer
	var cursor uint64
	gap := false
	for i := range chunks {
		c := &chunks[i]
		if c.offset > cursor {
			gap = true
			break
		}
		end := c.offset + uint64(len(c.data))
		if end <= cursor {
			continue
		}
		newBytes := c.data[cursor-c.offset:]
		if buf.Len()+len(newBytes) > MaxQUICCryptoBytes {
			break
		}
		buf.Write(newBytes)
		cursor = end
	}
	return buf.Bytes(), gap
}

// DecryptQUICInitial decrypts one or more client QUIC v1/v2 Initial UDP
// datagrams belonging to the same connection, reassembles their CRYPTO frames,
// and parses the embedded TLS 1.3 ClientHello and 'q13...' JA4 fingerprint.
func DecryptQUICInitial(datagrams [][]byte) (QUICHandshake, error) {
	if len(datagrams) == 0 {
		return QUICHandshake{}, fmt.Errorf("%w: empty datagram slice", ErrInvalidQUIC)
	}
	if len(datagrams) > MaxQUICPacketsPerFlow {
		return QUICHandshake{}, fmt.Errorf("%w: %d datagrams exceed %d", ErrQUICLimit, len(datagrams), MaxQUICPacketsPerFlow)
	}

	var firstHdr QUICInitialHeader
	var haveFirst bool
	var keys quicInitialKeys
	var chunks []quicCryptoChunk

	for _, dgram := range datagrams {
		rem := dgram
		for len(rem) >= 7 {
			hdr, err := ParseQUICInitialPacket(rem)
			if err != nil {
				break
			}
			if !haveFirst {
				firstHdr = hdr
				keys, err = deriveQUICInitialKeys(hdr.DCID, hdr.Version, true)
				if err != nil {
					return QUICHandshake{}, err
				}
				haveFirst = true
			}
			if plain, err := decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, keys); err == nil {
				_ = extractQUICCryptoFrames(plain, &chunks)
			}
			rem = rem[hdr.PacketLength:]
		}
	}

	if !haveFirst {
		return QUICHandshake{}, fmt.Errorf("%w: no valid QUIC Initial header found", ErrInvalidQUIC)
	}
	cryptoBytes, gap := reassembleQUICCryptoChunks(chunks)
	if len(cryptoBytes) < 4 {
		return QUICHandshake{}, fmt.Errorf("%w: no decrypted QUIC CRYPTO handshake bytes", ErrInvalidQUIC)
	}

	msgType := cryptoBytes[0]
	msgLen := int(cryptoBytes[1])<<16 | int(cryptoBytes[2])<<8 | int(cryptoBytes[3])
	if msgType != TLSHandshakeClientHello || msgLen > MaxQUICCryptoBytes || 4+msgLen > len(cryptoBytes) {
		return QUICHandshake{}, fmt.Errorf("%w: incomplete QUIC TLS 1.3 ClientHello (len=%d, have=%d)", ErrInvalidQUIC, 4+msgLen, len(cryptoBytes))
	}

	ch, err := parseTLSClientHelloWithRecordVersion(cryptoBytes[4:4+msgLen], TLSVersion13, true)
	if err != nil {
		return QUICHandshake{}, err
	}
	if gap {
		ch.Anomalies.TruncatedRecord = true
	}

	return QUICHandshake{
		Version:        firstHdr.Version,
		DCID:           firstHdr.DCID,
		SCID:           firstHdr.SCID,
		Token:          firstHdr.Token,
		HasClientHello: true,
		ClientHello:    ch,
		Anomalies:      ch.Anomalies,
	}, nil
}

// QUIC decrypts QUIC v1 and QUIC v2 Initial flows across all UDP packets in the
// capture and extracts their embedded TLS 1.3 ClientHello and 'q13...' JA4
// fingerprints.
func (c *Capture) QUIC(data []byte) ([]QUICRecord, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if c.PacketCount == 0 {
		return nil, nil
	}

	type quicFlowBuf struct {
		flowIndex int
		srcAddr   netip.Addr
		dstAddr   netip.Addr
		srcPort   uint16
		dstPort   uint16
		clientPkt [][]byte
		serverPkt [][]byte
	}

	r := SafeReader{data: data, size: int64(len(data))}
	var table flowIndexTable
	slotByFlow := make(map[int]int)
	var flows []quicFlowBuf

	err := c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 {
			return nil
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if frame.IPProtocol != IPProtoUDP || frame.PayloadLength < 7 {
			return nil
		}
		udpPayload := payload[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]
		if (udpPayload[0] & 0xc0) != 0xc0 {
			return nil
		}
		if _, err := ParseQUICInitialPacket(udpPayload); err != nil {
			return nil
		}

		slot, hasSlot := slotByFlow[flowIdx]
		if !hasSlot {
			if len(flows) >= MaxQUICFlowsPerScan {
				return fmt.Errorf("%w: exceeds %d QUIC flows", ErrQUICLimit, MaxQUICFlowsPerScan)
			}
			slot = len(flows)
			slotByFlow[flowIdx] = slot
			flows = append(flows, quicFlowBuf{
				flowIndex: flowIdx,
				srcAddr:   frame.SrcAddr,
				dstAddr:   frame.DstAddr,
				srcPort:   frame.SrcPort,
				dstPort:   frame.DstPort,
			})
		}

		fb := &flows[slot]
		if frame.SrcAddr == fb.srcAddr && frame.SrcPort == fb.srcPort {
			if len(fb.clientPkt) < MaxQUICPacketsPerFlow {
				fb.clientPkt = append(fb.clientPkt, udpPayload)
			}
		} else {
			if len(fb.serverPkt) < MaxQUICPacketsPerFlow {
				fb.serverPkt = append(fb.serverPkt, udpPayload)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var records []QUICRecord
	for i := range flows {
		fb := &flows[i]
		if len(fb.clientPkt) == 0 {
			continue
		}
		hs, err := DecryptQUICInitial(fb.clientPkt)
		if err != nil {
			continue
		}
		// Optionally decrypt server Initial packets using the client's first DCID.
		if len(fb.serverPkt) > 0 {
			if sh, ok := decryptQUICServerInitial(fb.serverPkt, hs.DCID, hs.Version); ok {
				hs.ServerHello = sh
				hs.HasServerHello = true
			}
		}
		records = append(records, QUICRecord{
			FlowIndex: fb.flowIndex,
			SrcAddr:   fb.srcAddr,
			DstAddr:   fb.dstAddr,
			SrcPort:   fb.srcPort,
			DstPort:   fb.dstPort,
			Handshake: hs,
		})
	}

	return records, nil
}

func decryptQUICServerInitial(datagrams [][]byte, clientDCID []byte, version uint32) (TLSServerHello, bool) {
	keys, err := deriveQUICInitialKeys(clientDCID, version, false)
	if err != nil {
		return TLSServerHello{}, false
	}
	var chunks []quicCryptoChunk
	for _, dgram := range datagrams {
		rem := dgram
		for len(rem) >= 7 {
			hdr, err := ParseQUICInitialPacket(rem)
			if err != nil {
				break
			}
			if plain, err := decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, keys); err == nil {
				_ = extractQUICCryptoFrames(plain, &chunks)
			}
			rem = rem[hdr.PacketLength:]
		}
	}
	cryptoBytes, _ := reassembleQUICCryptoChunks(chunks)
	if len(cryptoBytes) < 4 || cryptoBytes[0] != TLSHandshakeServerHello {
		return TLSServerHello{}, false
	}
	msgLen := int(cryptoBytes[1])<<16 | int(cryptoBytes[2])<<8 | int(cryptoBytes[3])
	if 4+msgLen > len(cryptoBytes) {
		return TLSServerHello{}, false
	}
	sh, err := parseTLSServerHelloWithRecordVersion(cryptoBytes[4:4+msgLen], TLSVersion13, true)
	if err != nil {
		return TLSServerHello{}, false
	}
	return sh, true
}

// HasQUICJA4 reports whether any QUIC Initial ClientHello in the capture matches
// the supplied JA4 fingerprint (such as "q13d...").
func (c *Capture) HasQUICJA4(data []byte, ja4 string) (bool, error) {
	records, err := c.QUIC(data)
	if err != nil {
		return false, err
	}
	for i := range records {
		if records[i].Handshake.HasClientHello && records[i].Handshake.ClientHello.JA4 == ja4 {
			return true, nil
		}
	}
	return false, nil
}

// HasQUICSNI reports whether any QUIC Initial ClientHello in the capture matches
// sni (case-insensitive ASCII comparison).
func (c *Capture) HasQUICSNI(data []byte, sni string) (bool, error) {
	records, err := c.QUIC(data)
	if err != nil {
		return false, err
	}
	for i := range records {
		if records[i].Handshake.HasClientHello && strings.EqualFold(records[i].Handshake.ClientHello.SNI, sni) {
			return true, nil
		}
	}
	return false, nil
}
