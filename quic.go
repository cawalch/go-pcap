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
	"math"
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
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte
	// HasRetry and HasVersionNegotiation report matching server packets observed by [Capture.QUIC].
	HasRetry              bool
	HasVersionNegotiation bool
	HasClientHello        bool
	HasServerHello        bool
	ClientHello           TLSClientHello
	ServerHello           TLSServerHello
	Anomalies             TLSAnomalies
}

// QUICRecord associates a parsed [QUICHandshake] with its first observed Initial
// UDP flow in a [Capture]. FlowIndex uses the ordering of [Capture.Flows].
// For fragmented UDP, the ports come from the reassembled datagram.
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
	hdr, err := parseQUICInitialPacketView(datagram)
	if err != nil {
		return QUICInitialHeader{}, err
	}
	hdr.DCID = bytes.Clone(hdr.DCID)
	hdr.SCID = bytes.Clone(hdr.SCID)
	hdr.Token = bytes.Clone(hdr.Token)
	return hdr, nil
}

// The ID and token slices borrow datagram for the duration of the scan.
func parseQUICInitialPacketView(datagram []byte) (QUICInitialHeader, error) {
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

	dcid, scid, offset, ok := quicConnectionIDs(datagram)
	if !ok {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid connection ID lengths", ErrInvalidQUIC)
	}

	tokenLen, n, ok := ReadQUICVarint(datagram[offset:])
	if !ok || tokenLen > MaxQUICTokenBytes || offset+n+int(tokenLen) > len(datagram) {
		return QUICInitialHeader{}, fmt.Errorf("%w: invalid QUIC Initial token length", ErrInvalidQUIC)
	}
	offset += n
	var token []byte
	if tokenLen > 0 {
		token = datagram[offset : offset+int(tokenLen)]
		offset += int(tokenLen)
	}

	remLen, n, ok := ReadQUICVarint(datagram[offset:])
	if !ok || remLen < 20 || remLen > uint64(len(datagram)-offset-n) {
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

// The caller has checked the seven-byte minimum long header.
func quicConnectionIDs(datagram []byte) (dcid, scid []byte, offset int, ok bool) {
	offset = 5
	dcidLen := int(datagram[offset])
	offset++
	if dcidLen > MaxQUICConnIDBytes || offset+dcidLen+1 > len(datagram) {
		return nil, nil, 0, false
	}
	dcid = datagram[offset : offset+dcidLen]
	offset += dcidLen

	scidLen := int(datagram[offset])
	offset++
	if scidLen > MaxQUICConnIDBytes || offset+scidLen > len(datagram) {
		return nil, nil, 0, false
	}
	scid = datagram[offset : offset+scidLen]
	offset += scidLen

	return dcid, scid, offset, true
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
	trafficSecret, err := tls13ExpandLabelHash(sha256.New, initialSecret, dirLabel, nil, 32)
	if err != nil {
		return quicInitialKeys{}, err
	}
	key, err := tls13ExpandLabelHash(sha256.New, trafficSecret, keyLabel, nil, 16)
	if err != nil {
		return quicInitialKeys{}, err
	}
	ivSlice, err := tls13ExpandLabelHash(sha256.New, trafficSecret, ivLabel, nil, 12)
	if err != nil {
		return quicInitialKeys{}, err
	}
	hpKey, err := tls13ExpandLabelHash(sha256.New, trafficSecret, hpLabel, nil, 16)
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
	// Header and plaintext share an allocation with disjoint AEAD input
	// and output ranges. The caller retains ownership of the wire packet.
	work := make([]byte, hdr.PacketLength-keys.aead.Overhead())
	headerLen := hdr.PayloadOffset + pnLen
	aad := work[:headerLen:headerLen]
	copy(aad, pkt[:headerLen])
	aad[0] = unmaskedFirst
	var pn uint64
	for i := range pnLen {
		aad[hdr.PayloadOffset+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(aad[hdr.PayloadOffset+i])
	}

	nonce := xorTLS13Nonce(keys.iv, pn)

	ciphertext := pkt[hdr.PayloadOffset+pnLen : hdr.PacketLength]
	plaintext, err := keys.aead.Open(work[headerLen:][:0], nonce[:], ciphertext, aad)
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
			// Skip Largest Acknowledged and ACK Delay before reading ACK Range Count.
			for range 2 {
				_, n, ok := ReadQUICVarint(plaintext[i:])
				if !ok {
					return ErrInvalidQUIC
				}
				i += n
			}
			ackRangeCount, n, ok := ReadQUICVarint(plaintext[i:])
			if !ok || ackRangeCount > 256 {
				return ErrInvalidQUIC
			}
			i += n
			// Skip First ACK Range, then a Gap and ACK Range Length for each range.
			fields := 1 + 2*int(ackRangeCount)
			if frameType == 0x03 {
				fields += 3 // ECT(0), ECT(1), and ECN-CE counts.
			}
			for range fields {
				_, n, ok := ReadQUICVarint(plaintext[i:])
				if !ok {
					return ErrInvalidQUIC
				}
				i += n
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
	// One complete CRYPTO frame already has the required contiguous layout.
	if len(chunks) == 1 && chunks[0].offset == 0 && len(chunks[0].data) <= MaxQUICCryptoBytes {
		return chunks[0].data, false
	}
	slices.SortStableFunc(chunks, func(a, b quicCryptoChunk) int {
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

// The 16-bit UDP length includes its eight-byte header.
const maxQUICUDPPayloadBytes = math.MaxUint16 - 8

// DecryptQUICInitial decrypts one or more client QUIC v1/v2 Initial UDP
// datagrams belonging to the same connection, reassembles their CRYPTO frames,
// and parses the embedded TLS 1.3 ClientHello and 'q13...' JA4 fingerprint.
// It returns [ErrQUICLimit] if the input contains more than
// [MaxQUICPacketsPerFlow] datagrams or any UDP payload exceeds 65,527 bytes.
func DecryptQUICInitial(datagrams [][]byte) (QUICHandshake, error) {
	return decryptQUICInitial(datagrams, nil, true)
}

func decryptQUICInitial(datagrams [][]byte, observedRetryID []byte, inferRetry bool) (QUICHandshake, error) {
	if len(datagrams) == 0 {
		return QUICHandshake{}, fmt.Errorf("%w: empty datagram slice", ErrInvalidQUIC)
	}
	if len(datagrams) > MaxQUICPacketsPerFlow {
		return QUICHandshake{}, fmt.Errorf("%w: %d datagrams exceed %d", ErrQUICLimit, len(datagrams), MaxQUICPacketsPerFlow)
	}
	for i, dgram := range datagrams {
		if len(dgram) > maxQUICUDPPayloadBytes {
			return QUICHandshake{}, fmt.Errorf("%w: datagram %d payload length %d exceeds %d bytes", ErrQUICLimit, i, len(dgram), maxQUICUDPPayloadBytes)
		}
	}

	var firstHdr QUICInitialHeader
	var haveFirst bool
	var effectiveDCID []byte
	var keys, retryKeys quicInitialKeys
	var chunks []quicCryptoChunk

	for _, dgram := range datagrams {
		rem := dgram
		for len(rem) >= 7 {
			hdr, err := parseQUICInitialPacketView(rem)
			if err != nil {
				break
			}
			if !haveFirst {
				firstHdr = hdr
				effectiveDCID = hdr.DCID
				keys, err = deriveQUICInitialKeys(hdr.DCID, hdr.Version, true)
				if err != nil {
					return QUICHandshake{}, err
				}
				haveFirst = true
			}
			plain, decErr := decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, keys)
			if decErr != nil && inferRetry && !bytes.Equal(hdr.DCID, effectiveDCID) {
				// The caller grouped these datagrams into one exchange. Try keys
				// derived from the new destination ID when the Retry is unavailable.
				if otherKeys, kErr := deriveQUICInitialKeys(hdr.DCID, hdr.Version, true); kErr == nil {
					if otherPlain, rErr := decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, otherKeys); rErr == nil {
						keys, effectiveDCID = otherKeys, hdr.DCID
						plain, decErr = otherPlain, nil
					}
				}
			}
			if decErr != nil && observedRetryID != nil && !bytes.Equal(hdr.DCID, firstHdr.DCID) {
				if retryKeys.aead == nil && bytes.Equal(hdr.DCID, observedRetryID) {
					retryKeys, _ = deriveQUICInitialKeys(observedRetryID, firstHdr.Version, true)
				}
				if retryKeys.aead != nil {
					plain, decErr = decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, retryKeys)
					if decErr == nil {
						effectiveDCID = observedRetryID
					}
				}
			}
			if decErr == nil {
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
		DCID:           bytes.Clone(effectiveDCID),
		SCID:           bytes.Clone(firstHdr.SCID),
		Token:          bytes.Clone(firstHdr.Token),
		HasClientHello: true,
		ClientHello:    ch,
		Anomalies:      ch.Anomalies,
	}, nil
}

// QUIC decrypts QUIC v1 and QUIC v2 Initial flows across all UDP packets in the
// capture and extracts their embedded TLS 1.3 ClientHello and 'q13...' JA4
// fingerprints. Distinct exchanges on a UDP tuple share its flow index. QUIC
// correlates unique nonempty connection IDs across client port changes and
// reports observed Retry and Version Negotiation responses.
func (c *Capture) QUIC(data []byte) ([]QUICRecord, error) {
	return scanQUIC(ipFrameSource{capture: c, data: data})
}

// quicScanHeader checks an Initial, Retry, or Version Negotiation header for
// flow correlation. The returned IDs borrow the UDP payload.
func quicScanHeader(udpPayload []byte) (version uint32, dcid, scid []byte, initialLength int, vn, retry, ok bool) {
	first := udpPayload[0]
	if first&0x80 == 0 {
		return 0, nil, nil, 0, false, false, false
	}
	version = binary.BigEndian.Uint32(udpPayload[1:5])
	vn = version == 0
	retry = (version == QUICVersion1 && first&0xf0 == 0xf0) || (version == QUICVersion2 && first&0xf0 == 0xc0)
	if vn || retry {
		var n int
		var ok bool
		dcid, scid, n, ok = quicConnectionIDs(udpPayload)
		if !ok {
			return 0, nil, nil, 0, false, false, false
		}
		tail := len(udpPayload) - n
		if vn && (tail == 0 || tail%4 != 0) || retry && (tail <= 16 || tail-16 > MaxQUICTokenBytes) {
			return 0, nil, nil, 0, false, false, false
		}
	} else {
		if first&0x40 == 0 {
			return 0, nil, nil, 0, false, false, false
		}
		hdr, err := parseQUICInitialPacketView(udpPayload)
		if err != nil {
			return 0, nil, nil, 0, false, false, false
		}
		dcid, scid, initialLength = hdr.DCID, hdr.SCID, hdr.PacketLength
	}
	return version, dcid, scid, initialLength, vn, retry, true
}

// quicCID owns the bytes of a length-validated long-header connection ID.
// Include the length so trailing zero bytes remain significant in map keys.
type quicCID struct {
	data   [MaxQUICConnIDBytes]byte
	length uint8
}

func makeQUICCID(data []byte) quicCID {
	id := quicCID{length: uint8(len(data))}
	copy(id.data[:], data)
	return id
}

// Intern addresses so each directional CID index stores compact endpoint keys.
type quicEndpoint struct {
	addr uint32
	port uint16
}

type quicTuple struct {
	client, server quicEndpoint
}

func (t quicTuple) reverse() quicTuple {
	return quicTuple{t.server, t.client}
}

type quicExchangeKey struct {
	tuple      quicTuple
	version    uint32
	dcid, scid quicCID
}

const (
	quicInitialDCID = iota
	quicResponseDCID
	quicServerSCID
)

type quicTupleCID struct {
	tuple   quicTuple
	version uint32
	id      quicCID
	kind    uint8
}

// quicEndpointCID deliberately excludes the client port so an Initial can be
// correlated after rebinding. A reused ID is ambiguous across ports.
type quicEndpointCID struct {
	client   uint32
	server   quicEndpoint
	id       quicCID
	response bool
}

func registerQUICSlot[K comparable](m map[K]int, key K, slot int) {
	if prev, found := m[key]; found && prev != slot {
		m[key] = -1
	} else {
		m[key] = slot
	}
}

type quicFlowBuf struct {
	key             quicExchangeKey
	flowIndex       int
	hasRetry, hasVN bool
	retryID         quicCID
	serverID        quicCID
	count           int
	failedProbes    int
	clientPkt       [][]byte
	serverPkt       [][]byte
}

func (fb *quicFlowBuf) isServerAlias(dcid quicCID) bool {
	return fb.serverID.length > 0 && dcid == fb.serverID && dcid != fb.key.dcid && (!fb.hasRetry || dcid != fb.retryID)
}

// Reserve speculative authentication for exchanges with packet budget left.
// A failed probe consumes the allowance for further probes, while direct CID
// matches still have the full packet budget.
func (fb *quicFlowBuf) canProbe() bool {
	return fb.count+fb.failedProbes < MaxQUICPacketsPerFlow
}

func scanQUIC(source ipFrameSource) ([]QUICRecord, error) {
	var table flowIndexTable
	var defrag ipFragAccumulator
	var flows []quicFlowBuf
	var addresses []netip.Addr
	addressIDs := make(map[netip.Addr]uint32)
	addressID := func(addr netip.Addr) uint32 {
		if id, ok := addressIDs[addr]; ok {
			return id
		}
		id := uint32(len(addresses))
		addresses = append(addresses, addr)
		addressIDs[addr] = id
		return id
	}
	byInitial := make(map[quicExchangeKey]int)
	byTupleCID := make(map[quicTupleCID]int)
	byEndpointCID := make(map[quicEndpointCID]int)
	register := func(key quicExchangeKey, slot int) {
		if _, known := byInitial[key]; known {
			return
		}
		byInitial[key] = slot
		tuple := key.tuple
		registerQUICSlot(byTupleCID, quicTupleCID{tuple, key.version, key.scid, quicResponseDCID}, slot)
		if tuple != flows[slot].key.tuple {
			return // The exchange is already indexed for rebinding.
		}
		if key == flows[slot].key {
			registerQUICSlot(byTupleCID, quicTupleCID{tuple, key.version, key.dcid, quicInitialDCID}, slot)
		}
		if key.dcid.length > 0 {
			registerQUICSlot(byEndpointCID, quicEndpointCID{tuple.client.addr, tuple.server, key.dcid, false}, slot)
		}
		if key.scid.length > 0 {
			registerQUICSlot(byEndpointCID, quicEndpointCID{tuple.client.addr, tuple.server, key.scid, true}, slot)
		}
	}
	registerServerID := func(slot int, tuple quicTuple, id quicCID) {
		fb := &flows[slot]
		fb.serverID = id
		registerQUICSlot(byTupleCID, quicTupleCID{fb.key.tuple, fb.key.version, id, quicServerSCID}, slot)
		if tuple != fb.key.tuple {
			registerQUICSlot(byTupleCID, quicTupleCID{tuple, fb.key.version, id, quicServerSCID}, slot)
		}
		registerQUICSlot(byEndpointCID, quicEndpointCID{tuple.client.addr, tuple.server, id, false}, slot)
	}

	err := source.walk(func(_ PacketRecord, frame Frame, udpPayload []byte) error {
		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if frame.mayContainUDPFragment() {
			var ok bool
			udpPayload, frame.SrcPort, frame.DstPort, ok = defrag.addUDPFragment(&frame, udpPayload)
			if !ok {
				return nil
			}
		} else if frame.IPProtocol != IPProtoUDP {
			return nil
		}
		if len(udpPayload) < 7 {
			return nil
		}
		version, dstID, srcID, initialLength, vn, retry, ok := quicScanHeader(udpPayload)
		if !ok {
			return nil
		}

		tuple := quicTuple{quicEndpoint{addressID(frame.SrcAddr), frame.SrcPort}, quicEndpoint{addressID(frame.DstAddr), frame.DstPort}}
		reverse := tuple.reverse()
		dcid, scid := makeQUICCID(dstID), makeQUICCID(srcID)
		initial := quicExchangeKey{tuple, version, dcid, scid}
		slot, found := byInitial[initial]
		client := true
		if vn || retry || !found {
			client, found = false, false
			if vn {
				// Version Negotiation echoes both of the client's IDs.
				for _, v := range [...]uint32{QUICVersion1, QUICVersion2} {
					if match, ok := byInitial[quicExchangeKey{reverse, v, scid, dcid}]; ok && flows[match].key.dcid == scid {
						if found && slot != match {
							return nil
						}
						slot, found = match, true
					}
				}
			} else {
				slot, found = byTupleCID[quicTupleCID{reverse, version, dcid, quicResponseDCID}]
				if found && slot < 0 {
					// This response's destination ID has multiple owners on the tuple.
					return nil
				}
			}
			if !found && dcid.length > 0 {
				f, fOK := byEndpointCID[quicEndpointCID{tuple.client.addr, tuple.server, dcid, false}]
				r, rOK := byEndpointCID[quicEndpointCID{reverse.client.addr, reverse.server, dcid, true}]
				if !vn && !retry && fOK && f >= 0 && !rOK && flows[f].key.version == version && flows[f].key.scid == scid {
					slot, found, client = f, true, true
				} else if rOK && r >= 0 && !fOK && (vn || flows[r].key.version == version) {
					slot, found = r, true
				}
			}
		}
		if vn || retry {
			if !found {
				return nil
			}
			fb := &flows[slot]
			if fb.count >= MaxQUICPacketsPerFlow {
				return nil
			}
			if vn && scid == fb.key.dcid {
				fb.hasVN = true
				fb.count++
			}
			if retry && !fb.hasRetry && scid != fb.key.dcid {
				fb.hasRetry = true
				fb.retryID = scid
				fb.count++
				alias := fb.key
				alias.dcid = scid
				register(alias, slot)
				alias.tuple = reverse
				register(alias, slot)
			}
			return nil
		}

		if !found || !client {
			// An Initial captured before its client packet has the client's
			// SCID as its DCID. Verify that it decrypts with server keys
			// before interpreting the earlier packets as a server Initial.
			previous, exists := byTupleCID[quicTupleCID{reverse, version, scid, quicInitialDCID}]
			if exists && previous >= 0 && (!found || slot == previous) {
				fb := &flows[previous]
				if fb.canProbe() && len(fb.clientPkt) > 0 && len(fb.serverPkt) == 0 && !fb.hasRetry && !fb.hasVN {
					if quicAuthenticatesInitial(fb.clientPkt[0], dstID, false) {
						delete(byInitial, fb.key)
						oldTuple := fb.key.tuple
						deleteQUICSlot(byTupleCID, quicTupleCID{oldTuple, version, fb.key.dcid, quicInitialDCID}, previous)
						deleteQUICSlot(byTupleCID, quicTupleCID{oldTuple, version, fb.key.scid, quicResponseDCID}, previous)
						deleteQUICSlot(byEndpointCID, quicEndpointCID{oldTuple.client.addr, oldTuple.server, fb.key.dcid, false}, previous)
						deleteQUICSlot(byEndpointCID, quicEndpointCID{oldTuple.client.addr, oldTuple.server, fb.key.scid, true}, previous)
						serverID := fb.key.scid
						fb.key = initial
						fb.serverPkt, fb.clientPkt = fb.clientPkt, nil
						if serverID.length > 0 && serverID != dcid {
							registerServerID(previous, tuple, serverID)
						}
						slot, found, client = previous, true, true
					} else {
						fb.failedProbes++
					}
				}
			}
		}
		if !found {
			if alias, ok := byTupleCID[quicTupleCID{tuple, version, dcid, quicServerSCID}]; ok && alias >= 0 && flows[alias].key.scid == scid {
				slot, found, client = alias, true, true
			}
		}
		if found && client {
			fb := &flows[slot]
			if fb.isServerAlias(dcid) {
				// A normal server SCID changes the destination ID without
				// changing the Initial keys. A new client can independently
				// choose the same IDs and will use different keys.
				found = false
				if fb.canProbe() {
					found = quicAuthenticatesInitial(udpPayload, fb.key.dcid.data[:fb.key.dcid.length], true) ||
						fb.hasRetry && quicAuthenticatesInitial(udpPayload, fb.retryID.data[:fb.retryID.length], true)
					if !found {
						fb.failedProbes++
					}
				}
			}
		}
		if !found {
			if len(flows) >= MaxQUICFlowsPerScan {
				return fmt.Errorf("%w: exceeds %d QUIC exchanges", ErrQUICLimit, MaxQUICFlowsPerScan)
			}
			slot = len(flows)
			flows = append(flows, quicFlowBuf{key: initial, flowIndex: flowIdx})
			client = true
		}

		fb := &flows[slot]
		if fb.count >= MaxQUICPacketsPerFlow {
			return nil
		}
		fb.count++
		udpPayload = quicSameInitials(udpPayload, initialLength, version, dstID, srcID)
		if client {
			if fb.isServerAlias(dcid) {
				registerQUICSlot(byTupleCID, quicTupleCID{tuple, version, scid, quicResponseDCID}, slot)
			} else {
				register(initial, slot)
			}
			fb.clientPkt = append(fb.clientPkt, udpPayload)
		} else {
			registerQUICSlot(byTupleCID, quicTupleCID{reverse, version, dcid, quicResponseDCID}, slot)
			if fb.serverID.length == 0 && scid.length > 0 && scid != fb.key.dcid && (!fb.hasRetry || scid != fb.retryID) {
				registerServerID(slot, reverse, scid)
			}
			fb.serverPkt = append(fb.serverPkt, udpPayload)
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
		tuple := fb.key.tuple
		clientPkt, serverPkt := fb.clientPkt, fb.serverPkt
		var retryID []byte
		if fb.hasRetry {
			retryID = fb.retryID.data[:fb.retryID.length]
		}
		hs, err := decryptQUICInitial(clientPkt, retryID, false)
		if err != nil && len(serverPkt) > 0 {
			// Handle server-first capture ordering by retrying client Initial on serverPkt.
			if swappedHS, swapErr := decryptQUICInitial(serverPkt, nil, false); swapErr == nil {
				hs = swappedHS
				err = nil
				serverPkt = clientPkt
				tuple = tuple.reverse()
			}
		}
		if err != nil {
			continue
		}
		hs.HasRetry = fb.hasRetry
		hs.HasVersionNegotiation = fb.hasVN
		// Optionally decrypt server Initial packets using the active client DCID.
		if len(serverPkt) > 0 {
			if sh, ok := decryptQUICServerInitial(serverPkt, hs.DCID, hs.Version); ok {
				hs.ServerHello = sh
				hs.HasServerHello = true
				hs.Anomalies = mergeTLSAnomalies(hs.Anomalies, sh.Anomalies)
			}
		}
		records = append(records, QUICRecord{
			FlowIndex: fb.flowIndex,
			SrcAddr:   addresses[tuple.client.addr],
			DstAddr:   addresses[tuple.server.addr],
			SrcPort:   tuple.client.port,
			DstPort:   tuple.server.port,
			Handshake: hs,
		})
	}

	return records, nil
}

func deleteQUICSlot[K comparable](m map[K]int, key K, slot int) {
	if prev, found := m[key]; found && prev == slot {
		delete(m, key)
	}
}

func quicAuthenticatesInitial(datagram, keyDCID []byte, client bool) bool {
	hdr, err := parseQUICInitialPacketView(datagram)
	if err != nil {
		return false
	}
	keys, err := deriveQUICInitialKeys(keyDCID, hdr.Version, client)
	if err != nil {
		return false
	}
	_, err = decryptSingleQUICInitial(datagram, hdr, keys)
	return err == nil
}

// Coalesced packets on the same datagram use the same destination ID. Stop
// before an Initial with different IDs or version so it cannot contribute
// CRYPTO data to this exchange.
func quicSameInitials(datagram []byte, n int, version uint32, dcid, scid []byte) []byte {
	for len(datagram)-n >= 7 {
		hdr, err := parseQUICInitialPacketView(datagram[n:])
		if err != nil || hdr.Version != version || !bytes.Equal(hdr.DCID, dcid) || !bytes.Equal(hdr.SCID, scid) {
			break
		}
		n += hdr.PacketLength
	}
	return datagram[:n]
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
			hdr, err := parseQUICInitialPacketView(rem)
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
