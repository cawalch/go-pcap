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

// QUICRecord associates a parsed [QUICHandshake] with its first observed Initial UDP flow in
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

	nonce := keys.iv
	for i := range 8 {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}

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
	var effectiveDCID []byte
	var keys quicInitialKeys
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
			if decErr != nil && !bytes.Equal(hdr.DCID, effectiveDCID) {
				// Retry-updated DCID: re-derive client Initial keys for the new DCID.
				if retryKeys, kErr := deriveQUICInitialKeys(hdr.DCID, hdr.Version, true); kErr == nil {
					if retryPlain, rErr := decryptSingleQUICInitial(rem[:hdr.PacketLength], hdr, retryKeys); rErr == nil {
						keys = retryKeys
						effectiveDCID = hdr.DCID
						plain, decErr = retryPlain, nil
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
// fingerprints. It correlates unique nonempty connection IDs across client port
// changes and reports observed Retry and Version Negotiation responses.
func (c *Capture) QUIC(data []byte) ([]QUICRecord, error) {
	return scanQUIC(ipFrameSource{capture: c, data: data})
}

// quicScanHeader checks an Initial, Retry, or Version Negotiation header for
// flow correlation. The returned IDs borrow the UDP payload.
func quicScanHeader(udpPayload []byte) (version uint32, dcid, scid []byte, vn, retry, ok bool) {
	first := udpPayload[0]
	if first&0x80 == 0 {
		return 0, nil, nil, false, false, false
	}
	version = binary.BigEndian.Uint32(udpPayload[1:5])
	vn = version == 0
	retry = (version == QUICVersion1 && first&0xf0 == 0xf0) || (version == QUICVersion2 && first&0xf0 == 0xc0)
	if vn || retry {
		var n int
		var ok bool
		dcid, scid, n, ok = quicConnectionIDs(udpPayload)
		if !ok {
			return 0, nil, nil, false, false, false
		}
		tail := len(udpPayload) - n
		if vn && (tail == 0 || tail%4 != 0) || retry && (tail <= 16 || tail-16 > MaxQUICTokenBytes) {
			return 0, nil, nil, false, false, false
		}
	} else {
		if first&0x40 == 0 {
			return 0, nil, nil, false, false, false
		}
		hdr, err := parseQUICInitialPacketView(udpPayload)
		if err != nil {
			return 0, nil, nil, false, false, false
		}
		dcid, scid = hdr.DCID, hdr.SCID
	}
	return version, dcid, scid, vn, retry, true
}

func scanQUIC(source ipFrameSource) ([]QUICRecord, error) {

	type quicFlowBuf struct {
		flowIndex       int
		srcAddr         netip.Addr
		dstAddr         netip.Addr
		srcPort         uint16
		dstPort         uint16
		version         uint32
		dcid, scid      []byte
		hasRetry, hasVN bool
		count           int
		clientPkt       [][]byte
		serverPkt       [][]byte
	}

	// Index the client's DCID in the forward direction and SCID in reverse.
	// Include the server port so only the client port can change.
	type cidKey struct {
		client   netip.Addr
		server   netip.AddrPort
		id       string
		response bool
	}
	byCID := make(map[cidKey]int)
	register := func(key cidKey, slot int) {
		if key.id == "" {
			return
		}
		if prev, found := byCID[key]; found && prev != slot {
			byCID[key] = -1 // More than one exchange uses this ID.
		} else {
			byCID[key] = slot
		}
	}

	var table flowIndexTable
	var defrag ipFragAccumulator
	slotByFlow := make(map[int]int)
	var flows []quicFlowBuf

	err := source.walk(func(_ PacketRecord, frame Frame, l4 []byte) error {

		var udpPayload []byte
		if frame.Anomalies.IPFragment && frame.IPProtocol == IPProtoUDP {
			var srcPort, dstPort uint16
			var ok bool
			udpPayload, srcPort, dstPort, ok = defrag.addUDPFragment(&frame, l4)
			if !ok {
				return nil
			}
			frame.SrcPort = srcPort
			frame.DstPort = dstPort
		} else if frame.IPProtocol == IPProtoUDP && frame.PayloadLength >= 7 {
			udpPayload = l4
		}

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		if frame.IPProtocol != IPProtoUDP || len(udpPayload) < 7 {
			return nil
		}
		version, dcid, scid, vn, retry, ok := quicScanHeader(udpPayload)
		if !ok {
			return nil
		}

		forward := cidKey{frame.SrcAddr, netip.AddrPortFrom(frame.DstAddr, frame.DstPort), string(dcid), false}
		reverse := cidKey{frame.DstAddr, netip.AddrPortFrom(frame.SrcAddr, frame.SrcPort), string(dcid), true}
		slot, hasTuple := slotByFlow[flowIdx]
		found := hasTuple
		client := true
		var tupleIDsMatch bool
		if found {
			fb := &flows[slot]
			client = frame.DstAddr == fb.dstAddr && frame.DstPort == fb.dstPort
			if client {
				tupleIDsMatch = fb.version == version && bytes.Equal(fb.dcid, dcid) && bytes.Equal(fb.scid, scid)
			} else {
				tupleIDsMatch = (vn || fb.version == version) && bytes.Equal(fb.scid, dcid)
			}
		}
		// A client can rebind onto a tuple already used by another exchange.
		// When its IDs disagree, prefer a unique directional CID match.
		if !tupleIDsMatch {
			f, fOK := byCID[forward]
			r, rOK := byCID[reverse]
			// A changed client SCID identifies a separate Initial exchange,
			// even when both clients chose the same destination ID.
			if !vn && !retry && fOK && f >= 0 && !rOK && flows[f].version == version && bytes.Equal(flows[f].scid, scid) {
				slot, found, client = f, true, true
			} else if rOK && r >= 0 && !fOK && (vn || flows[r].version == version) {
				slot, found, client = r, true, false
			}
		}
		if vn || retry {
			if !found || client {
				return nil
			}
			fb := &flows[slot]
			if fb.count >= MaxQUICPacketsPerFlow || !bytes.Equal(dcid, fb.scid) {
				return nil
			}
			if vn && bytes.Equal(scid, fb.dcid) {
				fb.hasVN = true
				fb.count++
			}
			if retry && version == fb.version && !fb.hasRetry && !bytes.Equal(scid, fb.dcid) {
				fb.hasRetry = true
				fb.count++
				register(cidKey{fb.srcAddr, netip.AddrPortFrom(fb.dstAddr, fb.dstPort), string(scid), false}, slot)
			}
			return nil
		}
		if !found {
			if len(flows) >= MaxQUICFlowsPerScan {
				return fmt.Errorf("%w: exceeds %d QUIC flows", ErrQUICLimit, MaxQUICFlowsPerScan)
			}
			slot = len(flows)
			flows = append(flows, quicFlowBuf{
				flowIndex: flowIdx, srcAddr: frame.SrcAddr, dstAddr: frame.DstAddr,
				srcPort: frame.SrcPort, dstPort: frame.DstPort, version: version, dcid: dcid, scid: scid,
			})
			register(forward, slot)
			register(cidKey{forward.client, forward.server, string(scid), true}, slot)
		}

		fb := &flows[slot]
		if fb.count >= MaxQUICPacketsPerFlow {
			return nil
		}
		if !hasTuple {
			slotByFlow[flowIdx] = slot
		}
		fb.count++
		if client {
			fb.clientPkt = append(fb.clientPkt, udpPayload)
		} else {
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
		srcAddr, dstAddr, srcPort, dstPort := fb.srcAddr, fb.dstAddr, fb.srcPort, fb.dstPort
		clientPkt, serverPkt := fb.clientPkt, fb.serverPkt
		hs, err := DecryptQUICInitial(clientPkt)
		if err != nil && len(serverPkt) > 0 {
			// Handle server-first capture ordering by retrying client Initial on serverPkt.
			if swappedHS, swapErr := DecryptQUICInitial(serverPkt); swapErr == nil {
				hs = swappedHS
				err = nil
				serverPkt = clientPkt
				srcAddr, dstAddr = dstAddr, srcAddr
				srcPort, dstPort = dstPort, srcPort
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
			SrcAddr:   srcAddr,
			DstAddr:   dstAddr,
			SrcPort:   srcPort,
			DstPort:   dstPort,
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
