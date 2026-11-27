package pcap

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

const quicPacketNumberLimit = uint64(1) << 62

var errQUICAuthentication = fmt.Errorf("%w: QUIC packet authentication failed", ErrInvalidQUIC)

// QUIC1RTTDecoder authenticates short-header packets for one sending direction
// of a QUIC connection with its initial 1-RTT keys. Initialize it with
// [NewQUIC1RTTDecoder]. The caller tracks packet numbers and connection IDs.
type QUIC1RTTDecoder struct {
	keys quicPacketKeys
}

// NewQUIC1RTTDecoder derives the packet protection keys for QUIC v1 or v2
// using TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384. Pass the sender's
// ClientTrafficSecret0 or ServerTrafficSecret0 from [TLSKeyLogEntry].
// Unsupported parameters and incorrect secret lengths return [ErrInvalidQUIC].
func NewQUIC1RTTDecoder(version uint32, cipherSuite uint16, trafficSecret []byte) (*QUIC1RTTDecoder, error) {
	if version != QUICVersion1 && version != QUICVersion2 {
		return nil, fmt.Errorf("%w: unsupported QUIC version %#x", ErrInvalidQUIC, version)
	}
	hashFn, keyLen := tls13SuiteParams(cipherSuite)
	if hashFn == nil {
		return nil, fmt.Errorf("%w: unsupported QUIC cipher suite %#x", ErrInvalidQUIC, cipherSuite)
	}
	if len(trafficSecret) != hashFn().Size() {
		return nil, fmt.Errorf("%w: incorrect QUIC traffic secret length", ErrInvalidQUIC)
	}
	keys, err := deriveQUICPacketKeys(trafficSecret, version, hashFn, keyLen)
	if err != nil {
		return nil, err
	}
	return &QUIC1RTTDecoder{keys: keys}, nil
}

// Open authenticates one complete QUIC short-header packet and returns its
// packet number and frame bytes. Pass the receiver's destination connection ID
// (which can be empty) and the sender's largest authenticated application
// packet number plus one. Use zero for a direction starting at packet number
// zero. Reordering and missing packets are recoverable while the expected
// number selects the correct encoding window. Update the expected number only
// after successful authentication and keep it monotonic.
//
// Open returns caller-owned plaintext only on success. Packets over 65,527
// bytes return [ErrQUICLimit]. Incorrect context, malformed packets and
// authentication failures return [ErrInvalidQUIC]. The decoder uses the
// original traffic secret and key phase zero.
func (d *QUIC1RTTDecoder) Open(packet, dcid []byte, expectedPacketNumber uint64) (uint64, []byte, error) {
	pn, _, payload, err := d.open(packet, dcid, expectedPacketNumber, nil)
	return pn, payload, err
}

// open proposes a generation without advancing a tracker.
func (d *QUIC1RTTDecoder) open(packet, dcid []byte, expectedPacketNumber uint64, tracker *QUIC1RTTKeyTracker) (uint64, uint8, []byte, error) {
	if len(packet) > maxQUICUDPPayloadBytes {
		return 0, 0, nil, fmt.Errorf("%w: QUIC 1-RTT packet exceeds %d bytes", ErrQUICLimit, maxQUICUDPPayloadBytes)
	}
	if d == nil || d.keys.aead == nil || len(dcid) > MaxQUICConnIDBytes || expectedPacketNumber > quicPacketNumberLimit {
		return 0, 0, nil, fmt.Errorf("%w: invalid QUIC 1-RTT decoder or packet context", ErrInvalidQUIC)
	}
	pnOffset := 1 + len(dcid)
	sampleOffset := pnOffset + 4
	// The supplied connection context and AEAD authenticate packets even when
	// the sender clears the fixed bit under RFC 9287.
	if len(packet) < sampleOffset+aes.BlockSize || packet[0]&0x80 != 0 || !bytes.Equal(dcid, packet[1:pnOffset]) {
		return 0, 0, nil, fmt.Errorf("%w: invalid QUIC 1-RTT header or destination connection ID", ErrInvalidQUIC)
	}

	forbidden := byte(0x18)
	if tracker == nil {
		forbidden |= 0x04
	}
	return d.openProtected(packet, pnOffset, expectedPacketNumber, 0x1f, forbidden, tracker)
}

// The long and short headers differ in which low bits are protected and
// reserved, but authenticate the same packet number, nonce and header.
func (d *QUIC1RTTDecoder) openPacket(packet []byte, pnOffset int, expectedPacketNumber uint64, protectedBits, forbiddenBits byte) (uint64, []byte, error) {
	pn, _, payload, err := d.openProtected(packet, pnOffset, expectedPacketNumber, protectedBits, forbiddenBits, nil)
	return pn, payload, err
}

func (d *QUIC1RTTDecoder) openProtected(packet []byte, pnOffset int, expectedPacketNumber uint64, protectedBits, forbiddenBits byte, tracker *QUIC1RTTKeyTracker) (uint64, uint8, []byte, error) {
	sampleOffset := pnOffset + 4
	var mask [aes.BlockSize]byte
	d.keys.hp.Encrypt(mask[:], packet[sampleOffset:sampleOffset+aes.BlockSize])
	firstByte := packet[0] ^ (mask[0] & protectedBits)
	pnLen := int(firstByte&0x03) + 1
	headerLen := pnOffset + pnLen

	// Header and plaintext occupy disjoint regions of one allocation.
	work := make([]byte, len(packet)-d.keys.aead.Overhead())
	aad := work[:headerLen:headerLen]
	copy(aad, packet[:headerLen])
	aad[0] = firstByte
	var truncated uint64
	for i := range pnLen {
		aad[pnOffset+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(aad[pnOffset+i])
	}
	packetNumber := decodeQUICPacketNumber(truncated, expectedPacketNumber, pnLen)
	if packetNumber >= quicPacketNumberLimit {
		return 0, 0, nil, fmt.Errorf("%w: QUIC packet number out of range", ErrInvalidQUIC)
	}
	keys, generation := d.keys, uint8(0)
	if tracker != nil {
		keys, generation = tracker.selectKeys(packetNumber, (firstByte>>2)&1)
	}
	if keys.aead == nil {
		return 0, 0, nil, ErrInvalidQUIC
	}
	nonce := xorTLS13Nonce(keys.iv, packetNumber)
	plaintext, err := keys.aead.Open(work[headerLen:][:0], nonce[:], packet[headerLen:], aad)
	if err != nil {
		return 0, 0, nil, errQUICAuthentication
	}
	if firstByte&forbiddenBits != 0 {
		return 0, 0, nil, fmt.Errorf("%w: invalid protected QUIC header bits", ErrInvalidQUIC)
	}
	return packetNumber, generation, plaintext, nil
}

// decodeQUICPacketNumber reconstructs the packet number in the window around
// expected, as described in RFC 9000 Appendix A.3.
func decodeQUICPacketNumber(truncated, expected uint64, encodingBytes int) uint64 {
	window := uint64(1) << (8 * encodingBytes)
	half := window / 2
	candidate := expected&^(window-1) | truncated
	if candidate+half <= expected && candidate < quicPacketNumberLimit-window {
		return candidate + window
	}
	if candidate > expected+half && candidate >= window {
		return candidate - window
	}
	return candidate
}
