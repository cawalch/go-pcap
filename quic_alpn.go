package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// QUICALPNSelection is the protocol selected by the server in an authenticated
// QUIC Handshake-level TLS EncryptedExtensions message. PacketIndices contains
// the sorted, distinct original packet indices supplying that message. Identical
// retransmissions use the first captured copy. Conflicting bytes yield no selection.
type QUICALPNSelection struct {
	Protocol      string
	PacketIndices []int
}

// KeyedQUICWithALPN returns the application packets from [Capture.KeyedQUIC]
// and observes server-selected ALPN with SERVER_HANDSHAKE_TRAFFIC_SECRET.
// A selection can produce a row without any application packets. ALPN is nil
// on an application row whose selection could not be recovered. Both encryption
// levels share the scan-wide authentication and retained-byte limits.
func (c *Capture) KeyedQUICWithALPN(data, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	return scanKeyedQUIC(ipFrameSource{capture: c, data: data}, extraKeyLog, true, nil)
}

// KeyedQUICWithALPNFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.KeyedQUICWithALPN]. Both passes share [MaxReaderAtScanBytes].
func (c *Capture) KeyedQUICWithALPNFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	return c.keyedQUICReaderAt(r, extraKeyLog, true, nil)
}

type quicALPNDirection struct {
	coverage *QUICProtectionObservation
	decoder  *QUIC1RTTDecoder
	version  uint32
	expected uint64 // Server Handshake packet number space, separate from 1-RTT.
	chunks   []quicALPNChunk
	bytes    int
}

type quicALPNChunk struct {
	quicCryptoChunk
	packet int
}

func (s *quicKeyedScan) observeHandshake(packetIndex int, f Frame, version uint32, dcid []byte, pnOffset int, packet []byte) error {
	// walkQUICLongHeaders has checked the 20 bytes needed from the PN offset
	// for the header-protection sample and the complete declared packet length.
	if len(packet) > maxQUICUDPPayloadBytes {
		return ErrQUICLimit
	}
	key := quicKeyedCID{path: keyedQUICPaths(f)[1], cid: makeQUICCID(dcid)}
	if len(dcid) == 0 {
		key.clientPort = f.DstPort
	}
	var match *quicALPNDirection
	var failed *QUICProtectionObservation
	probesBefore := s.probes
	var plain []byte
	var number uint64
	for _, candidate := range s.handshakes[key] {
		if candidate.version != version {
			continue
		}
		if !s.probe(len(packet)) {
			return ErrQUICLimit
		}
		pn, p, err := candidate.decoder.openPacket(packet, pnOffset, candidate.expected, 0x0f, 0x0c)
		if err != nil {
			if candidate.coverage != nil && errors.Is(err, errQUICAuthentication) {
				failed = candidate.coverage
			}
			continue
		}
		if match != nil {
			return nil
		}
		match, plain, number = candidate, p, pn
	}
	if match == nil {
		if failed != nil && s.probes-probesBefore == 1 {
			failed.authenticationFailed(packetIndex)
		}
		return nil
	}
	if match.coverage != nil {
		match.coverage.authenticated(packetIndex)
	}
	match.expected = max(match.expected, number+1)
	var chunks []quicALPNChunk
	n := 0
	err := visitQUICCryptoFrames(plain, func(chunk quicCryptoChunk) error {
		if len(chunk.data) == 0 {
			return nil
		}
		if len(chunks) >= MaxQUICStreamFrames-s.fragments || len(chunk.data) > MaxKeyedQUICBytes-s.kept-n || len(chunk.data) > MaxQUICStreamInputBytes-match.bytes-n {
			return ErrQUICLimit
		}
		chunks = append(chunks, quicALPNChunk{chunk, packetIndex})
		n += len(chunk.data)
		return nil
	})
	if errors.Is(err, ErrQUICLimit) {
		return err
	}
	if err != nil {
		return nil
	}
	for i := range chunks {
		chunks[i].data = bytes.Clone(chunks[i].data)
	}
	match.chunks = append(match.chunks, chunks...)
	match.bytes += n
	s.kept += n
	s.fragments += len(chunks)
	return nil
}

// The server Handshake CRYPTO stream starts at offset zero with
// EncryptedExtensions (RFC 9001 section 4). Recover precisely that message.
// A gap in subsequent certificate data does not affect the ALPN observation.
func (d *quicALPNDirection) selection() *QUICALPNSelection {
	var header [4]byte
	if !d.copyPrefix(header[:], nil) || header[0] != 8 {
		return nil
	}
	n := 4 + (int(header[1])<<16 | int(header[2])<<8 | int(header[3]))
	if n > MaxQUICCryptoBytes || n > d.bytes {
		return nil
	}
	var selection QUICALPNSelection
	message := make([]byte, n)
	if !d.copyPrefix(message, &selection.PacketIndices) {
		return nil
	}
	selection.Protocol = encryptedExtensionsALPN(message[4:])
	if selection.Protocol == "" {
		return nil
	}
	return &selection
}

// Fill the requested prefix in capture order, rejecting gaps and different
// values at the same CRYPTO offset. Count the first owner of each byte once.
func (d *quicALPNDirection) copyPrefix(dst []byte, owners *[]int) bool {
	present := make([]bool, len(dst))
	missing := len(dst)
	for _, chunk := range d.chunks {
		start := int(chunk.offset)
		used := false
		for pos := start; pos < min(len(dst), start+len(chunk.data)); pos++ {
			b := chunk.data[pos-start]
			if present[pos] {
				if dst[pos] != b {
					return false
				}
				continue
			}
			present[pos], dst[pos] = true, b
			missing--
			used = true
		}
		if used && owners != nil && (len(*owners) == 0 || (*owners)[len(*owners)-1] != chunk.packet) {
			*owners = append(*owners, chunk.packet)
		}
	}
	return missing == 0
}

// The server ALPN extension contains exactly one nonempty protocol name.
func encryptedExtensionsALPN(body []byte) string {
	if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
		return ""
	}
	var protocol string
	for exts := body[2:]; len(exts) > 0; {
		if len(exts) < 4 {
			return ""
		}
		typ, size := binary.BigEndian.Uint16(exts), int(binary.BigEndian.Uint16(exts[2:]))
		exts = exts[4:]
		if size > len(exts) {
			return ""
		}
		ext := exts[:size]
		exts = exts[size:]
		if typ != 16 {
			continue
		}
		if protocol != "" || size < 4 || int(binary.BigEndian.Uint16(ext)) != size-2 || int(ext[2]) != size-3 {
			return ""
		}
		protocol = string(ext[3:])
	}
	return protocol
}
