package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
)

// Limits shared by both directions and all connections in a keyed QUIC scan.
const (
	MaxKeyedQUICProbes     = 16_384
	MaxKeyedQUICProbeBytes = 64 << 20
	MaxKeyedQUICBytes      = 16 << 20
)

// QUIC1RTTPacket holds owned, authenticated frame bytes and their capture
// provenance. UDPOffset is the short header's offset within the UDP payload.
type QUIC1RTTPacket struct {
	PacketIndex  int
	UDPOffset    int
	PacketNumber uint64
	Payload      []byte
}

// KeyedQUICRecord associates 1-RTT packets in capture order with the
// Initial exchange and capture-wide flow index from [Capture.QUIC]. Client
// and Server identify the sender. Each side can be reassembled independently
// with [ReassembleQUIC1RTTStreams].
type KeyedQUICRecord struct {
	QUICRecord
	Client []QUIC1RTTPacket
	Server []QUIC1RTTPacket
}

// KeyedQUIC finds QUIC v1/v2 AES-GCM 1-RTT packets using the initial traffic
// secrets from [Capture.TLSKeyLog]. It seeds association from the observed
// ClientHello, ServerHello and Initial source connection IDs, and returns
// packets only when one candidate authenticates. It reads complete UDP
// datagrams, including trailing short headers in coalesced datagrams.
// An empty connection ID requires the original tuple. A nonempty ID can
// associate a client port change on the same IP pair and server port.
// Results follow Initial exchange order and contain at least one packet.
// A scan or resource-limit error returns no results.
func (c *Capture) KeyedQUIC(data, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	return scanKeyedQUIC(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// KeyedQUICFromReaderAt is the bounded ReaderAt equivalent of [Capture.KeyedQUIC].
// Both passes share [MaxReaderAtScanBytes].
func (c *Capture) KeyedQUICFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	// Charge reads from both walks directly to the original source.
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	return scanKeyedQUIC(ipFrameSource{capture: c, reader: &budget, needsPayload: quicInitialPayload}, extraKeyLog)
}

type quicKeyedPath struct {
	client     netip.Addr
	server     netip.AddrPort
	fromServer bool
}

type quicKeyedCID struct {
	path       quicKeyedPath
	cid        quicCID
	clientPort uint16 // Zero for a nonempty CID, which can survive rebinding.
}

type quicKeyedDirection struct {
	decoder  *QUIC1RTTDecoder
	expected uint64
	packets  []QUIC1RTTPacket
	bytes    int
}

type quicKeyedConnection struct {
	initial        QUICRecord
	client, server quicKeyedDirection
}

type quicKeyedScan struct {
	lengths                  map[quicKeyedPath]uint32
	candidates               map[quicKeyedCID][]*quicKeyedDirection
	probes, probeBytes, kept int
}

func scanKeyedQUIC(source ipFrameSource, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	keys, err := source.capture.TLSKeyLog(extraKeyLog)
	if err != nil || len(keys.Entries) == 0 {
		return nil, err
	}
	var serverIDs []quicCID
	initials, err := scanQUICInitials(source, &serverIDs)
	if err != nil {
		return nil, err
	}
	scan := quicKeyedScan{
		lengths:    make(map[quicKeyedPath]uint32),
		candidates: make(map[quicKeyedCID][]*quicKeyedDirection),
	}
	connections := make([]quicKeyedConnection, len(initials))
	for i, initial := range initials {
		hs := &initial.Handshake
		if !hs.HasServerHello {
			continue
		}
		entry, ok := keys.Entries[hs.ClientHello.Random]
		if !ok {
			continue
		}
		conn := &connections[i]
		conn.initial = initial
		path := quicKeyedPath{client: initial.SrcAddr, server: netip.AddrPortFrom(initial.DstAddr, initial.DstPort)}
		scan.register(path, initial.SrcPort, serverIDs[i], &conn.client, hs, entry.ClientTrafficSecret0)
		path.fromServer = true
		scan.register(path, initial.SrcPort, makeQUICCID(hs.SCID), &conn.server, hs, entry.ServerTrafficSecret0)
	}
	if len(scan.candidates) == 0 {
		return nil, nil
	}
	if source.reader != nil {
		source.needsPayload = scan.needsPayload
	}
	if err := source.walk(scan.visit); err != nil {
		return nil, err
	}
	var out []KeyedQUICRecord
	for i := range connections {
		c := &connections[i]
		if len(c.client.packets)+len(c.server.packets) != 0 {
			out = append(out, KeyedQUICRecord{QUICRecord: c.initial, Client: c.client.packets, Server: c.server.packets})
		}
	}
	return out, nil
}

func (s *quicKeyedScan) register(path quicKeyedPath, clientPort uint16, cid quicCID, dir *quicKeyedDirection, hs *QUICHandshake, secret []byte) {
	if len(secret) == 0 {
		return
	}
	decoder, err := NewQUIC1RTTDecoder(hs.Version, hs.ServerHello.CipherSuite, secret)
	if err != nil {
		return
	}
	dir.decoder = decoder
	s.lengths[path] |= 1 << cid.length
	if cid.length != 0 {
		clientPort = 0
	}
	key := quicKeyedCID{path: path, cid: cid, clientPort: clientPort}
	s.candidates[key] = append(s.candidates[key], dir)
}

func keyedQUICPaths(f Frame) [2]quicKeyedPath {
	return [2]quicKeyedPath{
		{client: f.SrcAddr, server: netip.AddrPortFrom(f.DstAddr, f.DstPort)},
		{client: f.DstAddr, server: netip.AddrPortFrom(f.SrcAddr, f.SrcPort), fromServer: true},
	}
}

func (s *quicKeyedScan) needsPayload(f Frame, _ []byte) bool {
	if f.IPProtocol != IPProtoUDP || f.mayContainUDPFragment() || f.PayloadLength < 21 {
		return false
	}
	paths := keyedQUICPaths(f)
	return s.lengths[paths[0]]|s.lengths[paths[1]] != 0
}

func (s *quicKeyedScan) visit(record PacketRecord, frame Frame, datagram []byte) error {
	if !s.needsPayload(frame, nil) {
		return nil
	}
	packet := quicShortTail(datagram)
	if len(packet) < 21 {
		return nil
	}
	dir, number, payload, err := s.authenticate(frame, packet)
	if err != nil || dir == nil {
		return err
	}
	if len(dir.packets) >= MaxQUICStreamPackets || len(payload) > MaxQUICStreamInputBytes-dir.bytes ||
		len(payload) > MaxKeyedQUICBytes-s.kept {
		return ErrQUICLimit
	}
	dir.expected = max(dir.expected, number+1)
	dir.packets = append(dir.packets, QUIC1RTTPacket{
		PacketIndex: record.Index, UDPOffset: len(datagram) - len(packet),
		PacketNumber: number, Payload: payload,
	})
	dir.bytes += len(payload)
	s.kept += len(payload)
	return nil
}

func (s *quicKeyedScan) authenticate(frame Frame, packet []byte) (*quicKeyedDirection, uint64, []byte, error) {
	var match *quicKeyedDirection
	var number uint64
	var payload []byte
	ports := [2]uint16{frame.SrcPort, frame.DstPort}
	for i, path := range keyedQUICPaths(frame) {
		for sizes := s.lengths[path]; sizes != 0; sizes &= sizes - 1 {
			size := bits.TrailingZeros32(sizes)
			if len(packet) < 21+size {
				break
			}
			id := packet[1 : 1+size]
			key := quicKeyedCID{path: path, cid: makeQUICCID(id)}
			if size == 0 {
				key.clientPort = ports[i]
			}
			for _, candidate := range s.candidates[key] {
				if s.probes >= MaxKeyedQUICProbes || len(packet) > MaxKeyedQUICProbeBytes-s.probeBytes {
					return nil, 0, nil, ErrQUICLimit
				}
				s.probes++
				s.probeBytes += len(packet)
				pn, plain, err := candidate.decoder.Open(packet, id, candidate.expected)
				if err != nil {
					continue
				}
				if match != nil {
					return nil, 0, nil, nil // More than one candidate authenticated.
				}
				match, number, payload = candidate, pn, plain
			}
		}
	}
	return match, number, payload, nil
}

// A short header consumes the remainder of its datagram. Skip length-bearing
// long headers only. Retry and Version Negotiation have no packet length.
func quicShortTail(datagram []byte) []byte {
	for count := 0; len(datagram) > 0 && datagram[0]&0x80 != 0; count++ {
		if count == 16 || len(datagram) < 7 {
			return nil
		}
		typ := (datagram[0] >> 4) & 3
		switch binary.BigEndian.Uint32(datagram[1:5]) {
		case QUICVersion1:
		case QUICVersion2:
			typ = (typ + 3) & 3 // Normalize the version 2 type rotation.
		default:
			return nil
		}
		if typ == 3 {
			return nil
		}
		_, _, pos, ok := quicConnectionIDs(datagram)
		if !ok {
			return nil
		}
		if typ == 0 {
			length, n, ok := ReadQUICVarint(datagram[pos:])
			if !ok || length > uint64(len(datagram)-pos-n) {
				return nil
			}
			pos += n + int(length)
		}
		length, n, ok := ReadQUICVarint(datagram[pos:])
		if !ok || length < 20 || length > uint64(len(datagram)-pos-n) {
			return nil
		}
		datagram = datagram[pos+n+int(length):]
	}
	return datagram
}
