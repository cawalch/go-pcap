package pcap

import (
	"encoding/binary"
	"errors"
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
	PacketIndex   int
	UDPOffset     int
	PacketNumber  uint64
	KeyGeneration uint8 // Authenticated application key generation, starting at zero.
	Payload       []byte
}

// KeyedQUICRecord associates 1-RTT packets in capture order with the
// Initial exchange and capture-wide flow index from [Capture.QUIC]. Client
// and Server identify the sender. Each side can be reassembled independently
// with [ReassembleQUIC1RTTStreams].
type KeyedQUICRecord struct {
	QUICRecord
	Client []QUIC1RTTPacket
	Server []QUIC1RTTPacket
	// ALPN is populated by KeyedQUICWithALPN when the server's selection
	// is present in authenticated Handshake-level CRYPTO data.
	ALPN *QUICALPNSelection
}

// KeyedQUIC finds QUIC v1/v2 AES-GCM 1-RTT packets using the initial traffic
// secrets from [Capture.TLSKeyLog]. It seeds association from the observed
// ClientHello, ServerHello and Initial source connection IDs, and returns
// packets only when one candidate authenticates. It reads complete UDP
// datagrams, including trailing short headers in coalesced datagrams.
// Authenticated NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames update the
// eligible destinations in capture order. An empty ID requires the original
// tuple. A nonempty ID can follow a client port change on the same IP pair
// and server port. Standalone short-header packets can follow a client IP
// change on that server endpoint using IDs learned from authenticated
// NEW_CONNECTION_ID frames. Each learned ID follows only the first client
// IP on which it authenticates.
// The IP addresses themselves are outside QUIC packet authentication.
// Results follow Initial exchange order and contain at least one packet.
// A scan or resource-limit error returns no results.
func (c *Capture) KeyedQUIC(data, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	return scanKeyedQUIC(ipFrameSource{capture: c, data: data}, extraKeyLog, false, nil)
}

// KeyedQUICFromReaderAt is the bounded ReaderAt equivalent of [Capture.KeyedQUIC].
// Both passes share [MaxReaderAtScanBytes].
func (c *Capture) KeyedQUICFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedQUICRecord, error) {
	return c.keyedQUICReaderAt(r, extraKeyLog, false, nil)
}

func (c *Capture) keyedQUICReaderAt(r io.ReaderAt, extraKeyLog []byte, alpn bool, coverage *[]QUICConnectionCoverage) ([]KeyedQUICRecord, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	// Charge reads from both walks directly to the original source.
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	return scanKeyedQUIC(ipFrameSource{capture: c, reader: &budget, needsPayload: quicInitialPayload}, extraKeyLog, alpn, coverage)
}

type quicKeyedPath struct {
	client     netip.Addr
	server     netip.AddrPort
	fromServer bool
}

func (p quicKeyedPath) anyClient() quicKeyedPath {
	p.client = netip.Addr{}
	return p
}

type quicKeyedCID struct {
	path       quicKeyedPath
	cid        quicCID
	clientPort uint16 // Zero for a nonempty CID, which can survive rebinding.
}

type quicKeyedDirection struct {
	coverage  *QUICProtectionObservation
	peer      *quicKeyedDirection
	initial   quicKeyedCID
	packetCID quicCID
	ids       *quicCIDHistory
	decoder   *QUIC1RTTKeyTracker
	expected  uint64
	packets   []QUIC1RTTPacket
	bytes     int
}

type quicKeyedConnection struct {
	initial        QUICRecord
	client, server quicKeyedDirection
	handshake      *quicALPNDirection
}

type quicKeyedScan struct {
	lengths                  map[quicKeyedPath]uint32
	candidates               map[quicKeyedCID][]*quicKeyedDirection
	handshakes               map[quicKeyedCID][]*quicALPNDirection
	fragments                int
	learnedIDs               int
	probes, probeBytes, kept int
}

func scanKeyedQUIC(source ipFrameSource, extraKeyLog []byte, alpn bool, coverage *[]QUICConnectionCoverage) ([]KeyedQUICRecord, error) {
	keyLog := source.capture.TLSKeyLog
	if coverage != nil {
		keyLog = source.capture.boundedTLSKeyLog
	}
	keys, err := keyLog(extraKeyLog)
	if err != nil || (coverage == nil && len(keys.Entries) == 0) {
		return nil, err
	}
	var contexts []quicInitialContext
	initials, err := scanQUIC(source, &contexts)
	if err != nil {
		return nil, err
	}
	if len(initials) == 0 {
		return nil, nil
	}
	if coverage != nil {
		*coverage = make([]QUICConnectionCoverage, len(initials))
	}
	scan := quicKeyedScan{
		lengths:    make(map[quicKeyedPath]uint32),
		candidates: make(map[quicKeyedCID][]*quicKeyedDirection),
	}
	connections := make([]quicKeyedConnection, len(initials))
	for i, initial := range initials {
		hs := &initial.Handshake
		entry, hasKeys := keys.Entries[hs.ClientHello.Random]
		conn := &connections[i]
		var evidence *QUICConnectionCoverage
		if coverage != nil {
			evidence = &(*coverage)[i]
			*evidence = quicConnectionCoverage(initial, contexts[i].packetIndex, entry)
			conn.client.coverage, conn.server.coverage = &evidence.Client1RTT, &evidence.Server1RTT
		}
		if !hs.HasServerHello || !hasKeys {
			continue
		}
		conn.initial = initial
		conn.client.peer, conn.server.peer = &conn.server, &conn.client
		path := quicKeyedPath{client: initial.SrcAddr, server: netip.AddrPortFrom(initial.DstAddr, initial.DstPort)}
		scan.register(path, initial.SrcPort, contexts[i].serverID, &conn.client, hs, entry.ClientTrafficSecret0)
		path.fromServer = true
		cid := makeQUICCID(hs.SCID)
		scan.register(path, initial.SrcPort, cid, &conn.server, hs, entry.ServerTrafficSecret0)
		if alpn && len(entry.ServerHandshakeSecret) != 0 {
			decoder, err := NewQUIC1RTTDecoder(hs.Version, hs.ServerHello.CipherSuite, entry.ServerHandshakeSecret)
			if err == nil {
				conn.handshake = &quicALPNDirection{decoder: decoder, version: hs.Version}
				if evidence != nil {
					conn.handshake.coverage = &evidence.ServerHandshake
				}
				if scan.handshakes == nil {
					scan.handshakes = make(map[quicKeyedCID][]*quicALPNDirection)
				}
				key := scan.registerCID(path, initial.SrcPort, cid)
				scan.handshakes[key] = append(scan.handshakes[key], conn.handshake)
			}
		}
	}
	if len(scan.candidates)+len(scan.handshakes) == 0 {
		return nil, nil
	}
	visit := scan.visit
	if source.reader != nil {
		source.needsPayload = scan.needsPayload
		// The visitor retains only owned, decrypted bytes.
		source.borrowUDPPayload = true
	} else {
		visit = func(record PacketRecord, frame Frame, datagram []byte) error {
			if !scan.needsPayload(frame, datagram) {
				return nil
			}
			return scan.visit(record, frame, datagram)
		}
	}
	if err := source.walk(visit); err != nil {
		return nil, err
	}
	var out []KeyedQUICRecord
	for i := range connections {
		c := &connections[i]
		if coverage != nil {
			for _, dir := range [2]*quicKeyedDirection{&c.client, &c.server} {
				if len(dir.packets) != 0 {
					dir.coverage.authenticated(dir.packets[0].PacketIndex)
				}
			}
		}
		var selection *QUICALPNSelection
		if c.handshake != nil {
			selection = c.handshake.selection()
		}
		if len(c.client.packets)+len(c.server.packets) != 0 || selection != nil {
			if coverage != nil {
				(*coverage)[i].RecordIndex = len(out)
			}
			out = append(out, KeyedQUICRecord{QUICRecord: c.initial, Client: c.client.packets, Server: c.server.packets, ALPN: selection})
		}
	}
	return out, nil
}

func (s *quicKeyedScan) register(path quicKeyedPath, clientPort uint16, cid quicCID, dir *quicKeyedDirection, hs *QUICHandshake, secret []byte) {
	if len(secret) == 0 {
		return
	}
	decoder, err := NewQUIC1RTTKeyTracker(hs.Version, hs.ServerHello.CipherSuite, secret)
	if err != nil {
		return
	}
	dir.decoder = decoder
	key := s.registerCID(path, clientPort, cid)
	dir.initial = key
	s.candidates[key] = append(s.candidates[key], dir)
}

func (s *quicKeyedScan) registerCID(path quicKeyedPath, clientPort uint16, cid quicCID) quicKeyedCID {
	s.lengths[path] |= 1 << cid.length
	if cid.length != 0 {
		clientPort = 0
	}
	return quicKeyedCID{path: path, cid: cid, clientPort: clientPort}
}

func keyedQUICPaths(f Frame) [2]quicKeyedPath {
	return [2]quicKeyedPath{
		{client: f.SrcAddr, server: netip.AddrPortFrom(f.DstAddr, f.DstPort)},
		{client: f.DstAddr, server: netip.AddrPortFrom(f.SrcAddr, f.SrcPort), fromServer: true},
	}
}

func (s *quicKeyedScan) needsPayload(f Frame, prefix []byte) bool {
	if f.IPProtocol != IPProtoUDP || f.mayContainUDPFragment() || f.PayloadLength < 21 {
		return false
	}
	paths := keyedQUICPaths(f)
	if s.lengths[paths[0]]|s.lengths[paths[1]] != 0 {
		return true
	}
	if len(prefix) != 0 && prefix[0]&0x80 != 0 {
		return false
	}
	for _, path := range paths {
		path = path.anyClient()
		for sizes := s.lengths[path]; sizes != 0; sizes &= sizes - 1 {
			size := bits.TrailingZeros32(sizes)
			if f.PayloadLength < uint32(21+size) {
				break
			}
			if len(prefix) < 1+size {
				return true
			}
			cid := makeQUICCID(prefix[1 : 1+size])
			if len(s.candidates[quicKeyedCID{path: path, cid: cid}]) != 0 {
				return true
			}
		}
	}
	return false
}

func (s *quicKeyedScan) visit(record PacketRecord, frame Frame, datagram []byte) error {
	if len(datagram) < 21 {
		return nil
	}
	var visit func(uint32, []byte, int, []byte) error
	if s.handshakes != nil {
		visit = func(version uint32, dcid []byte, pnOffset int, packet []byte) error {
			return s.observeHandshake(record.Index, frame, version, dcid, pnOffset, packet)
		}
	}
	packet, err := walkQUICLongHeaders(datagram, visit)
	if err != nil {
		return err
	}
	if len(packet) < 21 {
		return nil
	}
	dir, number, generation, payload, err := s.authenticate(record.Index, frame, packet, len(packet) != len(datagram))
	if err != nil || dir == nil {
		return err
	}
	if len(dir.packets) >= MaxQUICStreamPackets || len(payload) > MaxQUICStreamInputBytes-dir.bytes ||
		len(payload) > MaxKeyedQUICBytes-s.kept {
		return ErrQUICLimit
	}
	if err := dir.decoder.accept(number, generation); err != nil {
		return err
	}
	dir.expected = max(dir.expected, number+1)
	dir.packets = append(dir.packets, QUIC1RTTPacket{
		PacketIndex: record.Index, UDPOffset: len(datagram) - len(packet),
		PacketNumber: number, KeyGeneration: generation, Payload: payload,
	})
	dir.bytes += len(payload)
	s.kept += len(payload)
	return s.observeCIDs(dir, number, payload)
}

func (s *quicKeyedScan) authenticate(packetIndex int, frame Frame, packet []byte, coalesced bool) (*quicKeyedDirection, uint64, uint8, []byte, error) {
	var match *quicKeyedDirection
	var failed *QUICProtectionObservation
	probesBefore := s.probes
	var idUsed quicCID
	var learnedID *quicCIDEntry
	var clientIP netip.Addr
	var number uint64
	var generation uint8
	var payload []byte
	ports := [2]uint16{frame.SrcPort, frame.DstPort}
	paths := keyedQUICPaths(frame)
	for i, path := range [4]quicKeyedPath{paths[0], paths[1], paths[0].anyClient(), paths[1].anyClient()} {
		actual := paths[i%2]
		for sizes := s.lengths[path]; sizes != 0; sizes &= sizes - 1 {
			size := bits.TrailingZeros32(sizes)
			if len(packet) < 21+size {
				break
			}
			id := packet[1 : 1+size]
			key := quicKeyedCID{path: path, cid: makeQUICCID(id)}
			if size == 0 {
				key.clientPort = ports[i%2]
			}
			for _, candidate := range s.candidates[key] {
				if !s.probe(len(packet)) {
					return nil, 0, 0, nil, ErrQUICLimit
				}
				var learned *quicCIDEntry
				if !path.client.IsValid() {
					history := candidate.ids
					learned = history.bySequence[history.byID[key.cid]]
					if learned.client.IsValid() && learned.client != actual.client {
						continue
					}
					// A retired, previously unobserved ID cannot establish a new IP.
					if actual.client != candidate.initial.path.client && (coalesced || learned.retired && !learned.client.IsValid()) {
						continue
					}
				}
				pn, proposed, plain, err := candidate.decoder.headerDecoder.open(packet, id, candidate.expected, candidate.decoder)
				if err != nil {
					if candidate.coverage != nil && errors.Is(err, errQUICAuthentication) {
						failed = candidate.coverage
					}
					continue
				}
				if match != nil {
					return nil, 0, 0, nil, nil // More than one candidate authenticated.
				}
				match, number, generation, payload, idUsed = candidate, pn, proposed, plain, key.cid
				learnedID, clientIP = learned, actual.client
			}
		}
	}
	if match == nil && failed != nil && s.probes-probesBefore == 1 {
		failed.authenticationFailed(packetIndex)
	}
	if match != nil {
		if !match.ids.accepts(idUsed, number) {
			return nil, 0, 0, nil, nil
		}
		match.packetCID = idUsed
		if learnedID != nil {
			learnedID.client = clientIP
		}
	}
	return match, number, generation, payload, nil
}

func (s *quicKeyedScan) probe(size int) bool {
	if s.probes >= MaxKeyedQUICProbes || size > MaxKeyedQUICProbeBytes-s.probeBytes {
		return false
	}
	s.probes++
	s.probeBytes += size
	return true
}

// A short header consumes the remainder of its datagram. Skip length-bearing
// long headers only. Retry and Version Negotiation have no packet length.
func walkQUICLongHeaders(datagram []byte, visitHandshake func(uint32, []byte, int, []byte) error) ([]byte, error) {
	for count := 0; len(datagram) > 0 && datagram[0]&0x80 != 0; count++ {
		if count == 16 || len(datagram) < 7 {
			return nil, nil
		}
		typ := (datagram[0] >> 4) & 3
		version := binary.BigEndian.Uint32(datagram[1:5])
		switch version {
		case QUICVersion1:
		case QUICVersion2:
			typ = (typ + 3) & 3 // Normalize the version 2 type rotation.
		default:
			return nil, nil
		}
		if typ == 3 {
			return nil, nil
		}
		dcid, _, pos, ok := quicConnectionIDs(datagram)
		if !ok {
			return nil, nil
		}
		if typ == 0 {
			length, n, ok := ReadQUICVarint(datagram[pos:])
			if !ok || length > uint64(len(datagram)-pos-n) {
				return nil, nil
			}
			pos += n + int(length)
		}
		length, n, ok := ReadQUICVarint(datagram[pos:])
		if !ok || length < 20 || length > uint64(len(datagram)-pos-n) {
			return nil, nil
		}
		end := pos + n + int(length)
		if typ == 2 && visitHandshake != nil {
			if err := visitHandshake(version, dcid, pos+n, datagram[:end]); err != nil {
				return nil, err
			}
		}
		datagram = datagram[end:]
	}
	return datagram, nil
}
