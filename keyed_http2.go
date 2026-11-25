package pcap

import (
	"bytes"
	"cmp"
	"io"
	"net/netip"
	"slices"
)

// KeyedHTTP2TransactionID identifies the opening request HEADERS frame in a
// source capture. OpeningPacket is the first observed packet of the TCP opening.
// RecordWireOffset locates the TLS header in the client TCP stream, including
// any proxy prefix. OffsetInRecord locates the
// frame's first plaintext byte within that record. All offsets are zero-based.
type KeyedHTTP2TransactionID struct {
	OpeningPacket, RecordWireOffset, OffsetInRecord int
	StreamID                                        uint32
}

// HTTP2PlaintextRange is a zero-based half-open range of selected HTTP/2
// frame bytes in one authenticated direction. Adjacent frames on a selected
// stream can share a range. Each range includes frame headers and padding.
type HTTP2PlaintextRange struct {
	Start, End int
}

// KeyedHTTP2Transaction describes HTTP/2 evidence recovered from TLS.
// Request and Response use [HTTP2MessageEvidence] header and body semantics.
// Their PacketIndex and PacketPayloadOffset are -1 and their timestamps are
// zero. RequestPlaintextOffset and ResponsePlaintextOffset locate their HEADERS
// frames. ResponsePlaintextOffset is -1 when the final response is unavailable.
// Directional ranges locate selected frames, records contain their ciphertext,
// and PacketIndices lists the sorted distinct original packets supplying those
// records. SharedRecords reports other plaintext in a selected record.
// SharedPackets reports a packet also used by another selected transaction.
// A false value still permits control records or unselected streams in the packet.
// The caller owns the returned evidence.
type KeyedHTTP2Transaction struct {
	ID                                              KeyedHTTP2TransactionID
	FlowIndex                                       int
	Source, Destination                             netip.AddrPort
	Request                                         HTTP2MessageEvidence
	Informational                                   []HTTP2HeaderBlock
	Response                                        *HTTP2MessageEvidence
	StatusCode                                      int
	Pairing                                         HTTP2Pairing
	Reset, SharedRecords, SharedPackets             bool
	RequestPlaintextOffset, ResponsePlaintextOffset int
	RequestRanges, ResponseRanges                   []HTTP2PlaintextRange
	RequestRecords, ResponseRecords                 []TLSRecordEvidence
	PacketIndices                                   []int
	ClientCoverage, ServerCoverage                  TLSPlaintextCoverage
}

// KeyedHTTP2Transactions returns requests whose HEADERS follow an authenticated
// client preface and initial SETTINGS. It uses the key sources and limits of
// [Capture.KeyedHTTP1Transactions] and the body and header limits of
// [Capture.HTTP2Transactions]. Rows follow TCP opening and client plaintext
// order. Missing keys or an unobserved request produce no row.
func (c *Capture) KeyedHTTP2Transactions(data, extraKeyLog []byte) ([]KeyedHTTP2Transaction, error) {
	return scanKeyedHTTP2(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// KeyedHTTP2TransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.KeyedHTTP2Transactions]. Packet reads share [MaxReaderAtScanBytes].
func (c *Capture) KeyedHTTP2TransactionsFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]KeyedHTTP2Transaction, error) {
	return scanKeyedHTTP2(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}, extraKeyLog)
}

type keyedHTTP2Evidence struct {
	ranges     [2][]HTTP2PlaintextRange
	records    [2][]TLSRecordEvidence
	packets    []int
	extraBytes int
}

func (f *http2TransactionFrames) records() *tlsDirectionProvenance {
	if f.side == 0 {
		return &f.tls.client
	}
	return &f.tls.server
}

func (f *http2TransactionFrames) resetAt(end int) http2Reset {
	if f.dir != nil {
		packet, _ := f.dir.location(end - 1)
		return http2Reset{packet: packet.index, endSeq: f.dir.spans[0].seq + uint32(end)}
	}
	d := f.records()
	record := &d.records[d.recordAt(f.base+end-1)]
	wire := &f.tls.wire[f.side]
	packet, _ := wire.packetAt(record.wireEnd - 1) // The authenticated record mapper verified its full wire range.
	return http2Reset{packet: int(packet.index), endSeq: wire.seq + uint32(record.wireEnd)}
}

func (f *http2TransactionFrames) afterReset(start int, rst http2Reset) bool {
	if d := f.dir; d != nil {
		seg := d.spans[d.spanAt(start)].segment
		if d.dir.segments[seg].Flags&TCPFlagACK == 0 {
			return d.dir.packets[seg].index > rst.packet
		}
		return int32(d.acks[seg]-rst.endSeq) >= 0
	}
	d := f.records()
	record := &d.records[d.recordAt(f.base+start)]
	packet, ok := f.tls.wire[f.side].packetAt(record.wireStart)
	return !ok || int32(packet.ack-rst.endSeq) >= 0
}

func (ex *http2Exchange) acknowledged(server *http2TransactionFrames, start int) bool {
	client := ex.client
	if client.dir != nil {
		return http1Acknowledged(client.dir, server.dir, ex.requestEnd-1, start)
	}
	d := client.records()
	request := d.records[d.recordAt(client.base+ex.requestEnd-1)]
	return client.tls.acknowledged(request, server.base+start)
}

func (k *keyedHTTP2Evidence) add(f *http2TransactionFrames, start, end int, remaining *int) error {
	start, end = f.base+start, f.base+end
	ranges := k.ranges[f.side]
	if n := len(ranges); n > 0 && ranges[n-1].End == start {
		ranges[n-1].End = end
	} else {
		if *remaining == 0 {
			return ErrHTTPLimit
		}
		*remaining--
		k.ranges[f.side] = append(ranges, HTTP2PlaintextRange{start, end})
	}
	k.extraBytes -= end - start
	d := f.records()
	records := &k.records[f.side]
	for i := d.recordAt(start); i < len(d.records) && d.records[i].plainStart < end; i++ {
		r := &d.records[i]
		if r.plainEnd == r.plainStart {
			continue
		}
		if n := len(*records); n > 0 && (*records)[n-1].WireStart == r.wireStart {
			continue
		}
		if err := r.appendEvidence(records, &k.packets, remaining, false); err != nil {
			return err
		}
		k.extraBytes += r.plainEnd - r.plainStart
	}
	return nil
}

func scanKeyedHTTP2(source ipFrameSource, keys []byte) ([]KeyedHTTP2Transaction, error) {
	streams, err := scanTLSProvenance(source, keys)
	if err != nil {
		return nil, err
	}
	budget := newHTTP2TransactionBudget()
	budget.packetRefs = maxTLSProvenanceRanges
	var rows []KeyedHTTP2Transaction
	for i := range streams {
		s := &streams[i]
		firstRegular := s.firstRegularRecord()
		earlyEnd := 0
		if firstRegular > 0 {
			earlyEnd = s.client.records[firstRegular-1].plainEnd
		}
		opening := len(rows)
		for _, p := range [2]HTTP2PlaintextRange{{0, earlyEnd}, {earlyEnd, len(s.Client.Data)}} {
			data := s.Client.Data[p.Start:p.End]
			afterPreface, found := bytes.CutPrefix(data, HTTP2ClientPreface)
			if !found || !hasHTTP2InitialSettings(afterPreface) || afterPreface[4] != 0 {
				continue
			}
			client := http2TransactionFrames{tls: s, data: data, base: p.Start, anomalies: s.Client.Anomalies}
			rows, err = appendKeyedHTTP2(rows, &client, s.canPairHTTP(firstRegular), &budget)
			if err != nil {
				return nil, err
			}
		}
		if len(rows)-opening < 2 {
			continue
		}
		// A packet can carry frames for multiple streams in a shared record,
		// or separate records for different streams.
		owners := make(map[int]int)
		for j := opening; j < len(rows); j++ {
			for _, idx := range rows[j].PacketIndices {
				if other, ok := owners[idx]; ok {
					rows[other].SharedPackets = true
					rows[j].SharedPackets = true
				} else {
					owners[idx] = j
				}
			}
		}
		slices.SortFunc(rows[opening:], func(a, b KeyedHTTP2Transaction) int {
			return cmp.Compare(a.RequestPlaintextOffset, b.RequestPlaintextOffset)
		})
	}
	return rows, nil
}

func appendKeyedHTTP2(rows []KeyedHTTP2Transaction, client *http2TransactionFrames, canPair bool, budget *http2TransactionBudget) ([]KeyedHTTP2Transaction, error) {
	s := client.tls
	requests, err := client.read(true, &budget.headers)
	if err != nil {
		return nil, err
	}
	cc, sc := s.client.coverage(len(s.Client.Data)), s.server.coverage(len(s.Server.Data))
	responses := http2TransactionFrames{incomplete: len(s.Server.Data) > 0 || sc.IncompleteTail || sc.OpaquePrefix}
	if canPair && hasHTTP2InitialSettings(s.Server.Data) && s.Server.Data[4] == 0 {
		server := http2TransactionFrames{tls: s, side: 1, data: s.Server.Data, anomalies: s.Server.Anomalies}
		responses, err = server.read(false, &budget.headers)
		if err != nil {
			return nil, err
		}
		responses.incomplete = responses.incomplete || sc.IncompleteTail
	}
	streams, err := requests.exchanges(&responses, budget)
	if err != nil {
		return nil, err
	}
	for _, ex := range streams {
		if err := ex.finish(responses.incomplete, s.Client.Anomalies.OverlapConflict, budget); err != nil {
			return nil, err
		}
		ev := ex.keyed
		slices.Sort(ev.packets)
		row := &ex.row
		start := client.base + ex.requestStart
		record := s.client.records[s.client.recordAt(start)]
		rows = append(rows, KeyedHTTP2Transaction{
			ID:        KeyedHTTP2TransactionID{s.openingPacket, record.wireStart, start - record.plainStart, row.StreamID},
			FlowIndex: s.FlowIndex, Source: netip.AddrPortFrom(s.SrcAddr, s.SrcPort), Destination: netip.AddrPortFrom(s.DstAddr, s.DstPort),
			Request: row.Request, Informational: row.Informational, Response: row.Response, StatusCode: row.StatusCode, Pairing: row.Pairing, Reset: row.Reset,
			RequestPlaintextOffset: start, ResponsePlaintextOffset: ex.responseStart,
			RequestRanges: ev.ranges[0], ResponseRanges: ev.ranges[1], RequestRecords: ev.records[0], ResponseRecords: ev.records[1],
			SharedRecords: ev.extraBytes > 0, PacketIndices: slices.Compact(ev.packets),
			ClientCoverage: cc, ServerCoverage: sc,
		})
	}
	return rows, nil
}
