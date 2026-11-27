package pcap

import (
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net/netip"
	"slices"
)

// DoQMessageState describes one direction of an observed DNS-over-QUIC stream.
type DoQMessageState uint8

const (
	// DoQUnseen indicates no stream data or reset for this direction.
	DoQUnseen DoQMessageState = iota
	// DoQComplete indicates one complete, valid length-framed DNS message.
	DoQComplete
	// DoQIncomplete indicates missing stream bytes or an unobserved FIN.
	DoQIncomplete
	// DoQReset indicates an observed RESET_STREAM in this direction.
	DoQReset
	// DoQMalformed indicates invalid framing or DNS structure.
	DoQMalformed
	// DoQUnsupported identifies query types outside ordinary DoQ lookups.
	DoQUnsupported
	// DoQLimited indicates a DNS parser limit.
	DoQLimited
)

// DoQMessage describes a directional observation. DNS is present only for
// [DoQComplete]. PacketIndices locates the authenticated stream bytes and
// observed end or reset in the original capture, including retransmissions.
type DoQMessage struct {
	State         DoQMessageState
	DNS           *DNSMessage
	PacketIndices []int
}

// DoQTransaction associates observations on a client-initiated bidirectional
// stream. StreamID is scoped to the QUIC connection. ALPNPacketIndex locates
// the first packet contributing to the authenticated doq selection and
// FlowIndex is the index used by [Capture.QUIC].
type DoQTransaction struct {
	FlowIndex, ALPNPacketIndex int
	StreamID                   uint64
	Client, Resolver           netip.AddrPort
	Query, Reply               DoQMessage
}

// DoQTransactions reports ordinary DNS exchanges on connections with
// authenticated server selection of the doq ALPN. Results follow observed
// connection order and then ascending stream ID. Each direction requires a
// clean FIN and exactly one length-framed DNS message with ID zero to report
// a completed lookup. AXFR and IXFR are recognized as unsupported.
// Use [Capture.AnalyzeKeyedQUIC] when protection coverage is also needed.
func (c *Capture) DoQTransactions(data, extraKeyLog []byte) ([]DoQTransaction, error) {
	connections, err := c.KeyedQUICWithALPN(data, extraKeyLog)
	if err != nil {
		return nil, err
	}
	return doqTransactions(connections)
}

// DoQTransactionsFromReaderAt is the seekable equivalent of
// [Capture.DoQTransactions]. The capture scan shares [MaxReaderAtScanBytes]
// across metadata and payload reads.
func (c *Capture) DoQTransactionsFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]DoQTransaction, error) {
	connections, err := c.KeyedQUICWithALPNFromReaderAt(r, extraKeyLog)
	if err != nil {
		return nil, err
	}
	return doqTransactions(connections)
}

func doqTransactions(connections []KeyedQUICRecord) ([]DoQTransaction, error) {
	var rows []DoQTransaction
	remaining := MaxDNSMessagesPerScan
	for _, conn := range connections {
		if conn.ALPN == nil || conn.ALPN.Protocol != "doq" || len(conn.ALPN.PacketIndices) == 0 {
			continue
		}
		type exchange struct {
			DoQTransaction
			transfer bool
		}
		byID := make(map[uint64]exchange)
		for direction, packets := range [2][]QUIC1RTTPacket{conn.Client, conn.Server} {
			streams, err := locateQUICStreams(packets)
			if err != nil {
				return nil, err
			}
			for _, stream := range streams {
				id := stream.stream.ID
				if id&3 != 0 {
					continue
				}
				if remaining == 0 {
					return nil, ErrDNSLimit
				}
				remaining--
				row, present := byID[id]
				if !present {
					row.DoQTransaction = DoQTransaction{FlowIndex: conn.FlowIndex, ALPNPacketIndex: conn.ALPN.PacketIndices[0],
						StreamID: id, Client: netip.AddrPortFrom(conn.SrcAddr, conn.SrcPort),
						Resolver: netip.AddrPortFrom(conn.DstAddr, conn.DstPort)}
				}
				switch {
				case direction == 0:
					row.Query, row.transfer = parseDoQMessage(stream, false)
				case row.transfer:
					row.Reply = doqTransferReply(stream, &remaining)
				default:
					row.Reply, _ = parseDoQMessage(stream, true)
				}
				byID[id] = row
			}
		}
		for _, id := range slices.Sorted(maps.Keys(byID)) {
			rows = append(rows, byID[id].DoQTransaction)
		}
	}
	return rows, nil
}

func doqStreamCoverage(observed quicLocatedStream) DoQMessage {
	out := DoQMessage{PacketIndices: observed.packets}
	switch stream := observed.stream; {
	case stream.Reset:
		out.State = DoQReset
	case stream.Gap || !stream.Complete:
		out.State = DoQIncomplete
	default:
		out.State = DoQComplete
	}
	return out
}

func parseDoQMessage(observed quicLocatedStream, reply bool) (DoQMessage, bool) {
	out := doqStreamCoverage(observed)
	if out.State != DoQComplete {
		return out, false
	}
	data := observed.stream.Data
	if len(data) < 14 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		out.State = DoQMalformed
		return out, false
	}
	wire := data[2:]
	message, err := ParseDNS(wire)
	switch {
	case errors.Is(err, ErrDNSLimit):
		out.State = DoQLimited
	case err != nil || message.Anomalies.Any() || message.TransactionID != 0 || message.IsResponse != reply || !validDoQOptions(wire, message.Additionals):
		out.State = DoQMalformed
	case message.Opcode != 0 || !reply && len(message.Questions) != 1:
		out.State = DoQUnsupported
	case len(message.Questions) == 1 && (message.Questions[0].Type == 251 || message.Questions[0].Type == 252):
		out.State = DoQUnsupported
		return out, !reply
	default:
		out.DNS = &message
	}
	return out, false
}

func validDoQOptions(wire []byte, additionals []DNSResourceRecord) bool {
	for _, record := range additionals {
		if record.Type != DNSTypeOPT {
			continue
		}
		start, end := int(record.DataOffset), int(record.DataOffset)+int(record.DataLength)
		if start > len(wire) || end > len(wire) {
			return false
		}
		for options := wire[start:end]; len(options) != 0; {
			if len(options) < 4 {
				return false
			}
			code, size := binary.BigEndian.Uint16(options), int(binary.BigEndian.Uint16(options[2:]))
			// RFC 9250 forbids the EDNS TCP keepalive option on a DoQ stream.
			if code == 11 || size > len(options)-4 {
				return false
			}
			options = options[4+size:]
		}
	}
	return true
}

func doqTransferReply(observed quicLocatedStream, remaining *int) DoQMessage {
	out := doqStreamCoverage(observed)
	if out.State != DoQComplete {
		return out
	}
	// Only delimit the messages of an identified transfer. Its DNS contents
	// are outside this scan's scope.
	wire := observed.stream.Data
	out.State = DoQMalformed
	if len(wire) == 0 {
		return out
	}
	for first := true; len(wire) > 0; first = false {
		if !first {
			if *remaining == 0 {
				out.State = DoQLimited
				return out
			}
			(*remaining)--
		}
		if len(wire) < 14 {
			return out
		}
		n := int(binary.BigEndian.Uint16(wire))
		if n < 12 || n > len(wire)-2 || binary.BigEndian.Uint16(wire[2:]) != 0 || wire[4]&0x80 == 0 {
			return out
		}
		wire = wire[2+n:]
	}
	out.State = DoQUnsupported
	return out
}
