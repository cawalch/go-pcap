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
		byID := make(map[uint64]DoQTransaction)
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
					row = DoQTransaction{FlowIndex: conn.FlowIndex, ALPNPacketIndex: conn.ALPN.PacketIndices[0],
						StreamID: id, Client: netip.AddrPortFrom(conn.SrcAddr, conn.SrcPort),
						Resolver: netip.AddrPortFrom(conn.DstAddr, conn.DstPort)}
				}
				msg := parseDoQMessage(stream, direction == 1)
				if direction == 0 {
					row.Query = msg
				} else {
					row.Reply = msg
				}
				byID[id] = row
			}
		}
		for _, id := range slices.Sorted(maps.Keys(byID)) {
			row := byID[id]
			// A response on a zone-transfer stream cannot be an ordinary
			// lookup result even when its first framing is available.
			if row.Query.State == DoQUnsupported && row.Reply.State == DoQComplete {
				row.Reply.State, row.Reply.DNS = DoQUnsupported, nil
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseDoQMessage(observed quicLocatedStream, reply bool) DoQMessage {
	stream := observed.stream
	out := DoQMessage{PacketIndices: observed.packets}
	switch {
	case stream.Reset:
		out.State = DoQReset
		return out
	case stream.Gap || !stream.Complete:
		out.State = DoQIncomplete
		return out
	case len(stream.Data) < 2:
		out.State = DoQMalformed
		return out
	}
	size := int(binary.BigEndian.Uint16(stream.Data))
	if size < 12 || size != len(stream.Data)-2 {
		out.State = DoQMalformed
		return out
	}
	message, err := ParseDNS(stream.Data[2:])
	switch {
	case errors.Is(err, ErrDNSLimit):
		out.State = DoQLimited
	case err != nil || message.Anomalies.Any() || message.TransactionID != 0 || message.IsResponse != reply:
		out.State = DoQMalformed
	case message.Opcode != 0 || !reply && len(message.Questions) != 1 ||
		len(message.Questions) == 1 && (message.Questions[0].Type == 251 || message.Questions[0].Type == 252):
		out.State = DoQUnsupported
	default:
		out.State, out.DNS = DoQComplete, &message
	}
	return out
}
