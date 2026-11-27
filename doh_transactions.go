package pcap

import (
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// DoHTransport identifies the HTTP version carrying a DNS exchange.
type DoHTransport uint8

const (
	DoHHTTP2 DoHTransport = iota + 1
	DoHHTTP3
)

// DoHMessageState describes one direction of a DNS-over-HTTPS exchange.
type DoHMessageState uint8

const (
	// DoHUnseen indicates no observable message headers for this direction.
	DoHUnseen DoHMessageState = iota
	// DoHComplete indicates an observed, complete DNS wire message.
	DoHComplete
	// DoHIncomplete indicates a partial HTTP body or incomplete pairing.
	DoHIncomplete
	// DoHMalformed indicates invalid HTTP framing, DNS wire data, or encoding.
	DoHMalformed
	// DoHUnsupported indicates an unsupported media type or content coding.
	DoHUnsupported
	// DoHLimited indicates a per-message HTTP or DNS limit.
	DoHLimited
	// DoHNoDNSResponse indicates a final HTTP status that does not carry a
	// DoH answer, including non-2xx responses and 204 or 205.
	DoHNoDNSResponse
)

// DoHMessage holds an observation and the authenticated original packets
// contributing to it, including any observations of incomplete content. DNS
// is present only for [DoHComplete]. Packet indices are zero-based. HTTP/2
// retains whole TLS records. HTTP/3 retains any observed QPACK and peer
// SETTINGS context separately.
type DoHMessage struct {
	State              DoHMessageState
	DNS                *DNSMessage
	PacketIndices      []int
	QPACKPacketIndices []int
	TLSRecords         []TLSRecordEvidence
}

// DoHTransaction represents one observed DoH request and any response on the
// same authenticated HTTP stream. HTTP2ID identifies the TCP opening and
// request offset for HTTP/2. ConnectionIndex identifies the original keyed
// QUIC connection for HTTP/3 and is -1 for HTTP/2. StatusCode is zero when
// no final HTTP response was confirmed. The caller owns all retained evidence.
type DoHTransaction struct {
	Transport                  DoHTransport
	FlowIndex, ConnectionIndex int
	StreamID                   uint64
	HTTP2ID                    KeyedHTTP2TransactionID
	Client, Resolver           netip.AddrPort
	StatusCode                 int
	Query, Reply               DoHMessage
	ALPNPacketIndices          []int
}

// DoHTransactions reports keyed HTTP/2 and HTTP/3 exchanges whose observed
// HTTPS request headers identify a wire-format DNS GET or POST. Requests
// without observable identifying headers yield no row. Responses associate
// by HTTP stream rather than DNS ID. The scan supports absent or identity
// content coding for entities. HTTP/2 rows precede HTTP/3 rows, in their
// respective keyed analyzers' order. Each analyzer's limits apply. This scan
// also limits DNS wire bytes to [MaxTotalStreamBytes] and retains at most
// 65,536 DNS questions and resource records in total. A scan-wide error
// returns no results.
func (c *Capture) DoHTransactions(data, extraKeyLog []byte) ([]DoHTransaction, error) {
	return dohTransactions(func() ([]KeyedHTTP2Transaction, error) {
		return c.KeyedHTTP2Transactions(data, extraKeyLog)
	}, func() ([]KeyedHTTP3Transaction, error) {
		return c.KeyedHTTP3Transactions(data, extraKeyLog)
	})
}

// DoHTransactionsFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.DoHTransactions]. The two keyed analyses share one
// [MaxReaderAtScanBytes] read budget.
func (c *Capture) DoHTransactionsFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]DoHTransaction, error) {
	if r == nil {
		return nil, ErrInvalidHeader
	}
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	return dohTransactions(func() ([]KeyedHTTP2Transaction, error) {
		return c.KeyedHTTP2TransactionsFromReaderAt(&budget, extraKeyLog)
	}, func() ([]KeyedHTTP3Transaction, error) {
		return c.KeyedHTTP3TransactionsFromReaderAt(&budget, extraKeyLog)
	})
}

const maxDoHDNSEntriesPerScan = 65_536

type dohBudget struct {
	bytes, entries int
}

func dohTransactions(http2 func() ([]KeyedHTTP2Transaction, error), http3 func() ([]KeyedHTTP3Transaction, error)) ([]DoHTransaction, error) {
	budget := dohBudget{bytes: MaxTotalStreamBytes, entries: maxDoHDNSEntriesPerScan}
	rows, err := http2()
	if err != nil {
		return nil, err
	}
	var out []DoHTransaction
	for i := range rows {
		row, match, err := dohFromHTTP2(&rows[i], &budget)
		if err != nil {
			return nil, err
		}
		if match {
			out = append(out, row)
		}
	}
	quic, err := http3()
	if err != nil {
		return nil, err
	}
	for i := range quic {
		row, match, err := dohFromHTTP3(&quic[i], &budget)
		if err != nil {
			return nil, err
		}
		if match {
			out = append(out, row)
		}
	}
	return out, nil
}

func dohFromHTTP2(tx *KeyedHTTP2Transaction, budget *dohBudget) (DoHTransaction, bool, error) {
	if !strings.EqualFold(tx.Request.Scheme, "https") {
		return DoHTransaction{}, false, nil
	}
	query, match, err := budget.message(tx.Request.HTTP2HeaderBlock, tx.Request.Body, tx.Request.BodyState, tx.Request.BodyLimitExceeded, false)
	if !match || err != nil {
		return DoHTransaction{}, false, err
	}
	row := DoHTransaction{
		Transport: DoHHTTP2, FlowIndex: tx.FlowIndex, ConnectionIndex: -1, StreamID: uint64(tx.ID.StreamID),
		HTTP2ID: tx.ID, Client: tx.Source, Resolver: tx.Destination, StatusCode: tx.StatusCode, Query: query,
	}
	if tx.Response != nil {
		res := tx.Response
		row.Reply, _, err = budget.message(res.HTTP2HeaderBlock, res.Body, res.BodyState, res.BodyLimitExceeded, false)
		if err != nil {
			return DoHTransaction{}, false, err
		}
	} else if tx.Pairing == HTTP2ResponseAmbiguous || tx.Reset {
		row.Reply.State = DoHIncomplete
	}
	row.Query.setTLSRecords(tx.RequestRecords)
	row.Reply.setTLSRecords(tx.ResponseRecords)
	return row, true, nil
}

func (m *DoHMessage) setTLSRecords(records []TLSRecordEvidence) {
	m.TLSRecords = records
	for _, r := range records {
		m.PacketIndices = append(m.PacketIndices, r.PacketIndices...)
	}
	slices.Sort(m.PacketIndices)
	m.PacketIndices = slices.Compact(m.PacketIndices)
}

func dohFromHTTP3(tx *KeyedHTTP3Transaction, budget *dohBudget) (DoHTransaction, bool, error) {
	block, ok := dohHTTP3Initial(tx.Request)
	if !ok || !strings.EqualFold(block.Scheme, "https") {
		return DoHTransaction{}, false, nil
	}
	req := tx.Request
	query, match, err := budget.message(block, req.Body, req.BodyState, req.BodyLimitExceeded, req.Invalid)
	if !match || err != nil {
		return DoHTransaction{}, false, err
	}
	query.PacketIndices, query.QPACKPacketIndices = req.PacketIndices, req.QPACKPacketIndices
	row := DoHTransaction{
		Transport: DoHHTTP3, FlowIndex: tx.FlowIndex, ConnectionIndex: tx.ConnectionIndex,
		StreamID: tx.StreamID, Client: tx.Source, Resolver: tx.Destination, StatusCode: tx.StatusCode,
		Query: query, ALPNPacketIndices: tx.ALPNPacketIndices,
	}
	if res := tx.Response; res != nil {
		block, ok := dohHTTP3Initial(res)
		switch {
		case ok:
			row.Reply, _, err = budget.message(block, res.Body, res.BodyState, res.BodyLimitExceeded, res.Invalid)
			if err != nil {
				return DoHTransaction{}, false, err
			}
		case res.Invalid:
			row.Reply.State = DoHMalformed
		case res.Gap || res.Reset:
			row.Reply.State = DoHIncomplete
		}
		row.Reply.PacketIndices, row.Reply.QPACKPacketIndices = res.PacketIndices, res.QPACKPacketIndices
	}
	return row, true, nil
}

func dohHTTP3Initial(msg *HTTP3MessageEvidence) (HTTP2HeaderBlock, bool) {
	if msg != nil {
		for _, section := range msg.Sections {
			if section.Kind == HTTP3InitialSection && section.State == QPACKDecoded {
				return http3HeaderBlock(section.Headers), true
			}
		}
	}
	return HTTP2HeaderBlock{}, false
}

func (b *dohBudget) message(block HTTP2HeaderBlock, body []byte, state HTTPBodyState, capped, invalid bool) (DoHMessage, bool, error) {
	reply := block.Method == ""
	if reply && block.Status != "" && len(block.Status) == 3 &&
		(block.Status[0] != '2' || block.Status == "204" || block.Status == "205") {
		return DoHMessage{State: DoHNoDNSResponse}, true, nil
	}
	payload, match, err := dohPayload(block, body)
	if !match {
		return DoHMessage{State: DoHUnsupported}, false, nil
	}
	switch {
	case invalid || err != nil:
		return DoHMessage{State: DoHMalformed}, true, nil
	case block.Method != "GET":
		switch {
		case capped:
			return DoHMessage{State: DoHLimited}, true, nil
		case state == HTTPBodyPartial:
			return DoHMessage{State: DoHIncomplete}, true, nil
		case state == HTTPBodyUnsupported:
			return DoHMessage{State: DoHUnsupported}, true, nil
		case state != HTTPBodyComplete:
			return DoHMessage{State: DoHMalformed}, true, nil
		}
	}
	if len(payload) > b.bytes {
		return DoHMessage{}, false, ErrDNSLimit
	}
	b.bytes -= len(payload)
	msg, err := parseDoHPayload(payload, reply)
	if errors.Is(err, ErrDNSLimit) {
		return DoHMessage{State: DoHLimited}, true, nil
	}
	if err != nil || msg.Anomalies.Any() {
		return DoHMessage{State: DoHMalformed}, true, nil
	}
	entries := len(msg.Questions) + len(msg.Answers) + len(msg.Authorities) + len(msg.Additionals)
	if entries > b.entries {
		return DoHMessage{}, false, ErrDNSLimit
	}
	b.entries -= entries
	return DoHMessage{State: DoHComplete, DNS: &msg}, true, nil
}
