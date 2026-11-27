package pcap

import (
	"io"
	"slices"
)

// TLSHandshakeMessageEvidence identifies source capture packets used to recover a
// hello or Certificate message. PacketIndices are distinct, zero-based and sorted
// in capture order. A missing message has no packet indices. Protected identifies
// an authenticated TLS 1.3 handshake message. Each contributing ciphertext record
// is attributed in full, including its header and tag. For plaintext messages,
// indices cover the handshake message bytes and headers of contributing TLS records.
// Shared packets can also contain bytes belonging to another message.
type TLSHandshakeMessageEvidence struct {
	PacketIndices []int
	Protected     bool
}

// TLSHandshakeEvidence associates a TLSRecord with the first observed packet
// of its TCP opening and the messages supplying selected handshake fields.
// Client and server follow the oriented record endpoints. Certificate evidence
// covers the message carrying the chain. A packet may support multiple fields.
// Reordering can put the first capture index before the packet that carried
// the first message byte. References apply to the original capture.
type TLSHandshakeEvidence struct {
	TLSRecord
	OpeningPacket                          int
	ClientHello, ServerHello               TLSHandshakeMessageEvidence
	ClientCertificates, ServerCertificates TLSHandshakeMessageEvidence
}

// TLSHandshakeEvidence extracts the same handshake fields as [Capture.TLSWithKeyLog]
// and identifies their source packets. Pass nil to use only embedded TLS key logs.
// Attribution stops at each direction's first known gap and follows the same proxy
// and interface settings as TLS. A work limit returns [ErrTLSLimit] with no rows.
func (c *Capture) TLSHandshakeEvidence(data, extraKeyLog []byte) ([]TLSHandshakeEvidence, error) {
	return scanTLSHandshakeEvidence(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// TLSHandshakeEvidenceFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.TLSHandshakeEvidence]. Packet and length reads share [MaxReaderAtScanBytes].
func (c *Capture) TLSHandshakeEvidenceFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]TLSHandshakeEvidence, error) {
	return scanTLSHandshakeEvidence(c.tcpReaderAt(r), extraKeyLog)
}

type tlsHandshakeEvidenceScan struct {
	budget tlsProvenanceBudget
	rows   []TLSHandshakeEvidence
}

func scanTLSHandshakeEvidence(source ipFrameSource, extraKeyLog []byte) ([]TLSHandshakeEvidence, error) {
	keys, err := source.capture.boundedTLSKeyLog(extraKeyLog)
	if err != nil {
		return nil, err
	}
	streams, meta, err := tlsWireStreams(source, 0)
	if err != nil {
		return nil, err
	}
	scan := tlsHandshakeEvidenceScan{budget: tlsProvenanceBudget{records: maxTLSProvenanceRecords, ranges: maxTLSProvenanceRanges}}
	if _, err = tlsRecordsFromStreams(streams, meta, keys, nil, &scan); err != nil {
		return nil, err
	}
	return scan.rows, nil
}

type tlsHandshakeFragment struct {
	plainStart, plainEnd, wireStart, wireEnd int
}

type tlsHandshakeTrace struct {
	mapper                                 tlsRecordMapper
	fragments                              []tlsHandshakeFragment
	clientHello, serverHello, certificates TLSHandshakeMessageEvidence
	limited                                bool
}

func (s *tlsHandshakeEvidenceScan) directions(info *streamMetadata, reversed bool, clientPrefix, serverPrefix int) (*tlsHandshakeTrace, *tlsHandshakeTrace) {
	client, server := info.wire[0].spans, info.wire[1].spans
	if reversed {
		client, server = server, client
	}
	return &tlsHandshakeTrace{mapper: tlsRecordMapper{spans: client, prefix: clientPrefix, budget: &s.budget}},
		&tlsHandshakeTrace{mapper: tlsRecordMapper{spans: server, prefix: serverPrefix, budget: &s.budget}}
}

func (t *tlsHandshakeTrace) inspect() bool {
	if t.mapper.budget.records == 0 {
		t.limited = true
		return false
	}
	t.mapper.budget.records--
	return true
}

func (t *tlsHandshakeTrace) fragment(start, size, wireStart, wireEnd int) {
	if size != 0 {
		t.fragments = append(t.fragments, tlsHandshakeFragment{start, start + size, wireStart, wireEnd})
	}
}

func (t *tlsHandshakeTrace) locate(start, end int, protected bool) TLSHandshakeMessageEvidence {
	evidence := TLSHandshakeMessageEvidence{Protected: protected}
	// Different messages can share a TLS record, and the decrypted flight
	// begins a new logical handshake stream. Start each lookup independently.
	mapper := t.mapper
	add := func(lo, hi int) {
		rec, ok := mapper.mapRecord(lo, hi, 0, 0, false)
		if !ok {
			t.limited = true
			return
		}
		evidence.PacketIndices = append(evidence.PacketIndices, rec.packets...)
	}
	for _, f := range t.fragments {
		if f.plainStart >= end {
			break
		}
		if f.plainEnd <= start {
			continue
		}
		if protected {
			add(f.wireStart, f.wireEnd)
		} else {
			add(f.wireStart, f.wireStart+5)
			body := f.wireStart + 5
			add(body+max(start-f.plainStart, 0), body+min(end, f.plainEnd)-f.plainStart)
		}
	}
	slices.Sort(evidence.PacketIndices)
	evidence.PacketIndices = slices.Compact(evidence.PacketIndices)
	return evidence
}

func (s *tlsHandshakeEvidenceScan) add(record TLSRecord, opening int, client, server *tlsHandshakeTrace) {
	row := TLSHandshakeEvidence{TLSRecord: record, OpeningPacket: opening}
	if record.Handshake.HasClientHello {
		row.ClientHello = client.clientHello
	}
	if record.Handshake.HasServerHello {
		row.ServerHello = server.serverHello
	}
	if len(record.Handshake.ClientCertificates) > 0 {
		row.ClientCertificates = client.certificates
	}
	if len(record.Handshake.Certificates) > 0 {
		row.ServerCertificates = server.certificates
	}
	s.rows = append(s.rows, row)
}
