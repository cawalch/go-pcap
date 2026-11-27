package pcap

import (
	"io"
	"net/netip"
)

// QUICProtectionState describes evidence for one observed QUIC encryption level
// and sending direction.
type QUICProtectionState uint8

const (
	// QUICProtectionUnknown means the scan could not establish an outcome.
	QUICProtectionUnknown QUICProtectionState = iota
	// QUICProtectionHandshakeUnavailable means the Initial exchange did not
	// supply the final ServerHello needed to determine packet protection.
	QUICProtectionHandshakeUnavailable
	// QUICProtectionUnsupported means the observed suite is unsupported by
	// the offline decoder.
	QUICProtectionUnsupported
	// QUICProtectionMissingKey means the key log supplied no matching
	// directional secret at this level.
	QUICProtectionMissingKey
	// QUICProtectionAuthenticationFailed means a single candidate was
	// probed and the AEAD check failed. The underlying cause is unknown.
	QUICProtectionAuthenticationFailed
	// QUICProtectionAuthenticated means at least one packet was uniquely
	// authenticated and accepted at this level. Coverage can be partial.
	QUICProtectionAuthenticated
)

// QUICProtectionObservation holds one protection outcome. PacketIndex locates
// the first accepted packet, or the first failed probe when none was accepted.
// It is -1 when the outcome does not refer to an attempted protected packet.
type QUICProtectionObservation struct {
	State       QUICProtectionState
	PacketIndex int
}

// QUICConnectionCoverage describes an observed Initial exchange whose
// ClientHello was recovered. InitialPacketIndex locates the exchange's first
// observed Initial datagram. FlowIndex has the same meaning as in [QUICRecord].
// CipherSuite is zero when no ServerHello was recovered. RecordIndex matches
// the ConnectionIndex used by HTTP/3 and is -1 when the scan produced no keyed row.
type QUICConnectionCoverage struct {
	FlowIndex, InitialPacketIndex, RecordIndex int
	Client, Server                             netip.AddrPort
	Version                                    uint32
	CipherSuite                                uint16
	Client1RTT, Server1RTT, ServerHandshake    QUICProtectionObservation
}

// KeyedQUICAnalysis contains keyed records and protection coverage from one scan.
// Connections follows [Capture.QUIC] order, including exchanges with no keyed row.
type KeyedQUICAnalysis struct {
	Connections []QUICConnectionCoverage
	records     []KeyedQUICRecord
}

// AnalyzeKeyedQUIC reports protection coverage even when keys or transactions
// are unavailable. A capture without a recoverable Initial ClientHello yields
// no connection coverage. The scan uses the keyed QUIC limits and accepts up to
// [MaxDecryptionSecretBytes] of key logs. A terminal error returns a zero analysis.
func (c *Capture) AnalyzeKeyedQUIC(data, extraKeyLog []byte) (KeyedQUICAnalysis, error) {
	var coverage []QUICConnectionCoverage
	records, err := scanKeyedQUIC(ipFrameSource{capture: c, data: data}, extraKeyLog, true, &coverage)
	if err != nil {
		return KeyedQUICAnalysis{}, err
	}
	return KeyedQUICAnalysis{Connections: coverage, records: records}, nil
}

// AnalyzeKeyedQUICFromReaderAt is the seekable equivalent of
// [Capture.AnalyzeKeyedQUIC]. Its passes share [MaxReaderAtScanBytes].
func (c *Capture) AnalyzeKeyedQUICFromReaderAt(r io.ReaderAt, extraKeyLog []byte) (KeyedQUICAnalysis, error) {
	var coverage []QUICConnectionCoverage
	records, err := c.keyedQUICReaderAt(r, extraKeyLog, true, &coverage)
	if err != nil {
		return KeyedQUICAnalysis{}, err
	}
	return KeyedQUICAnalysis{Connections: coverage, records: records}, nil
}

// HTTP3Transactions recovers the same HTTP/3 rows as
// [Capture.KeyedHTTP3Transactions]. A transaction's ConnectionIndex matches
// the RecordIndex of its connection coverage.
func (a KeyedQUICAnalysis) HTTP3Transactions() ([]KeyedHTTP3Transaction, error) {
	return keyedHTTP3Transactions(a.records)
}

// DoQTransactions recovers the same DNS-over-QUIC rows as
// [Capture.DoQTransactions] from the analysis's keyed records.
func (a KeyedQUICAnalysis) DoQTransactions() ([]DoQTransaction, error) {
	return doqTransactions(a.records)
}

// DoHTransactions recovers the HTTP/3 rows of [Capture.DoHTransactions] from
// the analysis's keyed records. A transaction's ConnectionIndex matches
// the RecordIndex of its connection coverage.
func (a KeyedQUICAnalysis) DoHTransactions() ([]DoHTransaction, error) {
	rows, err := a.HTTP3Transactions()
	if err != nil {
		return nil, err
	}
	budget := dohBudget{bytes: MaxTotalStreamBytes, entries: maxDoHDNSEntriesPerScan}
	return appendHTTP3DoH(nil, rows, &budget)
}

func quicConnectionCoverage(initial QUICRecord, packetIndex int, secrets TLSKeyLogEntry) QUICConnectionCoverage {
	hs := &initial.Handshake
	result := QUICConnectionCoverage{
		FlowIndex: initial.FlowIndex, InitialPacketIndex: packetIndex, RecordIndex: -1,
		Client:  netip.AddrPortFrom(initial.SrcAddr, initial.SrcPort),
		Server:  netip.AddrPortFrom(initial.DstAddr, initial.DstPort),
		Version: hs.Version, CipherSuite: hs.ServerHello.CipherSuite,
	}
	hash, _ := tls13SuiteParams(result.CipherSuite)
	for _, input := range [...]struct {
		observation *QUICProtectionObservation
		secret      []byte
	}{
		{&result.Client1RTT, secrets.ClientTrafficSecret0},
		{&result.Server1RTT, secrets.ServerTrafficSecret0},
		{&result.ServerHandshake, secrets.ServerHandshakeSecret},
	} {
		input.observation.PacketIndex = -1
		switch {
		case !hs.HasServerHello || hs.ServerHello.IsHelloRetryRequest:
			input.observation.State = QUICProtectionHandshakeUnavailable
		case result.CipherSuite != 0 && hash == nil:
			input.observation.State = QUICProtectionUnsupported
		case hash != nil && len(input.secret) == 0:
			input.observation.State = QUICProtectionMissingKey
		}
	}
	return result
}

func (o *QUICProtectionObservation) authenticationFailed(packet int) {
	if o.State == QUICProtectionUnknown {
		*o = QUICProtectionObservation{QUICProtectionAuthenticationFailed, packet}
	}
}

func (o *QUICProtectionObservation) authenticated(packet int) {
	if o.State != QUICProtectionAuthenticated {
		*o = QUICProtectionObservation{QUICProtectionAuthenticated, packet}
	}
}
