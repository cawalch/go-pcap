package pcap

import (
	"io"
	"net/netip"
)

// TLSCoverageReason identifies an observed boundary of recovered TLS plaintext.
type TLSCoverageReason uint8

const (
	// TLSCoverageUnknown marks a boundary the scan cannot establish.
	TLSCoverageUnknown TLSCoverageReason = iota
	// TLSCoverageCapturedEnd marks the end of the captured direction.
	TLSCoverageCapturedEnd
	// TLSCoverageTCPGap marks a known missing TCP sequence range.
	TLSCoverageTCPGap
	// TLSCoverageTruncated marks a record with missing bytes.
	TLSCoverageTruncated
	// TLSCoverageMissingKey marks a protected range whose key was unavailable.
	TLSCoverageMissingKey
	// TLSCoverageAuthenticationFailed marks an unsuccessful authentication.
	TLSCoverageAuthenticationFailed
	// TLSCoverageInvalidRecord marks invalid record structure or content.
	TLSCoverageInvalidRecord
	// TLSCoverageUnsupported marks unsupported record protection.
	TLSCoverageUnsupported
	// TLSCoverageLimit marks a local scan limit.
	TLSCoverageLimit
)

// TLSCoverageBoundary locates a boundary within the directional TCP stream,
// including any proxy prefix. WireOffset is -1 when unavailable.
type TLSCoverageBoundary struct {
	WireOffset int
	Reason     TLSCoverageReason
}

// TLSDirectionCoverage describes recovered TLS application bytes.
// Before describes an earlier opaque range, if present. End describes where
// recovery stopped. AuthenticatedClose requires an authenticated close_notify.
type TLSDirectionCoverage struct {
	Bytes              int
	Before, End        TLSCoverageBoundary
	AuthenticatedClose bool
}

// KeyedHTTP1OpeningCoverage describes an observed TCP opening with paired TLS
// hellos. OpeningPacket and FlowIndex refer to the original capture. Endpoints
// are the observed TCP endpoints. An opening can have zero HTTP rows.
type KeyedHTTP1OpeningCoverage struct {
	OpeningPacket, FlowIndex       int
	Client, Server                 netip.AddrPort
	ClientCoverage, ServerCoverage TLSDirectionCoverage
}

// KeyedHTTP1Analysis holds authenticated HTTP transactions and analysis
// coverage for recognized TLS openings in capture order.
type KeyedHTTP1Analysis struct {
	Transactions []KeyedHTTP1Transaction
	Openings     []KeyedHTTP1OpeningCoverage
}

// AnalyzeKeyedHTTP1 finds HTTP evidence and TLS opening coverage in one scan.
// It returns a zero result on a terminal scan or analysis error.
func (c *Capture) AnalyzeKeyedHTTP1(data, extraKeyLog []byte) (KeyedHTTP1Analysis, error) {
	return analyzeKeyedHTTP1(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// AnalyzeKeyedHTTP1FromReaderAt is the seekable equivalent of [Capture.AnalyzeKeyedHTTP1].
// Its reads share [MaxReaderAtScanBytes].
func (c *Capture) AnalyzeKeyedHTTP1FromReaderAt(r io.ReaderAt, extraKeyLog []byte) (KeyedHTTP1Analysis, error) {
	return analyzeKeyedHTTP1(c.tcpReaderAt(r), extraKeyLog)
}

func analyzeKeyedHTTP1(source ipFrameSource, keys []byte) (KeyedHTTP1Analysis, error) {
	streams, err := scanTLSProvenance(source, keys)
	if err != nil {
		return KeyedHTTP1Analysis{}, err
	}
	rows, err := keyedHTTP1Transactions(streams)
	if err != nil || len(streams) == 0 {
		return KeyedHTTP1Analysis{}, err
	}
	openings := make([]KeyedHTTP1OpeningCoverage, len(streams))
	for i := range streams {
		s := &streams[i]
		openings[i] = KeyedHTTP1OpeningCoverage{
			OpeningPacket: s.openingPacket, FlowIndex: s.FlowIndex,
			Client: netip.AddrPortFrom(s.SrcAddr, s.SrcPort), Server: netip.AddrPortFrom(s.DstAddr, s.DstPort),
			ClientCoverage: annotatedTLSCoverage(&s.client, len(s.Client.Data)),
			ServerCoverage: annotatedTLSCoverage(&s.server, len(s.Server.Data)),
		}
	}
	return KeyedHTTP1Analysis{Transactions: rows, Openings: openings}, nil
}

func annotatedTLSCoverage(d *tlsDirectionProvenance, size int) TLSDirectionCoverage {
	before := TLSCoverageBoundary{WireOffset: -1}
	if d.before.reason != tlsStopEnd {
		before = tlsCoverageBoundary(d.before)
	}
	return TLSDirectionCoverage{
		Bytes: size, Before: before, End: tlsCoverageBoundary(d.stop), AuthenticatedClose: d.closeNotify != nil,
	}
}

func tlsCoverageBoundary(b tlsProvenanceBoundary) TLSCoverageBoundary {
	var reason TLSCoverageReason
	switch b.reason {
	case tlsStopEnd:
		reason = TLSCoverageCapturedEnd
	case tlsStopGap:
		reason = TLSCoverageTCPGap
	case tlsStopTruncated:
		reason = TLSCoverageTruncated
	case tlsStopMissingKey:
		reason = TLSCoverageMissingKey
	case tlsStopAuthentication:
		reason = TLSCoverageAuthenticationFailed
	case tlsStopInvalidRecord:
		reason = TLSCoverageInvalidRecord
	case tlsStopUnsupported:
		reason = TLSCoverageUnsupported
	case tlsStopLimit:
		reason = TLSCoverageLimit
	default:
		return TLSCoverageBoundary{WireOffset: -1}
	}
	return TLSCoverageBoundary{WireOffset: b.wireOffset, Reason: reason}
}
