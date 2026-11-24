package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

const dnsOverTLSPort = 853

// DNSOverTLSRecord pairs a DNS message recovered from authenticated TLS
// application data with its capture flow index and directional endpoints.
type DNSOverTLSRecord struct {
	FlowIndex        int
	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16
	Message          DNSMessage
}

// DNSOverTLS extracts length-prefixed DNS messages from TLS on TCP port 853.
// It uses embedded TLS key logs and optional extraKeyLog bytes in NSS format.
// Records follow first-seen flow order, client direction first, then wire order
// within each direction. A known TCP gap excludes that direction. An incomplete
// or undersized frame ends its direction. A DNS parse error skips that frame.
// It returns no records on scan errors, including exceeding [MaxDNSMessagesPerScan].
func (c *Capture) DNSOverTLS(data, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	return scanDNSOverTLS(ipFrameSource{capture: c, data: data}, extraKeyLog)
}

// DNSOverTLSFromReaderAt extracts the same messages as [Capture.DNSOverTLS]
// under [MaxReaderAtScanBytes]. Only TCP/853 flows need full TCP payloads.
func (c *Capture) DNSOverTLSFromReaderAt(r io.ReaderAt, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	if r == nil {
		return nil, ErrInvalidHeader
	}
	return scanDNSOverTLS(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool {
		return f.IPProtocol == IPProtoTCP && (f.SrcPort == dnsOverTLSPort || f.DstPort == dnsOverTLSPort)
	}}, extraKeyLog)
}

func scanDNSOverTLS(source ipFrameSource, extraKeyLog []byte) ([]DNSOverTLSRecord, error) {
	keys, err := source.capture.TLSKeyLog(extraKeyLog)
	if err != nil || len(keys.Entries) == 0 {
		return nil, err
	}
	streams, err := collectStreams(source, dnsOverTLSPort, nil)
	if err != nil {
		return nil, err
	}
	var records []DNSOverTLSRecord
	for _, stream := range decryptTLSStreams(streams, keys) {
		record := DNSOverTLSRecord{FlowIndex: stream.FlowIndex, SrcAddr: stream.SrcAddr, DstAddr: stream.DstAddr, SrcPort: stream.SrcPort, DstPort: stream.DstPort}
		for i, dir := range [...]StreamBuffer{stream.Client, stream.Server} {
			if i == 1 {
				record.SrcAddr, record.DstAddr = stream.DstAddr, stream.SrcAddr
				record.SrcPort, record.DstPort = stream.DstPort, stream.SrcPort
			}
			if dir.Anomalies.SequenceGap {
				continue
			}
			for data := dir.Data; len(data) >= 2; {
				n := int(binary.BigEndian.Uint16(data))
				data = data[2:]
				if n < 12 || n > len(data) {
					break
				}
				msg, err := ParseDNS(data[:n])
				data = data[n:]
				if err != nil {
					continue
				}
				if len(records) == MaxDNSMessagesPerScan {
					return nil, fmt.Errorf("%w: exceeds %d messages", ErrDNSLimit, MaxDNSMessagesPerScan)
				}
				record.Message = msg
				records = append(records, record)
			}
		}
	}
	return records, nil
}
