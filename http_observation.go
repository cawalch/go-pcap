package pcap

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"net/netip"
	"slices"
)

// HTTPRequestObservation identifies the packet supplying the first byte of an
// HTTP/1 request line or HTTP/2 HEADERS frame. PacketIndex is zero-based.
// TimestampNs is the packet's capture timestamp, possibly zero. StreamID is
// zero for HTTP/1. Source and Destination are in request direction.
type HTTPRequestObservation struct {
	PacketIndex, FlowIndex  int
	TimestampNs             int64
	Source, Destination     netip.AddrPort
	StreamID                uint32
	Method, Authority, Path string
}

// HTTPRequests returns packet-attributed requests on cleartext TCP directions
// in packet-index order. HTTP/2 requires the client preface. Only the contiguous
// stream prefix before a gap is inspected. Encrypted TLS records are skipped.
func (c *Capture) HTTPRequests(data []byte) ([]HTTPRequestObservation, error) {
	return scanHTTPRequests(ipFrameSource{capture: c, data: data})
}

// HTTPRequestsFromReaderAt is the bounded ReaderAt equivalent of [Capture.HTTPRequests].
// Frame and TCP payload reads share [MaxReaderAtScanBytes].
func (c *Capture) HTTPRequestsFromReaderAt(r io.ReaderAt) ([]HTTPRequestObservation, error) {
	return scanHTTPRequests(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }})
}

func collectHTTPRequestStreams(source ipFrameSource) (tcpMessageCollector, error) {
	collector := tcpMessageCollector{separateInterfaces: source.capture != nil && source.capture.SeparateTCPInterfaces}
	err := walkHTTPPackets(source, collector.add)
	return collector, err
}

func walkHTTPPackets(source ipFrameSource, visit func(PacketRecord, Frame, int, []byte) error) error {
	var table flowIndexTable
	remaining := MaxTotalStreamBytes
	return source.walk(func(pkt PacketRecord, f Frame, payload []byte) error {
		key, _ := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := table.lookupOrInsert(key)
		if err != nil || f.IPProtocol != IPProtoTCP {
			return err
		}
		if len(payload) > remaining {
			return ErrReassemblyLimit
		}
		remaining -= len(payload)
		return visit(pkt, f, flow, payload)
	})
}

func scanHTTPRequests(source ipFrameSource) ([]HTTPRequestObservation, error) {
	collector, err := collectHTTPRequestStreams(source)
	if err != nil {
		return nil, err
	}
	var rows []HTTPRequestObservation
	bodyBudget := httpDecodeBudget{remaining: MaxHTTPDecodedBodyBytesPerScan}
	headerBudget := MaxHTTP2DecodedHeaderBytes
	err = collector.walkContiguous(func(dir *tcpMessageDirection, data []byte, spans []packetSpan, _ StreamAnomalies) error {
		i := 0
		add := func(off int, stream uint32, method, authority, path string) error {
			if len(rows) >= MaxHTTPMessagesPerScan {
				return ErrHTTPLimit
			}
			for spans[i].end <= off {
				i++
			}
			packet := dir.packets[spans[i].segment]
			rows = append(rows, HTTPRequestObservation{
				PacketIndex: packet.index, TimestampNs: packet.timestamp, FlowIndex: dir.flowIndex,
				Source: dir.src, Destination: dir.dst, StreamID: stream,
				Method: method, Authority: authority, Path: path,
			})
			return nil
		}
		if bytes.HasPrefix(data, HTTP2ClientPreface) {
			_, err := readHTTP2Frames(data, &headerBudget, false, func(off int, id uint32, h HTTP2HeaderBlock) error {
				return add(off, id, h.Method, h.Authority, h.Path)
			}, nil)
			return err
		}
		for off := 0; off < len(data); {
			req, n, err := parseHTTPRequest(data[off:], &bodyBudget)
			if errors.Is(err, ErrHTTPLimit) {
				return err
			}
			if err != nil || n <= 0 {
				break
			}
			if err := add(off, 0, req.Method, req.Host, req.Path); err != nil {
				return err
			}
			if req.Method == "CONNECT" {
				break
			}
			off += n
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(a, b HTTPRequestObservation) int { return cmp.Compare(a.PacketIndex, b.PacketIndex) })
	return rows, nil
}
