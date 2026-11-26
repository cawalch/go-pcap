package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"sync"
)

const fileWindowSize = 64 << 10

// Holds one complete record or option, including its four-byte header.
const metadataWindowSize = 8 << 10

var fileWindowBuffers = sync.Pool{New: func() any { return new([fileWindowSize]byte) }}

// A scan owns its window until the walk finishes or the consumer breaks.
// File descriptor providers include *os.File and file-backed instrumentation.
// Other ReaderAt implementations keep their exact requested ranges.
type windowedReaderAt struct {
	r                        io.ReaderAt
	size, off, readAheadLeft int64
	buf                      *[fileWindowSize]byte
	valid                    int
	started                  bool
}

func fileWindow(r io.ReaderAt, size, extra int64) *windowedReaderAt {
	if _, ok := r.(interface{ Fd() uintptr }); !ok || size <= 0 || extra <= 0 {
		return nil
	}
	return &windowedReaderAt{r: r, size: size, readAheadLeft: extra}
}

func (w *windowedReaderAt) release() {
	if w.buf != nil {
		clear(w.buf[:])
		fileWindowBuffers.Put(w.buf)
	}
}

// ReadAt serves cached bytes first. A backwards miss (such as an EPB frame
// preceding already-read options) or a large read goes directly to the file.
func (w *windowedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 || off >= w.size {
		return 0, io.EOF
	}
	if available := w.size - off; int64(len(p)) > available {
		n, err := w.r.ReadAt(p[:available], off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	// A consumer that stops after its first read needs no buffer.
	if !w.started {
		w.started = true
		return w.r.ReadAt(p, off)
	}
	var copied int
	if off >= w.off && off-w.off < int64(w.valid) {
		copied = copy(p, w.buf[off-w.off:int64(w.valid)])
		if copied == len(p) {
			return copied, nil
		}
		off += int64(copied)
		p = p[copied:]
	}
	if off < w.off || len(p) >= fileWindowSize || w.readAheadLeft == 0 {
		n, err := w.r.ReadAt(p, off)
		return copied + n, err
	}
	want := int64(len(p))
	spare := min(int64(fileWindowSize)-want, w.size-off-want, w.readAheadLeft)
	w.readAheadLeft -= spare
	if w.buf == nil {
		w.buf = fileWindowBuffers.Get().(*[fileWindowSize]byte)
	}
	n, err := w.r.ReadAt(w.buf[:want+spare], off)
	w.off, w.valid = off, n
	n = copy(p, w.buf[:n])
	if n == len(p) {
		return copied + n, nil
	}
	if err == nil {
		err = io.EOF
	}
	return copied + n, err
}

// Exact L7 reads cover each classic record at most once. PcapNG also
// re-reads at most four header bytes per block (minimum block size 12).
// Give prefetch only the remaining allowance, preserving sparse scans that
// already need the budget. Cache hits still count toward retained input.
func (c *Capture) scanReadAhead() int64 {
	if c.fileSize >= MaxReaderAtScanBytes {
		return 0
	}
	extra := int64(MaxReaderAtScanBytes) - c.fileSize
	if c.Format == FormatPCAPNG {
		extra -= c.fileSize / 3
	}
	return extra
}

// NewFromReaderAt parses a classic PCAP or PcapNG container from an [io.ReaderAt]
// of total byte length size. File-backed scans can prefetch up to 64 KiB at a time.
// See [New] for signature errors.
func NewFromReaderAt(r io.ReaderAt, size int64) (*Capture, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if size < 4 {
		return nil, errNotPCAPOutOfBounds
	}
	var magicBuf [4]byte
	if err := readExactAt(r, magicBuf[:], 0, size); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotPCAP, err)
	}
	if w := fileWindow(r, size, size); w != nil {
		defer w.release()
		r = w
	}
	magic := binary.LittleEndian.Uint32(magicBuf[:])
	switch magic {
	case PCAPMagicMicroLE:
		return parseClassicPCAPFromReaderAt(r, size, binary.LittleEndian, false)
	case PCAPMagicMicroBE:
		return parseClassicPCAPFromReaderAt(r, size, binary.BigEndian, false)
	case PCAPMagicNanoLE:
		return parseClassicPCAPFromReaderAt(r, size, binary.LittleEndian, true)
	case PCAPMagicNanoBE:
		return parseClassicPCAPFromReaderAt(r, size, binary.BigEndian, true)
	case PCAPNGSectionHeaderMagic:
		return parsePCAPNGFromReaderAt(r, size)
	default:
		if magic == zstdFrameMagic {
			return nil, ErrUnsupportedZstd
		}
		if magic == xzMagicPrefix && size >= int64(4+len(xzMagicSuffix)) {
			var suffix [len(xzMagicSuffix)]byte
			if err := readExactAt(r, suffix[:], 4, size); err != nil {
				return nil, fmt.Errorf("%w: reading xz signature: %w", errNotPCAPInvalidMagic, err)
			}
			if string(suffix[:]) == xzMagicSuffix {
				return nil, ErrUnsupportedXZ
			}
		}
		return nil, errNotPCAPInvalidMagic
	}
}

// PacketSeqFromReaderAt yields packet metadata in capture order. File-backed
// scans may read ahead. Breaking the loop stops iteration. A read or parse error is
// yielded once, after any preceding complete records.
func (c *Capture) PacketSeqFromReaderAt(r io.ReaderAt) iter.Seq2[PacketRecord, error] {
	return func(yield func(PacketRecord, error) bool) {
		err := c.walkPacketsFromReaderAt(r, true, func(pkt PacketRecord) error {
			if !yield(pkt, nil) {
				return errStopWalk
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStopWalk) {
			yield(PacketRecord{}, err)
		}
	}
}

// PacketsFromReaderAt collects the records from [Capture.PacketSeqFromReaderAt].
func (c *Capture) PacketsFromReaderAt(r io.ReaderAt) ([]PacketRecord, error) {
	var packets []PacketRecord
	err := c.walkPacketsFromReaderAt(r, true, func(pkt PacketRecord) error {
		if packets == nil && c.PacketCount > 0 {
			packets = make([]PacketRecord, 0, min(c.PacketCount, MaxPackets))
		}
		packets = append(packets, pkt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return packets, nil
}

func (c *Capture) walkPacketsFromReaderAt(r io.ReaderAt, prefetch bool, cb func(PacketRecord) error) error {
	if err := c.validateContainer(); err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if prefetch {
		if w := fileWindow(r, c.fileSize, c.fileSize); w != nil {
			defer w.release()
			r = w
		}
	}
	if c.Format == FormatPCAP {
		order := binary.ByteOrder(binary.LittleEndian)
		if c.BigEndian {
			order = binary.BigEndian
		}
		_, err := scanClassicPCAPReaderAt(r, c.fileSize, c.SnapLen, c.LinkType, order, c.NanoTimestamp, cb)
		return err
	}
	_, err := scanPCAPNGReaderAt(r, c.fileSize, cb, nil)
	return err
}

// PacketPayloadFromReaderAt reads and returns a newly allocated slice containing
// pkt's captured frame bytes from r.
func (c *Capture) PacketPayloadFromReaderAt(r io.ReaderAt, pkt PacketRecord) ([]byte, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if pkt.PayloadOffset < 0 || pkt.PayloadLength < 0 || pkt.PayloadLength > MaxSnapLen {
		return nil, ErrOutOfBounds
	}
	end := pkt.PayloadOffset + pkt.PayloadLength
	if end < pkt.PayloadOffset {
		return nil, ErrIntegerOverflow
	}
	if end > c.fileSize {
		return nil, ErrOutOfBounds
	}
	buf := make([]byte, pkt.PayloadLength)
	if err := readExactAt(r, buf, pkt.PayloadOffset, c.fileSize); err != nil {
		return nil, err
	}
	return buf, nil
}

// UnsupportedLinkTypePacketsFromReaderAt reports the same coverage as
// [Capture.UnsupportedLinkTypePackets] using the unchanged reader. PcapNG
// metadata reads share [MaxReaderAtScanBytes].
func (c *Capture) UnsupportedLinkTypePacketsFromReaderAt(r io.ReaderAt) (count int, interfaceIDs []uint32, err error) {
	if r == nil {
		return 0, nil, ErrInvalidHeader
	}
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	return c.unsupportedLinkTypePackets(c.PacketSeqFromReaderAt(&budget))
}

// FlowsFromReaderAt aggregates deterministic 5-tuple flows from an [io.ReaderAt]
// using a 256-byte prefix for common transport headers. When the prefix is
// insufficient it extends the read up to the IP datagram boundary. Container
// and frame reads together are limited to [MaxReaderAtScanBytes].
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) FlowsFromReaderAt(r io.ReaderAt) ([]FlowSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if c.PacketCount == 0 {
		return nil, nil
	}
	if w := fileWindow(r, c.fileSize, c.scanReadAhead()); w != nil {
		defer w.release()
		r = w
	}
	if c.LinkType == LinkTypeIEEE80211RadioTap || slices.ContainsFunc(c.Interfaces, func(iface InterfaceDescriptor) bool {
		return iface.LinkType == LinkTypeIEEE80211RadioTap
	}) {
		return c.flowsFromRadiotapReader(r)
	}
	acc := flowAccumulator{separateInterfaces: c.SeparateTCPInterfaces && len(c.Interfaces) > 1}
	var header [256]byte
	var scratch []byte
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	err := c.walkPacketsFromReaderAt(&budget, false, func(pkt PacketRecord) error {
		n := min(pkt.PayloadLength, int64(len(header)))
		if n == 0 {
			return nil
		}
		payload := header[:n]
		if err := readExactAt(&budget, payload, pkt.PayloadOffset, c.fileSize); err != nil {
			return err
		}
		frame, err := decodeCaptureFrame(payload, pkt.LinkType)
		if err != nil {
			return nil
		}
		if n < pkt.PayloadLength {
			payload, err = extendFramePrefix(&budget, c.fileSize, pkt, &frame, payload, &scratch)
			if err != nil {
				return err
			}
		}
		if frame.IPVersion == 0 {
			return nil
		}
		return acc.observe(&pkt, &frame, payload)
	})
	if err != nil {
		return nil, err
	}
	return acc.flows, nil
}

// flowsFromRadiotapReader uses the shared prefix walker to retry large Radiotap
// headers. Other captures use the direct loop without that recovery path.
func (c *Capture) flowsFromRadiotapReader(r io.ReaderAt) ([]FlowSummary, error) {
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	acc := flowAccumulator{separateInterfaces: c.SeparateTCPInterfaces && len(c.Interfaces) > 1}
	err := c.walkFlowPrefixes(&budget, func(pkt PacketRecord, f Frame, prefix []byte) error {
		return acc.observe(&pkt, &f, prefix)
	})
	if err != nil {
		return nil, err
	}
	return acc.flows, nil
}

// completeFlowPrefix accounts for the missing payload tail when the prefix
// contains a complete, unencapsulated TCP or UDP header. An outer tunnel can
// have an independent length anomaly, so decode those frames in full. If the
// next header has a known end, required gives the exact prefix length to read.
func completeFlowPrefix(f *Frame, prefix []byte, captured int64) (complete bool, required int64) {
	if f.IPVersion == 0 && !f.Anomalies.TruncatedLayer {
		return true, 0
	}
	layers := f.LayerSlices()
	if len(layers) < 2 {
		return false, 0
	}
	transport := layers[len(layers)-1].Proto
	if transport != LayerTCP && (transport != LayerUDP || f.DstPort == 4789 || f.DstPort == 6081) {
		return false, 0
	}
	var end int64
	for _, layer := range layers {
		offset := int64(layer.Offset)
		switch layer.Proto {
		case LayerIPv4:
			if end != 0 {
				return false, 0
			}
			end = offset + int64(binary.BigEndian.Uint16(prefix[offset+2:]))
		case LayerIPv6:
			if end != 0 {
				return false, 0
			}
			end = offset + 40 + int64(binary.BigEndian.Uint16(prefix[offset+4:]))
		}
	}
	if end < int64(f.PayloadOffset) || f.PayloadOffset == 0 {
		return false, 0
	}
	f.Anomalies.IPTotalLengthExceedsFrame = end > captured
	ipBound := min(end, captured)
	payloadBound := ipBound
	if transport == LayerUDP {
		udpOff := int64(layers[len(layers)-1].Offset)
		udpLen := int64(binary.BigEndian.Uint16(prefix[udpOff+4:]))
		avail := ipBound - udpOff
		if udpLen > 0 {
			if udpLen < 8 {
				f.Anomalies.TruncatedLayer = true
				payloadBound = udpOff + 8
			} else if udpLen > avail {
				if !f.Anomalies.IPTotalLengthExceedsFrame {
					f.Anomalies.TruncatedLayer = true
				}
			} else {
				payloadBound = udpOff + udpLen
				if isIKEPort(f.SrcPort) || isIKEPort(f.DstPort) {
					// IKE classification needs only its header and optional
					// Non-ESP Marker. Validate against the full UDP bound.
					start := udpOff + 8
					headerEnd := start + ikev2HeaderLen
					if f.SrcPort == 4500 || f.DstPort == 4500 {
						headerEnd += 4
					}
					if needed := min(payloadBound, headerEnd); needed > int64(len(prefix)) {
						return false, needed
					}
					r := NewSafeReader(prefix)
					decodeIKEv2(r, start, payloadBound, f)
				}
			}
		}
	}
	f.PayloadLength = uint32(payloadBound - int64(f.PayloadOffset))
	return true, 0
}

// DNSFromReaderAt extracts DNS records using bounded metadata, frame header,
// DNS transport and UDP fragment reads under [MaxReaderAtScanBytes].
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) DNSFromReaderAt(r io.ReaderAt) ([]DNSRecord, error) {
	return scanDNS(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool {
		return f.mayContainUDPFragment() ||
			(f.IPProtocol == IPProtoUDP || f.IPProtocol == IPProtoTCP) && (isDNSPort(f.SrcPort) || isDNSPort(f.DstPort))
	}})
}

// tcpReaderAt visits all IP frames for flow indexing and reads full payloads only for TCP.
func (c *Capture) tcpReaderAt(r io.ReaderAt) ipFrameSource {
	return ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }}
}

// TLSFromReaderAt extracts TLS handshakes and fingerprints from reassembled
// TCP payloads on any port under [MaxReaderAtScanBytes].
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) TLSFromReaderAt(r io.ReaderAt) ([]TLSRecord, error) {
	streams, err := collectStreams(c.tcpReaderAt(r), 0, nil, tcpWireNone)
	if err != nil {
		return nil, err
	}
	return c.tlsFromStreams(streams, nil)
}

// QUICFromReaderAt extracts QUIC v1/v2 Initial handshakes and fingerprints
// using bounded UDP datagram and fragment reads under [MaxReaderAtScanBytes].
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) QUICFromReaderAt(r io.ReaderAt) ([]QUICRecord, error) {
	return scanQUIC(ipFrameSource{capture: c, reader: r, needsPayload: quicInitialPayload})
}

type scanReadBudget struct {
	r         io.ReaderAt
	remaining int64
}

func (b *scanReadBudget) check(n int64) error {
	if n > b.remaining {
		return fmt.Errorf("%w: ReaderAt scan exceeds %d bytes", ErrPacketLimit, MaxReaderAtScanBytes)
	}
	return nil
}

func (b *scanReadBudget) ReadAt(p []byte, off int64) (int, error) {
	if err := b.check(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := b.r.ReadAt(p, off)
	b.remaining -= int64(n)
	return n, err
}

// extendFramePrefix resolves incomplete headers and nested tunnel lengths.
func extendFramePrefix(budget *scanReadBudget, size int64, pkt PacketRecord, f *Frame, data []byte, scratch *[]byte) ([]byte, error) {
	for {
		if pkt.LinkType == LinkTypeNFLOG || (pkt.LinkType == LinkTypeApplePktap && f.Layers[1].Proto == LayerNFLOG) {
			// NFLOG needs the complete TLV list to distinguish byte orders.
			full, err := readFrameTail(budget, size, pkt.PayloadOffset, data, pkt.PayloadLength, scratch)
			if err != nil {
				return nil, err
			}
			*f, _ = decodeCaptureFrame(full, pkt.LinkType)
			return full, nil
		}
		complete, required := completeFlowPrefix(f, data, pkt.PayloadLength)
		if complete {
			return data, nil
		}
		n := int64(len(data))
		next := pkt.PayloadLength
		// Bytes after the outer IP datagram cannot affect any nested header.
		for _, layer := range f.LayerSlices() {
			offset := int(layer.Offset)
			switch layer.Proto {
			case LayerIPv4:
				next = min(next, int64(offset)+int64(binary.BigEndian.Uint16(data[offset+2:])))
			case LayerIPv6:
				next = min(next, int64(offset)+40+int64(binary.BigEndian.Uint16(data[offset+4:])))
			default:
				continue
			}
			break
		}
		if next <= n {
			return data, nil
		}
		limit := next
		if required != 0 {
			next = min(next, required)
		} else if f.Anomalies.TruncatedLayer {
			next = min(next, 2*n)
		}
		var err error
		data, err = readFrameTail(budget, size, pkt.PayloadOffset, data, next, scratch)
		if err != nil {
			return nil, err
		}
		// DecodeFrame has already accepted this link header. Extending its
		// backing data cannot shorten the header or change its link type.
		*f, _ = decodeCaptureFrame(data, pkt.LinkType)
		if next == limit {
			return data, nil
		}
	}
}

func readFrameTail(budget *scanReadBudget, size, offset int64, data []byte, end int64, scratch *[]byte) ([]byte, error) {
	n := int64(len(data))
	if err := budget.check(end - n); err != nil {
		return nil, err
	}
	if int64(cap(*scratch)) < end {
		*scratch = make([]byte, end)
	}
	copy((*scratch)[:n], data)
	data = (*scratch)[:end]
	if err := readExactAt(budget.r, data[n:], offset+n, size); err != nil {
		return nil, err
	}
	budget.remaining -= end - n
	return data, nil
}

func (s ipFrameSource) walkReaderAt(visit func(PacketRecord, Frame, []byte) error) error {
	if s.reader == nil {
		return fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if s.capture.PacketCount == 0 {
		return nil
	}
	if w := fileWindow(s.reader, s.capture.fileSize, s.capture.scanReadAhead()); w != nil {
		defer w.release()
		s.reader = w
	}
	budget := scanReadBudget{r: s.reader, remaining: MaxReaderAtScanBytes}
	return s.capture.walkFlowPrefixes(&budget, func(pkt PacketRecord, f Frame, data []byte) error {
		start, end := int64(f.PayloadOffset), int64(f.PayloadOffset)+int64(f.PayloadLength)
		available := data[start:min(end, int64(len(data)))]
		if f.PayloadLength == 0 || !s.needsPayload(f, available) {
			return visit(pkt, f, nil)
		}
		// Protocol state can retain these bytes across calls (TCP segments,
		// IP fragments and QUIC datagrams). Never retain prefix scratch.
		missing := int64(f.PayloadLength) - int64(len(available))
		if err := budget.check(missing); err != nil {
			return err
		}
		payload := make([]byte, f.PayloadLength)
		copied := copy(payload, available)
		if err := readExactAt(&budget, payload[copied:], pkt.PayloadOffset+start+int64(copied), s.capture.fileSize); err != nil {
			return err
		}
		return visit(pkt, f, payload)
	})
}

// walkFlowPrefixes supplies borrowed frame bytes through the transport header.
// The prefix can be shorter than the frame's declared payload.
func (c *Capture) walkFlowPrefixes(budget *scanReadBudget, visit func(PacketRecord, Frame, []byte) error) error {
	var header [256]byte
	var scratch []byte
	return c.walkPacketsFromReaderAt(budget, false, func(pkt PacketRecord) error {
		n := min(pkt.PayloadLength, int64(len(header)))
		if n == 0 {
			return nil
		}
		data := header[:n]
		if err := readExactAt(budget, data, pkt.PayloadOffset, c.fileSize); err != nil {
			return err
		}
		f, err := decodeCaptureFrame(data, pkt.LinkType)
		if err != nil {
			if pkt.LinkType != LinkTypeIEEE80211RadioTap {
				return nil
			}
			data, err = extendRadiotapPrefix(budget, c.fileSize, &pkt, &f, data, &scratch)
			if err != nil {
				return err
			}
			n = int64(len(data))
		}
		if n < pkt.PayloadLength {
			data, err = extendFramePrefix(budget, c.fileSize, pkt, &f, data, &scratch)
			if err != nil {
				return err
			}
		}
		if f.IPVersion == 0 {
			return nil
		}
		return visit(pkt, f, data)
	})
}

// extendRadiotapPrefix retries decoding when a Radiotap header extends past
// the initial prefix.
func extendRadiotapPrefix(budget *scanReadBudget, size int64, pkt *PacketRecord, f *Frame, data []byte, scratch *[]byte) ([]byte, error) {
	n := int64(len(data))
	if n < 8 || data[0] != 0 {
		return data, nil
	}
	length := int64(binary.LittleEndian.Uint16(data[2:4]))
	if length <= n || length > pkt.PayloadLength {
		return data, nil
	}
	end := min(length+n, pkt.PayloadLength)
	if err := budget.check(end - n); err != nil {
		return nil, err
	}
	if int64(cap(*scratch)) < end {
		*scratch = make([]byte, end)
	}
	result := (*scratch)[:end]
	copy(result, data)
	if err := readExactAt(budget, result[n:], pkt.PayloadOffset+n, size); err != nil {
		return nil, err
	}
	*f, _ = decodeCaptureFrame(result, pkt.LinkType)
	return result, nil
}

func readExactAt(r io.ReaderAt, buf []byte, offset, totalSize int64) error {
	if offset < 0 || int64(len(buf)) < 0 {
		return ErrOutOfBounds
	}
	end := offset + int64(len(buf))
	if end < offset {
		return ErrIntegerOverflow
	}
	if end > totalSize {
		return ErrOutOfBounds
	}
	if len(buf) == 0 {
		return nil
	}
	n, err := r.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrOutOfBounds
	}
	if err != nil {
		return err
	}
	return ErrOutOfBounds
}

func parseClassicPCAPFromReaderAt(r io.ReaderAt, size int64, order binary.ByteOrder, nano bool) (*Capture, error) {
	if size < pcapGlobalHeaderSize {
		return nil, fmt.Errorf("%w: classic PCAP header shorter than %d bytes", ErrInvalidHeader, pcapGlobalHeaderSize)
	}
	var hdr [pcapGlobalHeaderSize]byte
	if err := readExactAt(r, hdr[:], 0, size); err != nil {
		return nil, err
	}
	vMajor := order.Uint16(hdr[4:6])
	vMinor := order.Uint16(hdr[6:8])
	if vMajor != 2 || vMinor != 4 {
		return nil, fmt.Errorf("%w: unsupported PCAP version %d.%d", ErrInvalidHeader, vMajor, vMinor)
	}
	snapLen := order.Uint32(hdr[16:20])
	if snapLen > MaxSnapLen {
		return nil, fmt.Errorf("%w: snaplen %d exceeds %d", ErrInvalidHeader, snapLen, MaxSnapLen)
	}
	linkType := LinkType(order.Uint32(hdr[20:24]) & 0xffff)

	meta, err := scanClassicPCAPReaderAt(r, size, snapLen, linkType, order, nano, nil)
	if err != nil {
		return nil, err
	}
	if !isKnownLinkType(linkType) {
		meta.anomalies.UnknownLinkType = true
	}
	return &Capture{
		Format:         FormatPCAP,
		BigEndian:      order == binary.BigEndian,
		NanoTimestamp:  nano,
		VersionMajor:   vMajor,
		VersionMinor:   vMinor,
		SnapLen:        snapLen,
		LinkType:       linkType,
		Interfaces:     []InterfaceDescriptor{classicInterface(linkType, snapLen, nano)},
		PacketCount:    meta.packetCount,
		fileSize:       size,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanClassicPCAPReaderAt(
	r io.ReaderAt,
	size int64,
	snapLen uint32,
	linkType LinkType,
	order binary.ByteOrder,
	nano bool,
	cb func(PacketRecord) error,
) (scanSummary, error) {
	summary := scanSummary{declaredExtent: pcapGlobalHeaderSize}
	var hdr [pcapPacketHeaderSize]byte
	offset := int64(pcapGlobalHeaderSize)

	for offset < size {
		remaining := size - offset
		if remaining < pcapPacketHeaderSize {
			summary.anomalies.TrailingBytes = true
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset)+pcapPacketHeaderSize)
			break
		}
		if err := readExactAt(r, hdr[:], offset, size); err != nil {
			return scanSummary{}, err
		}
		tsSec := order.Uint32(hdr[0:4])
		tsSub := order.Uint32(hdr[4:8])
		capLen := order.Uint32(hdr[8:12])
		origLen := order.Uint32(hdr[12:16])

		if capLen > MaxSnapLen {
			return scanSummary{}, fmt.Errorf("%w: packet capture length %d exceeds %d", ErrInvalidPacket, capLen, MaxSnapLen)
		}
		if capLen > origLen {
			summary.anomalies.CaptureLenExceedsOriginal = true
		}
		if snapLen > 0 && capLen > snapLen {
			summary.anomalies.CaptureLenExceedsSnapLen = true
		}

		payloadOffset := offset + pcapPacketHeaderSize
		recordEnd := uint64(payloadOffset) + uint64(capLen)
		summary.declaredExtent = max(summary.declaredExtent, recordEnd)
		if recordEnd > uint64(size) {
			summary.anomalies.TruncatedPacketBlock = true
			break
		}
		if summary.packetCount >= MaxPackets {
			return scanSummary{}, fmt.Errorf("%w: exceeds %d", ErrPacketLimit, MaxPackets)
		}
		summary.packetCount++

		if cb != nil {
			subNs := int64(tsSub) * 1_000
			if nano {
				subNs = int64(tsSub)
			}
			if err := cb(PacketRecord{
				Index:         summary.packetCount - 1,
				InterfaceID:   0,
				LinkType:      linkType,
				TimestampNs:   int64(tsSec)*1_000_000_000 + subNs,
				CaptureLen:    capLen,
				OriginalLen:   origLen,
				PayloadOffset: payloadOffset,
				PayloadLength: int64(capLen),
			}); err != nil {
				return scanSummary{}, err
			}
		}
		offset = int64(recordEnd)
	}
	return summary, nil
}

func parsePCAPNGFromReaderAt(r io.ReaderAt, size int64) (*Capture, error) {
	meta, err := scanPCAPNGReaderAt(r, size, nil, nil)
	if err != nil {
		return nil, err
	}
	var snapLen uint32
	var linkType LinkType
	if len(meta.interfaces) > 0 {
		snapLen = meta.interfaces[0].SnapLen
		linkType = meta.interfaces[0].LinkType
	}
	return &Capture{
		Format:         FormatPCAPNG,
		BigEndian:      meta.bigEndian,
		VersionMajor:   meta.vMajor,
		VersionMinor:   meta.vMinor,
		SnapLen:        snapLen,
		LinkType:       linkType,
		Hardware:       meta.hardware,
		OS:             meta.os,
		UserAppl:       meta.userAppl,
		Interfaces:     meta.interfaces,
		Secrets:        meta.secrets,
		NameRecords:    meta.nameRecords,
		InterfaceStats: meta.interfaceStats,
		Processes:      meta.processes,
		PacketCount:    meta.packetCount,
		fileSize:       size,
		declaredExtent: meta.declaredExtent,
		anomalies:      meta.anomalies,
	}, nil
}

func scanPCAPNGReaderAt(r io.ReaderAt, size int64, cb func(PacketRecord) error, rawBlock func(uint32, binary.ByteOrder, int64, int64) error) (scanSummary, error) {
	if size < pcapngSHBMinSize {
		return scanSummary{}, fmt.Errorf("%w: PcapNG section header block shorter than %d bytes", ErrInvalidHeader, pcapngSHBMinSize)
	}

	var summary scanSummary
	var scratch []byte
	var totalSecretBytes int64
	order := binary.ByteOrder(binary.LittleEndian)
	haveSection := false
	offset := int64(0)
	var headerBuf [28]byte

	for offset < size {
		remaining := size - offset
		if remaining < pcapngMinBlockSize {
			if !haveSection {
				return scanSummary{}, fmt.Errorf("%w: missing PcapNG section header", ErrInvalidHeader)
			}
			summary.anomalies.TrailingBytes = true
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset)+pcapngMinBlockSize)
			break
		}
		if err := summary.countBlock(); err != nil {
			return scanSummary{}, err
		}

		if err := readExactAt(r, headerBuf[:8], offset, size); err != nil {
			return scanSummary{}, err
		}

		rawTypeLE := binary.LittleEndian.Uint32(headerBuf[0:4])
		if rawTypeLE == BlockTypeSectionHeader {
			if remaining < pcapngSHBMinSize {
				if !haveSection {
					return scanSummary{}, fmt.Errorf("%w: truncated PcapNG section header", ErrInvalidHeader)
				}
				summary.anomalies.TruncatedPacketBlock = true
				summary.declaredExtent = max(summary.declaredExtent, uint64(offset)+pcapngSHBMinSize)
				break
			}
			if err := readExactAt(r, headerBuf[8:12], offset+8, size); err != nil {
				return scanSummary{}, err
			}
			boMagicLE := binary.LittleEndian.Uint32(headerBuf[8:12])
			switch boMagicLE {
			case PCAPNGByteOrderMagic:
				order = binary.LittleEndian
			case 0x4d3c2b1a:
				order = binary.BigEndian
			default:
				return scanSummary{}, fmt.Errorf("%w: %w", ErrInvalidHeader, ErrInvalidMagic)
			}
		} else if !haveSection {
			return scanSummary{}, fmt.Errorf("%w: PcapNG must start with a Section Header Block", ErrInvalidHeader)
		}

		blockType := order.Uint32(headerBuf[0:4])
		blockLen := order.Uint32(headerBuf[4:8])
		if blockLen < pcapngMinBlockSize {
			return scanSummary{}, fmt.Errorf("%w: invalid block length %d", ErrInvalidBlock, blockLen)
		}
		if blockLen%4 != 0 {
			summary.anomalies.UnalignedBlockLength = true
		}

		paddedLen := uint64(blockLen)
		if rem := paddedLen % 4; rem != 0 {
			paddedLen += 4 - rem
		}
		blockEnd := uint64(offset) + paddedLen
		summary.declaredExtent = max(summary.declaredExtent, blockEnd)

		if blockEnd > uint64(size) {
			if !haveSection {
				return scanSummary{}, fmt.Errorf("%w: first PcapNG Section Header Block is truncated", ErrInvalidHeader)
			}
			summary.anomalies.TruncatedPacketBlock = true
			break
		}

		bodyEnd := int64(blockEnd) - 4
		if rawBlock != nil {
			// Export already validated packet records in the selection pass.
			// Recheck framing and leave reads of retained blocks to the writer.
			if err := readExactAt(r, headerBuf[:4], bodyEnd, size); err != nil {
				return scanSummary{}, err
			}
			if order.Uint32(headerBuf[:4]) != blockLen {
				return scanSummary{}, fmt.Errorf("%w: trailing block length mismatch", ErrInvalidBlock)
			}
			if err := rawBlock(blockType, order, offset, int64(blockEnd)); err != nil {
				return scanSummary{}, err
			}
			haveSection = true
			offset = int64(blockEnd)
			continue
		}
		tailOffset := bodyEnd
		var rec PacketRecord
		var packetErr error
		switch blockType {
		case blockTypeLegacyPacket, BlockTypeEnhancedPacket:
			var header []byte
			if bodyEnd-offset >= 28 {
				if err := readExactAt(r, headerBuf[8:28], offset+8, size); err != nil {
					return scanSummary{}, err
				}
				header = headerBuf[8:28]
			}
			var options int64
			rec, options, packetErr = decodePacketBlockHeader(blockType, header, offset+28, bodyEnd, order, &summary)
			if packetErr == nil {
				tailOffset = options
			}
		case BlockTypeSimplePacket:
			header := headerBuf[8:min(int64(12), bodyEnd-offset)]
			if err := readExactAt(r, header, offset+8, size); err != nil {
				return scanSummary{}, err
			}
			rec, packetErr = decodeSPBHeader(header, offset+12, bodyEnd, order, &summary)
		case BlockTypeSectionHeader, BlockTypeInterfaceDesc, BlockTypeDarwinProcessEvent:
			tailOffset = offset + 8
		default:
			if cb == nil && isCaptureOnlyBlock(blockType) {
				tailOffset = offset + 8
			}
		}

		// The tail contains the trailer and any metadata following the skipped frame.
		n := int64(blockEnd) - tailOffset
		var body, trailer []byte
		if n <= metadataWindowSize {
			if int64(cap(scratch)) < n {
				scratch = make([]byte, n)
			}
			tail := scratch[:n]
			if err := readExactAt(r, tail, tailOffset, size); err != nil {
				return scanSummary{}, err
			}
			body, trailer = tail[:n-4], tail[n-4:]
		} else {
			trailer = headerBuf[:4]
			if err := readExactAt(r, trailer, bodyEnd, size); err != nil {
				return scanSummary{}, err
			}
			if order.Uint32(trailer) == blockLen {
				var err error
				body, err = readLargeMetadata(r, tailOffset, bodyEnd, blockType, order, &summary, totalSecretBytes)
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return scanSummary{}, ErrOutOfBounds
				}
				if err != nil {
					return scanSummary{}, err
				}
			}
		}
		if order.Uint32(trailer) != blockLen {
			return scanSummary{}, fmt.Errorf("%w: trailing block length mismatch", ErrInvalidBlock)
		}
		if packetErr != nil {
			return scanSummary{}, packetErr
		}
		if cb != nil && isCaptureOnlyBlock(blockType) {
			offset = int64(blockEnd)
			continue
		}
		sr := SafeReader{data: body, size: int64(len(body))}
		switch blockType {
		case BlockTypeSectionHeader:
			if err := decodeSHB(&sr, 0, sr.size, order, &summary, &haveSection); err != nil {
				return scanSummary{}, err
			}
		case BlockTypeInterfaceDesc:
			if err := decodeIDB(&sr, 0, sr.size, order, &summary); err != nil {
				return scanSummary{}, err
			}
		case blockTypeLegacyPacket, BlockTypeEnhancedPacket, BlockTypeSimplePacket:
			if len(body) > 0 {
				if err := decodePacketBlockOptions(blockType, body, order, &summary, &rec); err != nil {
					return scanSummary{}, err
				}
			}
			if cb != nil {
				if err := cb(rec); err != nil {
					return scanSummary{}, err
				}
			}
		case BlockTypeDecryptionSecrets:
			prevLen := len(summary.secrets)
			if err := decodeDSB(&sr, 0, sr.size, order, &totalSecretBytes, &summary); err != nil {
				return scanSummary{}, err
			}
			if len(summary.secrets) > prevLen {
				summary.secrets[len(summary.secrets)-1].PayloadOffset += tailOffset
			}
		case BlockTypeNameResolution:
			if err := decodeNRB(&sr, 0, sr.size, order, &summary); err != nil {
				return scanSummary{}, err
			}
		case BlockTypeInterfaceStats:
			if err := decodeISB(&sr, 0, sr.size, order, &summary); err != nil {
				return scanSummary{}, err
			}
		case BlockTypeDarwinProcessEvent:
			if err := decodeDPEB(&sr, 0, sr.size, order, &summary); err != nil {
				return scanSummary{}, err
			}
		}

		offset = int64(blockEnd)
	}

	return summary, nil
}

// readLargeMetadata reads meaningful fields through a fixed-size window. NRB
// records go directly into the summary. Other decoders consume the fixed body
// and bounded options, up to the first end option.
func readLargeMetadata(r io.ReaderAt, start, end int64, kind uint32, order binary.ByteOrder, summary *scanSummary, secretBytes int64) ([]byte, error) {
	reader := bufio.NewReaderSize(io.NewSectionReader(r, start, end-start), metadataWindowSize)
	var fixed int
	switch kind {
	case BlockTypeSectionHeader:
		fixed = 16
	case BlockTypeInterfaceDesc, BlockTypeDecryptionSecrets:
		fixed = 8
	case BlockTypeInterfaceStats:
		fixed = 12
	case BlockTypeDarwinProcessEvent:
		fixed = 4
	}
	body := make([]byte, fixed)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	start += int64(fixed)
	if kind == BlockTypeDecryptionSecrets {
		length := int64(order.Uint32(body[4:]))
		if length > end-start {
			return nil, ErrInvalidBlock
		}
		if len(summary.secrets) >= MaxDecryptionSecrets || length > MaxDecryptionSecretBytes-secretBytes {
			return nil, ErrSecretLimit
		}
		n := (length + 3) &^ 3
		body = append(body, make([]byte, n)...)
		if _, err := io.ReadFull(reader, body[fixed:]); err != nil {
			return nil, err
		}
		start += n
	}
	records := kind == BlockTypeNameResolution
	for options := 0; start < end; {
		if end-start < 4 {
			return nil, ErrInvalidBlock
		}
		header, err := reader.Peek(4)
		if err != nil {
			return nil, err
		}
		code, length := order.Uint16(header), int(order.Uint16(header[2:]))
		if !records {
			if options >= MaxOptionsPerBlock {
				return nil, ErrOptionLimit
			}
			options++
		}
		if code == 0 {
			if !records {
				break
			}
			// Keep an NRB terminator before its options for decodeNRB.
			body = append(body, header...)
			records = false
			_, _ = reader.Discard(4)
			start += 4
			continue
		}
		if length > MaxOptionStringBytes {
			if records {
				return nil, ErrInvalidBlock
			}
			return nil, ErrOptionLimit
		}
		n := 4 + ((length + 3) &^ 3)
		if int64(n) > end-start {
			return nil, ErrInvalidBlock
		}
		field, err := reader.Peek(n)
		if err != nil {
			return nil, err
		}
		if records {
			if err := summary.addNRBRecord(code, field[4:4+length]); err != nil {
				return nil, err
			}
		} else {
			body = append(body, field...)
		}
		_, _ = reader.Discard(n)
		start += int64(n)
	}
	return body, nil
}
