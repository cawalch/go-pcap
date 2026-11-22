package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"sync"
)

const fileWindowSize = 64 << 10

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
		return nil, errNotPCAPInvalidMagic
	}
}

// PacketSeqFromReaderAt yields packet metadata in capture order. File-backed
// scans may read ahead. Breaking the loop stops iteration. A read or parse error is
// yielded once, after any preceding complete records.
func (c *Capture) PacketSeqFromReaderAt(r io.ReaderAt) iter.Seq2[PacketRecord, error] {
	return c.packetRecords(r, true)
}

func (c *Capture) packetRecords(r io.ReaderAt, prefetch bool) iter.Seq2[PacketRecord, error] {
	return func(yield func(PacketRecord, error) bool) {
		err := c.walkPacketsFromReaderAt(r, prefetch, func(pkt PacketRecord) error {
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
	_, err := scanPCAPNGReaderAt(r, c.fileSize, cb)
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

// FlowsFromReaderAt aggregates deterministic 5-tuple flows from an [io.ReaderAt]
// using a 256-byte prefix for common transport headers. When the prefix is
// insufficient it extends the read under [MaxReaderAtScanBytes].
func (c *Capture) FlowsFromReaderAt(r io.ReaderAt) ([]FlowSummary, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	if w := fileWindow(r, c.fileSize, c.scanReadAhead()); w != nil {
		defer w.release()
		r = w
	}
	type tcpHandshakeTime struct {
		synNs      int64
		synAckNs   int64
		hasSYN     bool
		hasSYNACK  bool
		hasClientL bool
	}
	var table flowIndexTable
	var flows []FlowSummary
	var hsTimes []tcpHandshakeTime
	var header [256]byte
	var scratch []byte
	budget := scanReadBudget{r: r, remaining: MaxReaderAtScanBytes}
	for pkt, err := range c.packetRecords(r, false) {
		if err != nil {
			return nil, err
		}
		n := min(pkt.PayloadLength, int64(len(header)))
		if n == 0 {
			continue
		}
		if err := budget.check(n); err != nil {
			return nil, err
		}
		payload := header[:n]
		if err := readExactAt(r, payload, pkt.PayloadOffset, c.fileSize); err != nil {
			return nil, err
		}
		budget.remaining -= n
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil {
			continue
		}
		if n < pkt.PayloadLength && !completeFlowPrefix(&frame, payload, pkt.PayloadLength) {
			payload, err = extendFramePrefix(&budget, c.fileSize, pkt, &frame, payload, &scratch)
			if err != nil {
				return nil, err
			}
		}
		if frame.IPVersion == 0 {
			continue
		}
		l4Len := uint64(frame.PayloadLength)

		key, _ := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		idx, exists, err := table.lookupOrInsert(key)
		if err != nil {
			return nil, err
		}
		if !exists {
			flows = append(flows, FlowSummary{
				Protocol:         frame.IPProtocol,
				SrcAddr:          frame.SrcAddr,
				DstAddr:          frame.DstAddr,
				SrcPort:          frame.SrcPort,
				DstPort:          frame.DstPort,
				FirstTimestampNs: pkt.TimestampNs,
				LastTimestampNs:  pkt.TimestampNs,
				ProcessID:        pkt.ProcessID,
				UserID:           pkt.UserID,
				ProcessName:      pkt.ProcessName,
				ProcessArgs:      pkt.ProcessArgs,
				ContainerID:      pkt.ContainerID,
				HasProcessID:     pkt.HasProcessID,
				HasUserID:        pkt.HasUserID,
				PortsUnavailable: !frame.hasPorts,
			})
			hsTimes = append(hsTimes, tcpHandshakeTime{})
		}

		flow := &flows[idx]
		if flow.PortsUnavailable && frame.hasPorts {
			flow.PortsUnavailable = false
		}
		hst := &hsTimes[idx]
		flow.PacketCount++
		if pkt.TimestampNs < flow.FirstTimestampNs {
			flow.FirstTimestampNs = pkt.TimestampNs
		}
		if pkt.TimestampNs > flow.LastTimestampNs {
			flow.LastTimestampNs = pkt.TimestampNs
		}
		if !flow.HasProcessID && pkt.HasProcessID {
			flow.ProcessID = pkt.ProcessID
			flow.HasProcessID = true
		}
		if !flow.HasUserID && pkt.HasUserID {
			flow.UserID = pkt.UserID
			flow.HasUserID = true
		}
		if flow.ProcessName == "" && pkt.ProcessName != "" {
			flow.ProcessName = pkt.ProcessName
		}
		if flow.ProcessArgs == "" && pkt.ProcessArgs != "" {
			flow.ProcessArgs = pkt.ProcessArgs
		}
		if flow.ContainerID == "" && pkt.ContainerID != "" {
			flow.ContainerID = pkt.ContainerID
		}
		if frame.TCPFlags&TCPFlagSYN != 0 && frame.TCPOptionsLength != 0 {
			flow.observeTCPTimestamp(&frame, payload)
		}
		flow.TCPFlags |= frame.TCPFlags
		flow.Anomalies = mergeFrameAnomalies(flow.Anomalies, frame.Anomalies)

		if frame.SrcAddr == flow.SrcAddr && frame.SrcPort == flow.SrcPort {
			flow.ClientPackets++
			flow.ClientBytes += l4Len
			if (frame.TCPFlags & (TCPFlagSYN | TCPFlagACK)) == TCPFlagSYN {
				if flow.ClientJA4T == "" {
					if fp, ok := frame.JA4T(payload); ok {
						flow.ClientJA4T = fp
					}
				}
				if !hst.hasSYN {
					hst.synNs = pkt.TimestampNs
					hst.hasSYN = true
				}
			} else if hst.hasSYNACK && !hst.hasClientL && (frame.TCPFlags&TCPFlagACK) != 0 {
				flow.ClientJA4L = JA4L(pkt.TimestampNs-hst.synAckNs, frame.TTL)
				hst.hasClientL = true
			}
		} else {
			flow.ServerPackets++
			flow.ServerBytes += l4Len
			if (frame.TCPFlags & (TCPFlagSYN | TCPFlagACK)) == (TCPFlagSYN | TCPFlagACK) {
				if flow.ServerJA4TS == "" {
					if fp, ok := frame.JA4T(payload); ok {
						flow.ServerJA4TS = fp
					}
				}
				if hst.hasSYN && !hst.hasSYNACK {
					hst.synAckNs = pkt.TimestampNs
					hst.hasSYNACK = true
					flow.ServerJA4L = JA4L(pkt.TimestampNs-hst.synNs, frame.TTL)
				}
			}
		}
	}
	return flows, nil
}

// completeFlowPrefix accounts for the missing payload tail when the prefix
// contains a complete, unencapsulated TCP or UDP header. An outer tunnel can
// have an independent length anomaly, so decode those frames in full.
func completeFlowPrefix(f *Frame, prefix []byte, captured int64) bool {
	if f.IPVersion == 0 && !f.Anomalies.TruncatedLayer {
		return true
	}
	layers := f.LayerSlices()
	if len(layers) < 2 {
		return false
	}
	transport := layers[len(layers)-1].Proto
	if transport != LayerTCP && (transport != LayerUDP || f.DstPort == 4789 || f.DstPort == 6081) {
		return false
	}
	var end int64
	for _, layer := range layers {
		offset := int64(layer.Offset)
		switch layer.Proto {
		case LayerIPv4:
			if end != 0 {
				return false
			}
			end = offset + int64(binary.BigEndian.Uint16(prefix[offset+2:]))
		case LayerIPv6:
			if end != 0 {
				return false
			}
			end = offset + 40 + int64(binary.BigEndian.Uint16(prefix[offset+4:]))
		}
	}
	if end < int64(f.PayloadOffset) || f.PayloadOffset == 0 {
		return false
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
			}
		}
	}
	f.PayloadLength = uint32(payloadBound - int64(f.PayloadOffset))
	return true
}

// DNSFromReaderAt extracts DNS records using bounded metadata, frame header,
// DNS transport and UDP fragment reads under [MaxReaderAtScanBytes].
func (c *Capture) DNSFromReaderAt(r io.ReaderAt) ([]DNSRecord, error) {
	return scanDNS(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool {
		return f.IPProtocol == IPProtoUDP && f.Anomalies.IPFragment ||
			(f.IPProtocol == IPProtoUDP || f.IPProtocol == IPProtoTCP) && (isDNSPort(f.SrcPort) || isDNSPort(f.DstPort))
	}})
}

// TLSFromReaderAt extracts TLS handshakes and fingerprints from reassembled
// TCP payloads on any port under [MaxReaderAtScanBytes].
func (c *Capture) TLSFromReaderAt(r io.ReaderAt) ([]TLSRecord, error) {
	streams, err := collectStreams(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return f.IPProtocol == IPProtoTCP }})
	if err != nil {
		return nil, err
	}
	return c.tlsFromStreams(streams, nil)
}

// QUICFromReaderAt extracts QUIC v1/v2 Initial handshakes and fingerprints
// using bounded UDP datagram and fragment reads under [MaxReaderAtScanBytes].
func (c *Capture) QUICFromReaderAt(r io.ReaderAt) ([]QUICRecord, error) {
	return scanQUIC(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, start []byte) bool {
		return f.IPProtocol == IPProtoUDP && (f.Anomalies.IPFragment ||
			f.PayloadLength >= 7 && (len(start) == 0 || start[0]&0xc0 == 0xc0))
	}})
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
		n := int64(len(data))
		next := pkt.PayloadLength
		if f.Anomalies.TruncatedLayer {
			next = min(next, 2*n)
		}
		if err := budget.check(next - n); err != nil {
			return nil, err
		}
		if int64(cap(*scratch)) < next {
			*scratch = make([]byte, next)
		}
		copy((*scratch)[:n], data)
		data = (*scratch)[:next]
		if err := readExactAt(budget.r, data[n:], pkt.PayloadOffset+n, size); err != nil {
			return nil, err
		}
		budget.remaining -= next - n
		// DecodeFrame has already accepted this link header. Extending its
		// backing data cannot shorten the header or change its link type.
		*f, _ = DecodeFrame(data, pkt.LinkType)
		if next == pkt.PayloadLength || completeFlowPrefix(f, data, pkt.PayloadLength) {
			return data, nil
		}
	}
}

func (s ipFrameSource) walkReaderAt(visit func(PacketRecord, Frame, []byte) error) error {
	if s.reader == nil {
		return fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if w := fileWindow(s.reader, s.capture.fileSize, s.capture.scanReadAhead()); w != nil {
		defer w.release()
		s.reader = w
	}
	var header [256]byte
	var scratch []byte
	budget := scanReadBudget{r: s.reader, remaining: MaxReaderAtScanBytes}
	return s.capture.walkPacketsFromReaderAt(&budget, false, func(pkt PacketRecord) error {
		n := min(pkt.PayloadLength, int64(len(header)))
		if n == 0 {
			return nil
		}
		data := header[:n]
		if err := readExactAt(&budget, data, pkt.PayloadOffset, s.capture.fileSize); err != nil {
			return err
		}
		f, err := DecodeFrame(data, pkt.LinkType)
		if err != nil {
			return nil
		}
		if n < pkt.PayloadLength && !completeFlowPrefix(&f, data, pkt.PayloadLength) {
			data, err = extendFramePrefix(&budget, s.capture.fileSize, pkt, &f, data, &scratch)
			if err != nil {
				return err
			}
		}
		if f.IPVersion == 0 {
			return nil
		}
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
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapPacketHeaderSize))
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
	meta, err := scanPCAPNGReaderAt(r, size, nil)
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

func scanPCAPNGReaderAt(r io.ReaderAt, size int64, cb func(PacketRecord) error) (scanSummary, error) {
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
			summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapngMinBlockSize))
			break
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
				summary.declaredExtent = max(summary.declaredExtent, uint64(offset+pcapngSHBMinSize))
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
		tailOffset := bodyEnd
		var rec PacketRecord
		var packetErr error
		switch blockType {
		case BlockTypeEnhancedPacket:
			var header []byte
			if bodyEnd-offset >= 28 {
				if err := readExactAt(r, headerBuf[8:28], offset+8, size); err != nil {
					return scanSummary{}, err
				}
				header = headerBuf[8:28]
			}
			var options int64
			rec, options, packetErr = decodeEPBHeader(header, offset+28, bodyEnd, order, &summary)
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
		if n > MaxSnapLen+4096 {
			return scanSummary{}, fmt.Errorf("%w: metadata read length %d exceeds limit", ErrInvalidBlock, n)
		}
		if int64(cap(scratch)) < n {
			scratch = make([]byte, n)
		}
		tail := scratch[:n]
		if err := readExactAt(r, tail, tailOffset, size); err != nil {
			return scanSummary{}, err
		}
		if order.Uint32(tail[n-4:]) != blockLen {
			return scanSummary{}, fmt.Errorf("%w: trailing block length mismatch", ErrInvalidBlock)
		}
		if packetErr != nil {
			return scanSummary{}, packetErr
		}
		if cb != nil && isCaptureOnlyBlock(blockType) {
			offset = int64(blockEnd)
			continue
		}
		body := tail[:n-4]
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
		case BlockTypeEnhancedPacket, BlockTypeSimplePacket:
			if len(body) > 0 {
				if err := decodeEPBOptions(body, order, &summary, &rec); err != nil {
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
