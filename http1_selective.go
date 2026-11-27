package pcap

import "bytes"

const httpMethodPrefixBytes = 8

// Defer payload reads until an opening qualifies. The existing packet and
// segment limits bound the index. Cached prefixes fit within the read budget.
type http1Payloads struct {
	budget scanReadBudget
	dirs   [][]http1PayloadRef
}

type http1PayloadRef struct {
	offset int64
	length int
	prefix []byte
}

func (p *http1Payloads) walk(source ipFrameSource, visit func(PacketRecord, Frame, int, []byte) error) error {
	var table flowIndexTable
	index := func(pkt PacketRecord, f Frame, prefix []byte) error {
		key, _ := makeCanonicalFlowKey(f.IPProtocol, f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort)
		flow, _, err := table.lookupOrInsert(key)
		if err != nil || f.IPProtocol != IPProtoTCP {
			return err
		}
		return visit(pkt, f, flow, prefix)
	}
	if source.reader == nil {
		return source.walk(func(pkt PacketRecord, f Frame, _ []byte) error {
			return index(pkt, f, nil)
		})
	}
	if err := source.capture.validateContainer(); err != nil {
		return err
	}
	p.budget = scanReadBudget{r: source.reader, remaining: MaxReaderAtScanBytes}
	return source.capture.walkScopedFlowPrefixes(&p.budget, source.scope, func(pkt PacketRecord, f Frame, frame []byte) error {
		start := int(f.PayloadOffset)
		return index(pkt, f, frame[start:min(len(frame), start+int(f.PayloadLength))])
	})
}

func (p *http1Payloads) add(dir int, pkt PacketRecord, f Frame, prefix []byte) {
	if dir == len(p.dirs) {
		p.dirs = append(p.dirs, nil)
	}
	p.dirs[dir] = append(p.dirs[dir], http1PayloadRef{
		offset: pkt.PayloadOffset + int64(f.PayloadOffset),
		length: int(f.PayloadLength),
		prefix: bytes.Clone(prefix),
	})
}

func (p *http1Payloads) read(source ipFrameSource, ref *http1PayloadRef, offset int, dst []byte) error {
	if source.reader == nil {
		start := ref.offset + int64(offset)
		copy(dst, source.data[start:start+int64(len(dst))])
		return nil
	}
	n := copy(dst, ref.prefix[min(offset, len(ref.prefix)):])
	return readExactAt(&p.budget, dst[n:], ref.offset+int64(offset+n), source.capture.fileSize)
}

func (p *http1Payloads) hasMethod(source ipFrameSource, dir int, segments []TCPSegmentInput) (bool, error) {
	var inline [8]int
	lengths := inline[:min(len(segments), len(inline))]
	if len(segments) > len(inline) {
		lengths = make([]int, len(segments))
	}
	refs := p.dirs[dir]
	for i := range refs {
		lengths[i] = refs[i].length
	}
	var prefix [httpMethodPrefixBytes]byte
	var readErr error
	end, gapped := 0, false
	_, _, err := assembleTCPRanges(segments, lengths, int64(len(prefix)), func(i, limit int, seq uint32, gap bool) {
		gapped = gapped || gap
		if gapped || readErr != nil {
			return
		}
		start := segments[i].Seq
		if segments[i].Flags&TCPFlagSYN != 0 {
			start++
		}
		readErr = p.read(source, &refs[i], int(seq-start), prefix[end:limit])
		end = limit
	})
	if err != nil {
		return false, err
	}
	return readErr == nil && hasHTTPMethodPrefix(prefix[:end]), readErr
}

func (p *http1Payloads) materialize(source ipFrameSource, dirs []http1Direction, streams []tcpMessageDirection) ([]bool, error) {
	candidates := make([]bool, len(dirs))
	for i := range dirs {
		if candidates[i] {
			continue
		}
		match, err := p.hasMethod(source, i, streams[i].segments)
		if err != nil {
			return nil, err
		}
		if match {
			candidates[i] = true
			if peer := dirs[i].peer; peer != 0 {
				candidates[peer-1] = true
			}
		}
	}

	remaining := MaxTotalStreamBytes
	for i, candidate := range candidates {
		refs := p.dirs[i]
		p.dirs[i] = nil
		if !candidate {
			continue
		}
		for j := range refs {
			ref := &refs[j]
			if ref.length == 0 {
				continue
			}
			if ref.length > remaining {
				return nil, ErrReassemblyLimit
			}
			remaining -= ref.length
			seg := &streams[i].segments[j]
			if source.reader == nil {
				seg.Payload = source.data[ref.offset : ref.offset+int64(ref.length)]
				continue
			}
			if len(ref.prefix) == ref.length {
				seg.Payload = ref.prefix
				continue
			}
			if err := p.budget.check(int64(ref.length - len(ref.prefix))); err != nil {
				return nil, err
			}
			seg.Payload = make([]byte, ref.length)
			if err := p.read(source, ref, 0, seg.Payload); err != nil {
				return nil, err
			}
		}
	}
	return candidates, nil
}
