package pcap

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"sort"
)

// SMB2Evidence locates a decoded command or observed encrypted transform
// header in its original capture. OpeningPacket is the first packet observed
// in its TCP opening. PacketIndex identifies the packet that supplied the
// first byte of the SMB magic. PacketIndices lists all distinct contributing
// packets in capture order, including for a command split across packets.
// The packet supplying the first byte can appear later in capture order.
// Packet indices are zero-based and omit retransmissions that add no bytes.
// The caller owns PacketIndices.
//
// StreamOffset and WireLength describe the byte range in the recovered TCP
// direction before stripping any proxy preface. A compound command ends at
// its next-command offset or the end of the NetBIOS frame. For an unframed
// last command the range reaches the end of the available contiguous input.
// An encrypted transform contributes only its visible 52-byte header.
// A source packet may also contain bytes for other commands.
type SMB2Evidence struct {
	SMB2Record
	OpeningPacket int
	PacketIndex   int
	StreamOffset  int
	WireLength    int
	PacketIndices []int
}

const maxSMBEvidenceSpans = 262_144

// SMB extracts SMB2 commands, embedded NTLMSSP metadata and SMB3 encrypted
// transform headers across the reassembled TCP streams in a capture.
// Message parsing in each direction stops at its first known TCP sequence gap.
func (c *Capture) SMB(data []byte) ([]SMB2Record, error) {
	var records []SMB2Record
	err := walkSMB(ipFrameSource{capture: c, data: data}, tcpWireNone,
		func(record SMB2Record, _, _, _ int, _ []tcpWireSpan) error {
			records = append(records, record)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return records, nil
}

// SMB2Evidence extracts the same records as [Capture.SMB] and locates
// their original packets. The scan charges up to 262,144 packet span
// references before deduplication. A scan or limit error discards the result.
func (c *Capture) SMB2Evidence(data []byte) ([]SMB2Evidence, error) {
	return scanSMB2Evidence(ipFrameSource{capture: c, data: data})
}

// SMB2EvidenceFromReaderAt is the bounded ReaderAt equivalent of
// [Capture.SMB2Evidence]. The scan reads TCP payloads on any port and shares
// [MaxReaderAtScanBytes] across packet metadata and payload reads.
func (c *Capture) SMB2EvidenceFromReaderAt(r io.ReaderAt) ([]SMB2Evidence, error) {
	return scanSMB2Evidence(c.tcpReaderAt(r))
}

func scanSMB2Evidence(source ipFrameSource) ([]SMB2Evidence, error) {
	var records []SMB2Evidence
	remaining := maxSMBEvidenceSpans
	err := walkSMB(source, tcpWireSpans, func(record SMB2Record, opening, start, length int, spans []tcpWireSpan) error {
		row := SMB2Evidence{SMB2Record: record, OpeningPacket: opening, StreamOffset: start, WireLength: length}
		if err := row.locate(spans, &remaining); err != nil {
			return err
		}
		records = append(records, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (r *SMB2Evidence) locate(spans []tcpWireSpan, remaining *int) error {
	start, end := r.StreamOffset, r.StreamOffset+r.WireLength
	first := sort.Search(len(spans), func(i int) bool { return int(spans[i].end) > start })
	last := first
	for last < len(spans) && int(spans[last].end) < end {
		last++
	}
	if last == len(spans) {
		return ErrInvalidSMB
	}
	count := last - first + 1
	if count > *remaining {
		return ErrSMBLimit
	}
	*remaining -= count
	r.PacketIndex = int(spans[first].packet.index)
	r.PacketIndices = make([]int, 0, count)
	for _, span := range spans[first : last+1] {
		r.PacketIndices = append(r.PacketIndices, int(span.packet.index))
	}
	slices.Sort(r.PacketIndices)
	r.PacketIndices = slices.Compact(r.PacketIndices)
	return nil
}

func walkSMB(source ipFrameSource, mode tcpWireMode, visit func(record SMB2Record, opening, offset, length int, spans []tcpWireSpan) error) error {
	var meta []streamMetadata
	streams, err := collectStreams(source, 0, &meta, mode)
	if err != nil {
		return err
	}
	count := 0
	for i := range streams {
		info := &meta[i]
		wire := info.contiguousStream(streams[i])
		st, clientOffset, serverOffset := proxyStream(wire)
		spans := [2][]tcpWireSpan{info.wire[0].spans, info.wire[1].spans}
		if st.SrcAddr != wire.SrcAddr || st.SrcPort != wire.SrcPort {
			spans[0], spans[1] = spans[1], spans[0]
		}
		offsets := [2]int{clientOffset, serverOffset}
		for dir, data := range [2][]byte{st.Client.Data, st.Server.Data} {
			record := SMB2Record{FlowIndex: st.FlowIndex, SrcAddr: st.SrcAddr, DstAddr: st.DstAddr,
				SrcPort: st.SrcPort, DstPort: st.DstPort}
			if dir == 1 {
				record.SrcAddr, record.DstAddr = record.DstAddr, record.SrcAddr
				record.SrcPort, record.DstPort = record.DstPort, record.SrcPort
			}
			err := walkSMBCommands(data, func(off, length int, msg SMB2Message) error {
				if count >= MaxSMBRecordsPerScan {
					return fmt.Errorf("%w: exceeds %d SMB2 records", ErrSMBLimit, MaxSMBRecordsPerScan)
				}
				count++
				record.Message = msg
				return visit(record, info.firstPacket, offsets[dir]+off, length, spans[dir])
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func walkSMBCommands(stream []byte, visit func(int, int, SMB2Message) error) error {
	for off := 0; len(stream)-off >= 4; {
		data := stream[off:]
		start := off
		var frame []byte
		switch data[0] {
		case 0x85:
			// NetBIOS Session Keep-Alive (4-byte header, zero payload).
			if data[1] != 0 || data[2] != 0 || data[3] != 0 {
				return nil
			}
			off += 4
			continue
		case 0x00:
			n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
			if n > len(data)-4 {
				return nil
			}
			start += 4
			frame = data[4 : 4+n]
			off = start + n
			if n > MaxSMB2PacketBytes {
				// Skip oversized data frames without aborting the flow.
				continue
			}
			if !bytes.HasPrefix(frame, smb2Magic) && !bytes.HasPrefix(frame, smb3TransformMagic) {
				// Skip SMB1 Negotiate and SMB3 compression.
				continue
			}
		default:
			if !bytes.HasPrefix(data, smb2Magic) && !bytes.HasPrefix(data, smb3TransformMagic) {
				return nil
			}
			frame = data
			off = len(stream)
		}
		for len(frame) > 0 {
			msg, next, err := parseSMBCommand(frame)
			length := len(frame) - len(next)
			if err == nil {
				size := length
				if msg.IsEncrypted {
					size = 52
				}
				if err := visit(start, size, msg); err != nil {
					return err
				}
			}
			start += length
			frame = next
		}
	}
	return nil
}
