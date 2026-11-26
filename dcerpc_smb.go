package pcap

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"math"
	"slices"
	"sort"
)

const (
	smbRPCLogoff         = 0x0002
	smbRPCTreeDisconnect = 0x0004
	smbRPCRead           = 0x0008
	smbRPCWrite          = 0x0009
	smbRPCIOCTL          = 0x000b
	smbRPCPipeTransceive = 0x0011c017
	smbRPCPending        = 0x00000103
	smbRPCBufferOverflow = 0x80000005
)

type smbRPCScan struct {
	openings map[int]int
	events   []smbRPCEvent
}

type smbRPCEvent struct {
	opening, seenAt int
	dir             *tcpMessageDirection
	spans           []packetSpan
	session, id     uint64
	asyncID         uint64
	tree, status    uint32
	command         uint16
	response, async bool
	pipeShare       bool
	payload         []byte
	offset          int
}

func isRPCSMBPort(src, dst uint16) bool {
	return src == 139 || src == 445 || dst == 139 || dst == 445
}

func (s *smbRPCScan) addTCP(c *tcpMessageCollector, pkt PacketRecord, f Frame, flow int, data []byte) error {
	if !isRPCSMBPort(f.SrcPort, f.DstPort) {
		return c.add(pkt, f, flow, data)
	}
	if !keepTCPMessageSegment(&f, len(data), TCPFlagSYN) {
		return nil
	}
	before := len(c.directions)
	dirs, err := c.addSegment(pkt, f, flow, data)
	if err != nil || len(c.directions) == before || dirs[1] == 0 {
		return err
	}
	first := c.directions[dirs[0]-1].packets[0].index
	peer := c.directions[dirs[1]-1].packets[0].index
	if s.openings == nil {
		s.openings = make(map[int]int)
	}
	s.openings[first], s.openings[peer] = min(first, peer), min(first, peer)
	return nil
}

func (s *smbRPCScan) collect(dir *tcpMessageDirection, data []byte, spans []packetSpan) error {
	opening := dir.packets[0].index
	if paired, ok := s.openings[opening]; ok {
		opening = paired
	}
	var savedSpans []packetSpan
	var seenAt, consumed, span int
	netBIOS := dir.src.Port() == 139 || dir.dst.Port() == 139
	for len(data)-consumed >= 4 {
		header := data[consumed : consumed+4]
		if netBIOS && header[1] > 1 {
			break
		}
		length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
		start := consumed + 4
		if length > len(data)-start {
			break
		}
		consumed = start + length
		if header[0] == 0x85 && length == 0 {
			continue
		}
		if netBIOS && start == 4 && (header[0] == 0x81 && length >= 68 || header[0] == 0x82 && length == 0) {
			continue
		}
		if header[0] != 0 || length < 4 || !bytes.Equal(data[start+1:start+4], smb2Magic[1:]) {
			break
		}
		switch data[start] {
		case 0xff, 0xfd, 0xfc:
			continue // Legacy SMB, encrypted SMB3, or compressed SMB3.
		case 0xfe:
		default:
			return nil
		}
		if length > MaxSMB2PacketBytes {
			continue
		}
		var previous smbRPCEvent
		for frame := data[start:consumed]; len(frame) != 0; {
			commandAt := consumed - len(frame)
			cmd, rest, err := splitSMB2Command(frame)
			if err != nil {
				break
			}
			frame = rest
			e := readSMBRPCEvent(cmd, previous)
			previous = e
			if !e.keep(cmd[64:]) {
				continue
			}
			if len(s.events) == MaxSMBRecordsPerScan {
				return ErrDCERPCLimit
			}
			// Process control events when the entire command has arrived.
			// Earlier commands in this direction may themselves be reordered.
			end := commandAt + len(cmd)
			for {
				seenAt = max(seenAt, dir.packets[spans[span].segment].index)
				if spans[span].end >= end {
					break
				}
				span++
			}
			e.opening, e.seenAt, e.dir = opening, seenAt, dir
			if len(e.payload) != 0 {
				if savedSpans == nil {
					savedSpans = slices.Clone(spans)
				}
				e.spans, e.offset = savedSpans, commandAt+e.offset
			}
			s.events = append(s.events, e)
		}
	}
	return nil
}

func readSMBRPCEvent(cmd []byte, previous smbRPCEvent) smbRPCEvent {
	le := binary.LittleEndian
	flags := le.Uint32(cmd[16:20])
	e := smbRPCEvent{
		command: le.Uint16(cmd[12:14]), status: le.Uint32(cmd[8:12]),
		id: le.Uint64(cmd[24:32]), session: le.Uint64(cmd[40:48]),
		response: flags&1 != 0, async: flags&2 != 0,
	}
	if e.async {
		e.asyncID = le.Uint64(cmd[32:40])
	} else {
		e.tree = le.Uint32(cmd[36:40])
	}
	if flags&4 != 0 {
		if e.session == math.MaxUint64 {
			e.session = previous.session
		}
		if e.tree == math.MaxUint32 {
			e.tree = previous.tree
		}
	}
	e.payload, e.offset = smbRPCPayload(cmd, e)
	return e
}

func (e *smbRPCEvent) keep(body []byte) bool {
	le := binary.LittleEndian
	switch e.command {
	case SMB2CommandTreeConnect:
		if !e.response || e.status != 0 || e.tree == 0 || e.tree == math.MaxUint32 {
			return false
		}
		e.pipeShare = len(body) >= 16 && le.Uint16(body) == 16 && body[2] == 2
		return true
	case smbRPCLogoff, smbRPCTreeDisconnect:
		return e.response && e.status == 0 && len(body) >= 4 && le.Uint16(body) == 4
	case smbRPCRead:
		// Track READ requests for asynchronous responses without a TreeId.
		return e.response || len(body) >= 48 && le.Uint16(body) == 49
	default:
		return len(e.payload) != 0
	}
}

func smbRPCPayload(cmd []byte, e smbRPCEvent) ([]byte, int) {
	if e.response && e.status != 0 && e.status != smbRPCBufferOverflow {
		return nil, 0
	}
	body := cmd[64:]
	le := binary.LittleEndian
	var offset, count uint32
	var minimum int
	switch e.command {
	case smbRPCWrite:
		if e.response || len(body) < 48 || le.Uint16(body) != 49 || le.Uint64(body[8:16]) != 0 {
			return nil, 0
		}
		offset, count, minimum = uint32(le.Uint16(body[2:4])), le.Uint32(body[4:8]), 112
	case smbRPCRead:
		if !e.response || len(body) < 16 || le.Uint16(body) != 17 {
			return nil, 0
		}
		offset, count, minimum = uint32(body[2]), le.Uint32(body[4:8]), 80
	case smbRPCIOCTL:
		if len(body) < 48 || le.Uint32(body[4:8]) != smbRPCPipeTransceive {
			return nil, 0
		}
		if e.response && le.Uint16(body) == 49 {
			offset, count, minimum = le.Uint32(body[32:36]), le.Uint32(body[36:40]), 112
		} else if !e.response && len(body) >= 56 && le.Uint16(body) == 57 && le.Uint32(body[48:52]) == 1 {
			offset, count, minimum = le.Uint32(body[24:28]), le.Uint32(body[28:32]), 120
		} else {
			return nil, 0
		}
	default:
		return nil, 0
	}
	if offset < uint32(minimum) || uint64(offset)+uint64(count) > uint64(len(cmd)) {
		return nil, 0
	}
	data := cmd[offset : offset+count]
	if !hasDCERPCPrefix(data) {
		return nil, 0
	}
	return data, int(offset)
}

type smbRPCSession struct {
	opening int
	id      uint64
}

type smbRPCReadState struct {
	dir        *tcpMessageDirection
	tree       uint32
	generation int
	asyncID    uint64
	pending    bool
}

type smbRPCSessionState struct {
	trees map[uint32]int
	reads map[uint64]smbRPCReadState
}

func (s *smbRPCScan) walk(emit func(*tcpMessageDirection, messagePacket, DCERPCMessage, uint16) error) error {
	if len(s.events) == 0 {
		return nil
	}
	slices.SortStableFunc(s.events, func(a, b smbRPCEvent) int { return cmp.Compare(a.seenAt, b.seenAt) })
	sessions := make(map[smbRPCSession]*smbRPCSessionState)
	for i, e := range s.events {
		key := smbRPCSession{e.opening, e.session}
		state := sessions[key]
		pipe := false
		switch e.command {
		case SMB2CommandTreeConnect:
			if e.pipeShare {
				if state == nil {
					state = &smbRPCSessionState{trees: make(map[uint32]int)}
					sessions[key] = state
				}
				state.trees[e.tree] = i + 1
			} else if state != nil {
				delete(state.trees, e.tree)
			}
		case smbRPCLogoff:
			delete(sessions, key)
		case smbRPCTreeDisconnect:
			if state != nil {
				delete(state.trees, e.tree)
			}
		case smbRPCRead:
			if state != nil {
				pipe = state.readIsPipe(e)
			}
		case smbRPCWrite:
			pipe = state != nil && state.trees[e.tree] != 0
		case smbRPCIOCTL:
			pipe = true // FSCTL_PIPE_TRANSCEIVE identifies the pipe operation.
		}
		if !pipe || len(e.payload) == 0 {
			continue
		}
		span := sort.Search(len(e.spans), func(i int) bool { return e.spans[i].end > e.offset })
		if err := walkDCERPCFragments(e.payload, func(off int, msg DCERPCMessage) error {
			for e.spans[span].end <= e.offset+off {
				span++
			}
			return emit(e.dir, e.dir.packets[e.spans[span].segment], msg, e.command)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *smbRPCSessionState) readIsPipe(e smbRPCEvent) bool {
	if !e.response {
		delete(s.reads, e.id)
		if generation := s.trees[e.tree]; generation != 0 {
			if s.reads == nil {
				s.reads = make(map[uint64]smbRPCReadState)
			}
			s.reads[e.id] = smbRPCReadState{dir: e.dir, tree: e.tree, generation: generation}
		}
		return false
	}
	read, found := s.reads[e.id]
	matched := found && read.dir != e.dir
	if e.status == smbRPCPending {
		if matched && e.async && !read.pending {
			read.asyncID, read.pending = e.asyncID, true
			s.reads[e.id] = read
		}
		return false
	}
	if matched {
		delete(s.reads, e.id)
	}
	if !e.async {
		return s.trees[e.tree] != 0
	}
	return matched && s.trees[read.tree] == read.generation && (!read.pending || read.asyncID == e.asyncID)
}
