package pcap

// Limits for authenticated connection-ID history. Each direction starts with
// the Initial source ID issued by its peer. Sequence numbers are sparse.
const (
	MaxKeyedQUICActiveIDs     = 16
	MaxKeyedQUICHistoricalIDs = 64
	MaxKeyedQUICLearnedIDs    = 16_384
)

type quicCIDChange struct {
	sequence, prior uint64
	id              quicCID // Empty for RETIRE_CONNECTION_ID.
	token           [16]byte
}

func (r *quicFrameReader) newConnectionID() quicCIDChange {
	op := quicCIDChange{sequence: r.varint(), prior: r.varint()}
	length := r.take(1)
	if len(length) != 1 || length[0] == 0 || length[0] > MaxQUICConnIDBytes {
		r.err = ErrInvalidQUIC
		return op
	}
	op.id = makeQUICCID(r.take(uint64(length[0])))
	copy(op.token[:], r.take(16))
	return op
}

type quicCIDEntry struct {
	id         quicCID
	token      [16]byte
	tokenKnown bool
	retired    bool
	retiredAt  uint64 // Packet number in the direction that used this DCID.
}

type quicCIDHistory struct {
	bySequence map[uint64]*quicCIDEntry
	byID       map[quicCID]uint64
	prior      uint64
	conflict   bool
}

func (h *quicCIDHistory) accepts(id quicCID, pn uint64) bool {
	if h == nil {
		return true
	}
	seq, known := h.byID[id]
	if !known || h.conflict {
		return false
	}
	entry := h.bySequence[seq]
	if entry.retired {
		return pn < entry.retiredAt
	}
	return seq >= h.prior
}

// Only a completely parsed, uniquely authenticated packet can change the
// lookup table. An unknown trailing frame leaves its application bytes usable
// but prevents committing partial connection-ID changes.
func (s *quicKeyedScan) observeCIDs(dir *quicKeyedDirection, number uint64, payload []byte) error {
	var inline [4]quicCIDChange
	changes := inline[:0]
	r := quicFrameReader{data: payload}
	for len(r.data) > 0 && r.err == nil {
		typ := r.data[0]
		r.data = r.data[1:]
		switch {
		case typ == 0x18:
			op := r.newConnectionID()
			if op.prior > op.sequence {
				return nil
			}
			changes = append(changes, op)
		case typ == 0x19:
			changes = append(changes, quicCIDChange{sequence: r.varint()})
		case typ == 0x04 || typ >= 0x08 && typ <= 0x0f:
			r.streamFrame(typ)
		default:
			r.skip(typ)
		}
		if len(changes) > MaxKeyedQUICHistoricalIDs {
			return ErrQUICLimit
		}
	}
	if r.err != nil {
		return nil
	}
	for _, op := range changes {
		target := dir
		if op.id.length != 0 {
			target = dir.peer
		}
		if target == nil || target.decoder == nil || target.initial.cid.length == 0 {
			continue
		}
		if err := s.applyCID(target, op, number); err != nil {
			return err
		}
	}
	return nil
}

func (s *quicKeyedScan) applyCID(dir *quicKeyedDirection, op quicCIDChange, number uint64) error {
	if dir.ids == nil {
		id := dir.initial.cid
		dir.ids = &quicCIDHistory{bySequence: map[uint64]*quicCIDEntry{0: {id: id}}, byID: map[quicCID]uint64{id: 0}}
	}
	h := dir.ids
	if h.conflict {
		return nil
	}
	entry := h.bySequence[op.sequence]
	if entry == nil {
		if len(h.bySequence) >= MaxKeyedQUICHistoricalIDs || s.learnedIDs == MaxKeyedQUICLearnedIDs {
			return ErrQUICLimit
		}
		entry = new(quicCIDEntry)
		h.bySequence[op.sequence] = entry
		s.learnedIDs++
	}
	if op.id.length == 0 {
		// A sender cannot retire the DCID used by this very packet.
		if entry.id == dir.packetCID && entry.id.length != 0 {
			h.conflict = true
			return nil
		}
		if !entry.retired || number < entry.retiredAt {
			entry.retiredAt = number
		}
		entry.retired = true
		return nil
	}
	seq, used := h.byID[op.id]
	if used && seq != op.sequence || entry.id.length != 0 && entry.id != op.id || entry.tokenKnown && entry.token != op.token {
		h.conflict = true
		return nil
	}
	h.prior = max(h.prior, op.prior)
	entry.token, entry.tokenKnown = op.token, true
	if used {
		return nil
	}
	entry.id = op.id
	h.byID[op.id] = op.sequence
	active := 0
	for seq, v := range h.bySequence {
		if seq >= h.prior && !v.retired && v.id.length != 0 {
			active++
		}
	}
	if active > MaxKeyedQUICActiveIDs {
		return ErrQUICLimit
	}
	key := s.registerCID(dir.initial.path, 0, op.id)
	s.candidates[key] = append(s.candidates[key], dir)
	return nil
}
