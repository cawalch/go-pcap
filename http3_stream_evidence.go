package pcap

import "errors"

type http3LocatedStream struct {
	quicLocatedStream
	framing  HTTP3Stream
	invalid  bool
	sections []QPACKFieldSection
}

type http3Direction struct {
	requests         []*http3LocatedStream
	control, encoder *http3LocatedStream
	capacity         uint64
	settingsEnd      int
	settingsKnown    bool
}

func locateHTTP3Streams(packets []QUIC1RTTPacket, server bool, remainingFrames *int) (http3Direction, error) {
	var out http3Direction
	located, err := locateQUICStreams(packets)
	if err != nil {
		return out, err
	}
	for _, loc := range located {
		s := &http3LocatedStream{quicLocatedStream: loc}
		stream := s.stream
		// Request streams are client-initiated and bidirectional. All
		// unidirectional streams must be sent by their initiator.
		if stream.ID&3 == 1 || stream.ID&2 != 0 && (stream.ID&1 != 0) != server {
			return out, ErrInvalidHTTP3
		}
		s.framing, err = ParseHTTP3Stream(stream)
		if err != nil {
			if errors.Is(err, ErrHTTP3Limit) {
				return out, err
			}
			// Malformed request framing affects that stream. A broken control
			// stream can invalidate the QPACK settings for all peer streams.
			if stream.ID&2 != 0 {
				return out, err
			}
			s.invalid = true
		}
		if len(s.framing.Frames) > *remainingFrames {
			return out, ErrHTTP3Limit
		}
		*remainingFrames -= len(s.framing.Frames)
		if stream.ID&3 == 0 {
			out.requests = append(out.requests, s)
			continue
		}
		switch s.framing.Kind {
		case HTTP3StreamQPACKEncoder:
			if out.encoder != nil {
				return out, ErrInvalidHTTP3
			}
			out.encoder = s
		case HTTP3StreamControl:
			if out.control != nil {
				return out, ErrInvalidHTTP3
			}
			out.control = s
			if len(s.framing.Frames) > 0 {
				f := s.framing.Frames[0]
				out.settingsEnd = f.PayloadOffset + f.PayloadLength
				out.capacity, err = http3QPACKCapacity(stream.Data[f.PayloadOffset:out.settingsEnd])
				if err != nil {
					return out, err
				}
				out.settingsKnown = true
			}
		}
	}
	return out, nil
}

// The SETTINGS payload contains pairs of QUIC variable-length integers.
func http3QPACKCapacity(data []byte) (uint64, error) {
	var capacity uint64
	seen := map[uint64]bool{}
	for len(data) > 0 {
		id, n, ok := ReadQUICVarint(data)
		if !ok {
			return 0, ErrInvalidHTTP3
		}
		value, m, ok := ReadQUICVarint(data[n:])
		if !ok || seen[id] || id >= 2 && id <= 5 {
			return 0, ErrInvalidHTTP3
		}
		if len(seen) >= MaxHTTPHeaders {
			return 0, ErrHTTP3Limit
		}
		seen[id] = true
		if id == 1 {
			capacity = value
		}
		data = data[n+m:]
	}
	return capacity, nil
}
