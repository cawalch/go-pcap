package pcap

import (
	"errors"
	"fmt"
)

// MaxHTTP3FramesPerStream bounds frame records returned for one sender.
const MaxHTTP3FramesPerStream = 1024

var (
	// ErrInvalidHTTP3 indicates invalid HTTP/3 framing or frame placement.
	ErrInvalidHTTP3 = errors.New("invalid HTTP/3 framing")
	// ErrHTTP3Limit indicates that HTTP/3 framing exceeds a size or frame limit.
	ErrHTTP3Limit = errors.New("HTTP/3 framing exceeds limit")
)

// HTTP3StreamKind identifies how HTTP/3 uses a QUIC stream.
type HTTP3StreamKind uint8

const (
	HTTP3StreamUnknown HTTP3StreamKind = iota
	HTTP3StreamRequest
	HTTP3StreamControl
	HTTP3StreamPush
	HTTP3StreamQPACKEncoder
	HTTP3StreamQPACKDecoder
)

// HTTP/3 frame types defined by RFC 9114.
const (
	HTTP3FrameData        = 0x00
	HTTP3FrameHeaders     = 0x01
	HTTP3FrameCancelPush  = 0x03
	HTTP3FrameSettings    = 0x04
	HTTP3FramePushPromise = 0x05
	HTTP3FrameGoAway      = 0x07
	HTTP3FrameMaxPushID   = 0x0d
)

// HTTP3Frame locates a complete frame in the original [QUICStream].Data.
// Offset is the start of the frame type field, including any stream prologue
// when counting from offset zero.
type HTTP3Frame struct {
	Type          uint64
	Offset        int
	PayloadOffset int
	PayloadLength int
}

// HTTP3Stream describes the framing observed in one directional QUIC stream.
// StreamType is the wire type for a unidirectional stream with a parsed type.
// PushID is defined for push streams with a complete prologue.
// HeaderLength counts the prologue bytes parsed before any frames.
// Incomplete reports that the source stream lacks a clean end.
// Truncated reports an incomplete prologue or frame at the end of the input.
// QPACK and unknown stream types produce no frame records.
type HTTP3Stream struct {
	ID           uint64
	Kind         HTTP3StreamKind
	StreamType   uint64
	PushID       uint64
	HeaderLength int
	Incomplete   bool
	Truncated    bool
	Frames       []HTTP3Frame
}

// ParseHTTP3Stream delimits frames in the contiguous prefix of a [QUICStream]
// from a connection known to carry HTTP/3. Keep the two senders separate.
// The parser validates frame placement by stream kind and the control stream's
// initial SETTINGS. Frame records describe wire ranges and own no payload bytes.
// Frame payloads remain opaque, including compressed field sections.
//
// A gap, reset, or missing FIN can leave a partial prologue or frame. In that
// case the result contains preceding complete frames and sets Truncated. A
// clean FIN in the middle of a prologue or frame returns [ErrInvalidHTTP3].
// Limit and framing errors return a zero result.
func ParseHTTP3Stream(stream QUICStream) (HTTP3Stream, error) {
	if len(stream.Data) > MaxQUICStreamBytes {
		return HTTP3Stream{}, ErrHTTP3Limit
	}
	if stream.ID >= 1<<62 || stream.ID&3 == 1 {
		return HTTP3Stream{}, fmt.Errorf("%w: invalid HTTP/3 stream ID %d", ErrInvalidHTTP3, stream.ID)
	}
	cleanEnd := stream.Complete && !stream.Gap && !stream.Reset
	out := HTTP3Stream{ID: stream.ID, Kind: HTTP3StreamRequest, Incomplete: !cleanEnd}
	if stream.ID&2 != 0 {
		out.Kind = HTTP3StreamUnknown
		typ, n, ok := ReadQUICVarint(stream.Data)
		if !ok {
			return truncatedHTTP3(out, cleanEnd)
		}
		out.StreamType = typ
		out.HeaderLength = n
		switch typ {
		case 0:
			out.Kind = HTTP3StreamControl
		case 1:
			if stream.ID&1 == 0 {
				return HTTP3Stream{}, fmt.Errorf("%w: client push stream", ErrInvalidHTTP3)
			}
			out.Kind = HTTP3StreamPush
			id, size, ok := ReadQUICVarint(stream.Data[n:])
			if !ok {
				return truncatedHTTP3(out, cleanEnd)
			}
			out.PushID = id
			out.HeaderLength += size
		case 2:
			out.Kind = HTTP3StreamQPACKEncoder
			return out, nil
		case 3:
			out.Kind = HTTP3StreamQPACKDecoder
			return out, nil
		default:
			return out, nil
		}
	}

	for offset := out.HeaderLength; offset < len(stream.Data); {
		if len(out.Frames) == MaxHTTP3FramesPerStream {
			return HTTP3Stream{}, ErrHTTP3Limit
		}
		typ, n, ok := ReadQUICVarint(stream.Data[offset:])
		if !ok {
			return truncatedHTTP3(out, cleanEnd)
		}
		length, m, ok := ReadQUICVarint(stream.Data[offset+n:])
		if !ok {
			return truncatedHTTP3(out, cleanEnd)
		}
		if length > MaxQUICStreamBytes {
			return HTTP3Stream{}, ErrHTTP3Limit
		}
		payload := offset + n + m
		if length > uint64(len(stream.Data)-payload) {
			return truncatedHTTP3(out, cleanEnd)
		}
		if !http3FrameAllowed(typ, out.Kind, len(out.Frames) == 0) {
			return HTTP3Stream{}, fmt.Errorf("%w: frame type %#x at stream offset %d", ErrInvalidHTTP3, typ, offset)
		}
		out.Frames = append(out.Frames, HTTP3Frame{Type: typ, Offset: offset, PayloadOffset: payload, PayloadLength: int(length)})
		offset = payload + int(length)
	}
	if out.Kind == HTTP3StreamControl && cleanEnd && len(out.Frames) == 0 {
		return HTTP3Stream{}, fmt.Errorf("%w: control stream missing SETTINGS", ErrInvalidHTTP3)
	}
	return out, nil
}

func truncatedHTTP3(out HTTP3Stream, cleanEnd bool) (HTTP3Stream, error) {
	if cleanEnd {
		return HTTP3Stream{}, fmt.Errorf("%w: incomplete prologue or frame at FIN", ErrInvalidHTTP3)
	}
	out.Truncated = true
	return out, nil
}

func http3FrameAllowed(typ uint64, kind HTTP3StreamKind, first bool) bool {
	if kind == HTTP3StreamControl && first {
		return typ == HTTP3FrameSettings
	}
	switch typ {
	case 0x02, 0x06, 0x08, 0x09: // Reserved HTTP/2 frame types.
		return false
	case HTTP3FrameSettings:
		return false // SETTINGS is only allowed first on the control stream.
	case HTTP3FrameData, HTTP3FrameHeaders:
		return kind == HTTP3StreamRequest || kind == HTTP3StreamPush
	case HTTP3FrameCancelPush, HTTP3FrameGoAway, HTTP3FrameMaxPushID:
		return kind == HTTP3StreamControl
	case HTTP3FramePushPromise:
		return kind == HTTP3StreamRequest
	default:
		return true // Unknown extensions still have delimited wire ranges.
	}
}
