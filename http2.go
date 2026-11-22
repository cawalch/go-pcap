package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
)

// HTTP2ClientPreface is the 24-byte RFC 9113 §3.4 HTTP/2 client connection preface.
var HTTP2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP/2 frame type codes (RFC 9113 §6).
const (
	HTTP2FrameData         uint8 = 0x0
	HTTP2FrameHeaders      uint8 = 0x1
	HTTP2FramePriority     uint8 = 0x2
	HTTP2FrameRSTStream    uint8 = 0x3
	HTTP2FrameSettings     uint8 = 0x4
	HTTP2FramePushPromise  uint8 = 0x5
	HTTP2FramePing         uint8 = 0x6
	HTTP2FrameGoAway       uint8 = 0x7
	HTTP2FrameWindowUpdate uint8 = 0x8
	HTTP2FrameContinuation uint8 = 0x9
)

// HTTP2Setting represents a single 6-byte parameter in an HTTP/2 SETTINGS frame.
type HTTP2Setting struct {
	ID    uint16
	Value uint32
}

// HTTP2StreamData holds reassembled DATA frame payloads for one HTTP/2 stream ID.
type HTTP2StreamData struct {
	StreamID uint32
	Data     []byte
}

// HTTP2Summary contains the parsed HTTP/2 frames, SETTINGS parameters, and
// carved DATA stream bodies from a directional HTTP/2 stream.
type HTTP2Summary struct {
	HasClientPreface    bool
	FrameCount          int
	Settings            []HTTP2Setting
	SettingsFingerprint string
	WindowUpdate        uint32
	Streams             []HTTP2StreamData
}

// HTTP2Record associates a parsed [HTTP2Summary] with its 5-tuple TCP flow and
// indicates whether it was extracted from a decrypted TLS stream.
type HTTP2Record struct {
	FlowIndex   int
	SrcAddr     netip.Addr
	DstAddr     netip.Addr
	SrcPort     uint16
	DstPort     uint16
	IsServer    bool
	IsDecrypted bool
	Summary     HTTP2Summary
}

// ParseHTTP2Frames parses an HTTP/2 byte stream (starting either with the
// 24-byte client connection preface or directly with a 9-byte HTTP/2 SETTINGS
// frame), extracts SETTINGS parameters and their fingerprint, and reassembles
// DATA frame payloads per stream ID under [MaxHTTPBodyBytes].
func ParseHTTP2Frames(stream []byte) (HTTP2Summary, error) {
	var out HTTP2Summary
	offset := 0
	if bytes.HasPrefix(stream, HTTP2ClientPreface) {
		out.HasClientPreface = true
		offset = len(HTTP2ClientPreface)
	}

	if len(stream)-offset < 9 {
		if out.HasClientPreface {
			return out, nil
		}
		return HTTP2Summary{}, fmt.Errorf("%w: buffer shorter than 9-byte HTTP/2 frame header", ErrInvalidHTTP)
	}
	// If no client preface is present, require the first frame to be a valid SETTINGS frame (type 0x04, stream 0).
	if !out.HasClientPreface {
		firstType := stream[offset+3]
		firstFlags := stream[offset+4]
		firstStream := binary.BigEndian.Uint32(stream[offset+5:offset+9]) & 0x7fffffff
		firstLen := int(stream[offset])<<16 | int(stream[offset+1])<<8 | int(stream[offset+2])
		if firstType != HTTP2FrameSettings || firstStream != 0 || (firstFlags&^0x01) != 0 || firstLen%6 != 0 || firstLen > 36 {
			return HTTP2Summary{}, fmt.Errorf("%w: stream does not begin with HTTP/2 preface or SETTINGS frame", ErrInvalidHTTP)
		}
	}

	dataByStream := make(map[uint32]*bytes.Buffer)
	var streamOrder []uint32
	totalDataBytes := 0

	for offset+9 <= len(stream) && out.FrameCount < MaxHTTP2FramesPerStream {
		fLen := int(stream[offset])<<16 | int(stream[offset+1])<<8 | int(stream[offset+2])
		fType := stream[offset+3]
		fFlags := stream[offset+4]
		streamID := binary.BigEndian.Uint32(stream[offset+5:offset+9]) & 0x7fffffff
		offset += 9

		if fType > HTTP2FrameContinuation || fLen > MaxHTTP2FramePayload || offset+fLen > len(stream) {
			break
		}
		payload := stream[offset : offset+fLen]
		offset += fLen
		out.FrameCount++

		switch fType {
		case HTTP2FrameSettings:
			// Ignore SETTINGS ACK frames (flag 0x01 with empty payload).
			if (fFlags&0x01) == 0 && len(out.Settings) == 0 && len(payload)%6 == 0 {
				count := min(len(payload)/6, MaxHTTP2Settings)
				out.Settings = make([]HTTP2Setting, count)
				var fpBuf [128]byte
				fp := fpBuf[:0]
				for i := range count {
					id := binary.BigEndian.Uint16(payload[i*6 : i*6+2])
					val := binary.BigEndian.Uint32(payload[i*6+2 : i*6+6])
					out.Settings[i] = HTTP2Setting{ID: id, Value: val}
					if i > 0 {
						fp = append(fp, ';')
					}
					fp = strconv.AppendUint(fp, uint64(id), 10)
					fp = append(fp, ':')
					fp = strconv.AppendUint(fp, uint64(val), 10)
				}
				out.SettingsFingerprint = string(fp)
			}

		case HTTP2FrameWindowUpdate:
			if len(payload) == 4 && out.WindowUpdate == 0 {
				out.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}

		case HTTP2FrameData:
			dataPayload := payload
			if (fFlags & 0x08) != 0 {
				// PADDED flag: 1-byte Pad Length prefix.
				if len(dataPayload) < 1 {
					break
				}
				padLen := int(dataPayload[0])
				if 1+padLen > len(dataPayload) {
					break
				}
				dataPayload = dataPayload[1 : len(dataPayload)-padLen]
			}
			if len(dataPayload) > 0 && totalDataBytes < MaxHTTPBodyBytes {
				take := min(len(dataPayload), MaxHTTPBodyBytes-totalDataBytes)
				buf, ok := dataByStream[streamID]
				if !ok {
					buf = &bytes.Buffer{}
					dataByStream[streamID] = buf
					streamOrder = append(streamOrder, streamID)
				}
				buf.Write(dataPayload[:take])
				totalDataBytes += take
			}
		}
	}

	if out.FrameCount == 0 && !out.HasClientPreface {
		return HTTP2Summary{}, fmt.Errorf("%w: no valid HTTP/2 frames decoded", ErrInvalidHTTP)
	}
	for _, sid := range streamOrder {
		out.Streams = append(out.Streams, HTTP2StreamData{
			StreamID: sid,
			Data:     dataByStream[sid].Bytes(),
		})
	}
	return out, nil
}

// HTTP2 extracts HTTP/2 frame summaries, SETTINGS fingerprints, and carved DATA
// stream payloads from both cleartext TCP streams (h2c) and DSB-decrypted TLS
// 1.2/1.3 streams.
func (c *Capture) HTTP2(data []byte) ([]HTTP2Record, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	var records []HTTP2Record
	for i := range streams {
		appendHTTP2FromTCPStream(&streams[i], false, &records)
	}
	if decStreams, err := c.DecryptedTLSStreams(data, nil); err == nil {
		for i := range decStreams {
			appendHTTP2FromTCPStream(&decStreams[i], true, &records)
		}
	}
	return records, nil
}

func appendHTTP2FromTCPStream(st *TCPStream, isDecrypted bool, records *[]HTTP2Record) {
	if len(st.Client.Data) >= 9 {
		if sum, err := ParseHTTP2Frames(st.Client.Data); err == nil {
			*records = append(*records, HTTP2Record{
				FlowIndex:   st.FlowIndex,
				SrcAddr:     st.SrcAddr,
				DstAddr:     st.DstAddr,
				SrcPort:     st.SrcPort,
				DstPort:     st.DstPort,
				IsServer:    false,
				IsDecrypted: isDecrypted,
				Summary:     sum,
			})
		}
	}
	if len(st.Server.Data) >= 9 {
		if sum, err := ParseHTTP2Frames(st.Server.Data); err == nil {
			*records = append(*records, HTTP2Record{
				FlowIndex:   st.FlowIndex,
				SrcAddr:     st.DstAddr,
				DstAddr:     st.SrcAddr,
				SrcPort:     st.DstPort,
				DstPort:     st.SrcPort,
				IsServer:    true,
				IsDecrypted: isDecrypted,
				Summary:     sum,
			})
		}
	}
}
