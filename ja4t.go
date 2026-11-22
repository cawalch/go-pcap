package pcap

import (
	"encoding/binary"
	"strconv"
)

// TCP option kinds.
const (
	tcpOptKindEOL         uint8 = 0
	tcpOptKindNOP         uint8 = 1
	tcpOptKindMSS         uint8 = 2
	tcpOptKindWindowScale uint8 = 3
)

// JA4T computes the FoxIO JA4T (or JA4TS) TCP fingerprint from a TCP header's
// window size and raw TCP option bytes:
//
//	<window>_<option_kinds_joined_by_hyphen>_<mss>_<window_scale>
//
// When no options are present, the option list is "00". When MSS or Window
// Scale is absent, its field is "00". If the TCP option TLV stream is truncated
// or contains an invalid length (< 2), JA4T stops at the malformed option and
// returns ok == false along with the partial fingerprint.
func JA4T(window uint16, options []byte) (string, bool) {
	var kinds [MaxTCPOptions]uint8
	kindCount := 0
	var mss uint16
	var hasMSS bool
	var ws uint8
	var hasWS bool
	valid := true

	i := 0
	for i < len(options) {
		if kindCount >= MaxTCPOptions {
			valid = false
			break
		}
		kind := options[i]
		kinds[kindCount] = kind
		kindCount++

		if kind == tcpOptKindEOL {
			// Wireshark reports consecutive zero padding bytes as EOLs.
			i++
			if i < len(options) && options[i] == tcpOptKindEOL {
				continue
			}
			break
		}
		if kind == tcpOptKindNOP {
			i++
			continue
		}
		if i+1 >= len(options) {
			valid = false
			break
		}
		optLen := int(options[i+1])
		if optLen < 2 || i+optLen > len(options) {
			valid = false
			break
		}
		switch kind {
		case tcpOptKindMSS:
			if optLen == 4 {
				mss = binary.BigEndian.Uint16(options[i+2 : i+4])
				hasMSS = true
			} else {
				valid = false
			}
		case tcpOptKindWindowScale:
			if optLen == 3 {
				ws = options[i+2]
				hasWS = true
			} else {
				valid = false
			}
		}
		i += optLen
	}

	var buf [96]byte
	out := strconv.AppendUint(buf[:0], uint64(window), 10)
	out = append(out, '_')
	if kindCount == 0 {
		out = append(out, "00"...)
	} else {
		for idx := range kindCount {
			if idx > 0 {
				out = append(out, '-')
			}
			out = strconv.AppendUint(out, uint64(kinds[idx]), 10)
		}
	}
	out = append(out, '_')
	if hasMSS {
		out = strconv.AppendUint(out, uint64(mss), 10)
	} else {
		out = append(out, "00"...)
	}
	out = append(out, '_')
	if hasWS {
		out = strconv.AppendUint(out, uint64(ws), 10)
	} else {
		out = append(out, "00"...)
	}
	return string(out), valid
}

// JA4T computes the JA4T (for SYN) or JA4TS (for SYN-ACK) TCP fingerprint for f
// using the original frame bytes passed to [DecodeFrame]. It returns ("", false)
// when f is not a TCP SYN or SYN-ACK frame or its option span lies outside
// frameData.
func (f *Frame) JA4T(frameData []byte) (string, bool) {
	if f == nil || f.IPProtocol != IPProtoTCP || (f.TCPFlags&TCPFlagSYN) == 0 {
		return "", false
	}
	var opts []byte
	if f.TCPOptionsLength > 0 {
		end := uint64(f.TCPOptionsOffset) + uint64(f.TCPOptionsLength)
		if end > uint64(len(frameData)) {
			return "", false
		}
		opts = frameData[f.TCPOptionsOffset:end]
	}
	return JA4T(f.TCPWindow, opts)
}

// JA4L formats a FoxIO JA4L (Light Distance / Latency) fingerprint from a
// one-way or half-RTT latency delta in nanoseconds and the peer's IP TTL /
// HopLimit:
//
//	<half_rtt_microseconds>_<ttl>
func JA4L(deltaNs int64, ttl uint8) string {
	if deltaNs < 0 {
		deltaNs = 0
	}
	halfRTTMicros := uint64(deltaNs) / 2_000
	// Round to the nearest microsecond, with an even result at a tie.
	remainder := deltaNs % 2_000
	if remainder > 1_000 || remainder == 1_000 && halfRTTMicros%2 != 0 {
		halfRTTMicros++
	}
	var buf [32]byte
	out := strconv.AppendUint(buf[:0], halfRTTMicros, 10)
	out = append(out, '_')
	out = strconv.AppendUint(out, uint64(ttl), 10)
	return string(out)
}

// JA4SSHSegment describes one TCP packet in an SSH flow for [JA4SSH].
type JA4SSHSegment struct {
	IsClient      bool
	PayloadLength int
	Flags         uint8
}

type ja4sshAccumulator struct {
	clientCounts   map[int]int
	serverCounts   map[int]int
	clientDataPkts int
	serverDataPkts int
	clientBareACKs int
	serverBareACKs int
}

func (a *ja4sshAccumulator) add(seg JA4SSHSegment) {
	if seg.PayloadLength > 0 {
		if seg.IsClient {
			a.clientDataPkts++
			if a.clientCounts == nil {
				a.clientCounts = make(map[int]int)
			}
			a.clientCounts[seg.PayloadLength]++
		} else {
			a.serverDataPkts++
			if a.serverCounts == nil {
				a.serverCounts = make(map[int]int)
			}
			a.serverCounts[seg.PayloadLength]++
		}
	} else if (seg.Flags&TCPFlagACK) != 0 && (seg.Flags&(TCPFlagSYN|TCPFlagFIN|TCPFlagRST)) == 0 {
		if seg.IsClient {
			a.clientBareACKs++
		} else {
			a.serverBareACKs++
		}
	}
}

func (a *ja4sshAccumulator) fingerprint() string {
	clientMode := modePayloadLen(a.clientCounts)
	serverMode := modePayloadLen(a.serverCounts)

	var buf [64]byte
	out := append(buf[:0], 'c')
	out = strconv.AppendInt(out, int64(clientMode), 10)
	out = append(out, 's')
	out = strconv.AppendInt(out, int64(serverMode), 10)
	out = append(out, '_', 'c')
	out = strconv.AppendInt(out, int64(a.clientDataPkts), 10)
	out = append(out, 's')
	out = strconv.AppendInt(out, int64(a.serverDataPkts), 10)
	out = append(out, '_', 'c')
	out = strconv.AppendInt(out, int64(a.clientBareACKs), 10)
	out = append(out, 's')
	out = strconv.AppendInt(out, int64(a.serverBareACKs), 10)
	return string(out)
}

// JA4SSH computes the FoxIO JA4SSH fingerprint over a sequence of bidirectional
// TCP segments:
//
//	c<client_mode_len>s<server_mode_len>_c<client_data_pkts>s<server_data_pkts>_c<client_bare_acks>s<server_bare_acks>
//
// When two payload lengths share the same maximum frequency, the smaller length
// wins (matching FoxIO JA4SSH tie-breaking).
func JA4SSH(segments []JA4SSHSegment) string {
	var acc ja4sshAccumulator
	for i := range segments {
		acc.add(segments[i])
	}
	return acc.fingerprint()
}

func modePayloadLen(counts map[int]int) int {
	bestLen := 0
	bestCount := 0
	for length, c := range counts {
		if c > bestCount || (c == bestCount && (bestLen == 0 || length < bestLen)) {
			bestCount = c
			bestLen = length
		}
	}
	return bestLen
}
