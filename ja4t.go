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
