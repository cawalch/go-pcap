package pcap

import "encoding/binary"

// DecodeFrameWithChecksums decodes a frame and checks the innermost decoded
// IPv4 header and complete TCP segment or UDP datagram. It flags observed mismatches
// in [Frame.Anomalies]. Transport verification skips IP fragments, possible
// transmit offloads, and routing options that change pseudo-header addresses.
// Truncated packets leave both checksum flags clear.
func DecodeFrameWithChecksums(data []byte, linkType LinkType) (Frame, error) {
	f, err := DecodeFrame(data, linkType)
	if err == nil && !f.Anomalies.TruncatedLayer && !f.Anomalies.IPTotalLengthExceedsFrame &&
		!f.Anomalies.InvalidIPHeaderLength {
		checkFrameChecksums(data, &f)
	}
	return f, err
}

func checkFrameChecksums(data []byte, f *Frame) {
	layers := f.LayerSlices()
	ipIndex := -1
	var transport LayerSpan
	for i, layer := range layers {
		switch layer.Proto {
		case LayerIPv4, LayerIPv6:
			ipIndex = i
			transport = LayerSpan{}
		case LayerTCP, LayerUDP:
			transport = layer
		}
	}
	if ipIndex < 0 {
		return
	}
	network := layers[ipIndex]
	start, headerEnd := int64(network.Offset), int64(network.Offset)+int64(network.Length)
	ip := data[start:headerEnd]
	var end int64
	if network.Proto == LayerIPv4 {
		f.Anomalies.InvalidIPChecksum = !VerifyIPv4HeaderChecksum(ip)
		end = start + int64(binary.BigEndian.Uint16(ip[2:4]))
	} else {
		end = headerEnd + int64(binary.BigEndian.Uint16(ip[4:6]))
	}
	if transport.Proto != LayerTCP && transport.Proto != LayerUDP || f.Anomalies.IPFragment ||
		int64(transport.Offset) < headerEnd || int64(transport.Offset)+int64(transport.Length) > end || end > int64(len(data)) {
		return
	}
	if network.Proto == LayerIPv4 {
		if !checksumIPv4AddressesKnown(ip[20:]) {
			return
		}
	} else if !checksumIPv6AddressesKnown(data, ip[6], layers[ipIndex+1:]) {
		return
	}
	segment := data[transport.Offset:end]
	var valid, offload bool
	if transport.Proto == LayerTCP {
		valid, offload = VerifyTCPChecksum(f.SrcAddr, f.DstAddr, segment)
	} else {
		// A zero UDP length is only defined for jumbograms.
		if binary.BigEndian.Uint16(segment[4:6]) == 0 {
			return
		}
		valid, offload = VerifyUDPChecksum(f.SrcAddr, f.DstAddr, segment)
	}
	f.Anomalies.InvalidL4Checksum = !valid && !offload
}

func checksumIPv4AddressesKnown(options []byte) bool {
	for len(options) != 0 {
		switch options[0] {
		case 0: // End of list.
			return true
		case 1: // NOP.
			options = options[1:]
			continue
		case 131, 137: // Loose and strict source route.
			return false
		}
		if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
			return false
		}
		options = options[options[1]:]
	}
	return true
}

func checksumIPv6AddressesKnown(data []byte, next byte, layers []LayerSpan) bool {
	for _, layer := range layers {
		if layer.Proto != LayerIPv6Ext {
			break
		}
		offset := int64(layer.Offset)
		ext := data[offset : offset+int64(layer.Length)]
		switch next {
		case IPProtoIPv6Route:
			if ext[3] != 0 { // Segments Left.
				return false
			}
		case IPProtoIPv6Opts:
			for options := ext[2:]; len(options) != 0; {
				if options[0] == 0 { // Pad1.
					options = options[1:]
					continue
				}
				// A Mobile IPv6 Home Address option replaces the source.
				if options[0] == 0xc9 || len(options) < 2 || int(options[1])+2 > len(options) {
					return false
				}
				options = options[int(options[1])+2:]
			}
		}
		next = ext[0]
	}
	return true
}
