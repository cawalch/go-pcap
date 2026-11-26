package pcap

import "encoding/binary"

const (
	nflogHeaderLen = 4
	nflogTLVLen    = 4
	nflogMaxTLVs   = 256
)

func decodeNFLOG(r *SafeReader, f *Frame) {
	if r.Size() < nflogHeaderLen {
		f.Anomalies.TruncatedLayer = true
		return
	}
	if r.data[1] != 0 {
		return
	}

	// The writer's native order applies to the TLV headers. DecodeFrame
	// receives raw packet bytes without the capture section's byte order.
	start, end, little := nflogPayload(r.data, binary.LittleEndian)
	bigStart, bigEnd, big := nflogPayload(r.data, binary.BigEndian)
	if little == big {
		f.Anomalies.TruncatedLayer = true
		return
	}
	if big {
		start, end = bigStart, bigEnd
	}
	if start == 0 {
		return
	}

	f.pushLayer(LayerNFLOG, 0, start)
	switch r.data[start] >> 4 {
	case 4:
		f.EtherType = EtherTypeIPv4
	case 6:
		f.EtherType = EtherTypeIPv6
	}
	dispatchEtherType(r, start, end, f)
}

func nflogPayload(data []byte, order binary.ByteOrder) (start, end int64, valid bool) {
	const payloadType = 9
	const typeMask = 0x3fff
	for offset, count := nflogHeaderLen, 0; offset < len(data); count++ {
		if count == nflogMaxTLVs || len(data)-offset < nflogTLVLen {
			return 0, 0, false
		}
		length := int(order.Uint16(data[offset : offset+2]))
		padded := (length + 3) &^ 3
		if length < nflogTLVLen || padded > len(data)-offset {
			return 0, 0, false
		}
		if order.Uint16(data[offset+2:offset+nflogTLVLen])&typeMask == payloadType {
			if start != 0 || length == nflogTLVLen {
				return 0, 0, false
			}
			start, end = int64(offset+nflogTLVLen), int64(offset+length)
		}
		offset += padded
	}
	return start, end, true
}
