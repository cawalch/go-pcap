package pcap

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDecodeFrameBoundsAndAnomalies(t *testing.T) {
	// 1. Unsupported link type.
	if _, err := DecodeFrame([]byte{1, 2, 3, 4}, LinkType(9999)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodeFrame(unsupported linkType) err = %v, want ErrInvalidFrame", err)
	}

	// 2. Ethernet header shorter than 14 bytes.
	if _, err := DecodeFrame(make([]byte, 13), LinkTypeEthernet); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("DecodeFrame(short Ethernet) err = %v, want ErrInvalidFrame", err)
	}

	// 3. Excessive nested VLAN tags (> MaxVLANTags).
	vlanBomb := make([]byte, 14+4*(MaxVLANTags+1)+20)
	binary.BigEndian.PutUint16(vlanBomb[12:14], EtherTypeVLAN)
	for i := range MaxVLANTags + 1 {
		off := 14 + i*4
		binary.BigEndian.PutUint16(vlanBomb[off+2:off+4], EtherTypeVLAN)
	}
	fVLAN, err := DecodeFrame(vlanBomb, LinkTypeEthernet)
	if err != nil || !fVLAN.Anomalies.VLANDepthExceeded {
		t.Fatalf("DecodeFrame(VLAN bomb) = (%+v, %v), want VLANDepthExceeded", fVLAN.Anomalies, err)
	}

	// 4. IPv4 header with invalid IHL (< 5).
	badIHL := make([]byte, 14+20)
	binary.BigEndian.PutUint16(badIHL[12:14], EtherTypeIPv4)
	badIHL[14] = 0x43 // IHL = 3 (12 bytes < 20)
	fIHL, err := DecodeFrame(badIHL, LinkTypeEthernet)
	if err != nil || !fIHL.Anomalies.InvalidIPHeaderLength {
		t.Fatalf("DecodeFrame(bad IHL) = (%+v, %v), want InvalidIPHeaderLength", fIHL.Anomalies, err)
	}

	// 5. IPv4 fragment skips L4 port decoding and sets IPFragment anomaly.
	fragFrame := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 1, TCPFlagSYN, []byte("frag"))
	binary.BigEndian.PutUint16(fragFrame[14+6:14+8], 0x2001) // MF=1, offset=1
	fFrag, err := DecodeFrame(fragFrame, LinkTypeEthernet)
	if err != nil || !fFrag.Anomalies.IPFragment || fFrag.SrcPort != 0 {
		t.Fatalf("DecodeFrame(IPv4 fragment) = (%+v, srcPort=%d, %v)", fFrag.Anomalies, fFrag.SrcPort, err)
	}

	// 6. TCP header with invalid DataOffset (< 5).
	badTCP := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1234, 80, 1, 1, TCPFlagSYN, nil)
	badTCP[34+12] = 3 << 4 // DataOffset = 12 bytes < 20
	fTCP, err := DecodeFrame(badTCP, LinkTypeEthernet)
	if err != nil || !fTCP.Anomalies.InvalidTCPDataOffset {
		t.Fatalf("DecodeFrame(bad TCP DataOffset) = (%+v, %v), want InvalidTCPDataOffset", fTCP.Anomalies, err)
	}
}
