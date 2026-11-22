package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestParseBPFBufferBatch(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1111, 80, 1, 0, TCPFlagSYN, []byte("a"))
	f2 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 80, 1111, 2, 2, TCPFlagSYN|TCPFlagACK, []byte("bc"))

	var bpfBuf bytes.Buffer
	for i, frame := range [][]byte{f1, f2} {
		var hdr [18]byte
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(hdr[4:8], 500)
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(frame)))
		binary.LittleEndian.PutUint16(hdr[16:18], 18)
		bpfBuf.Write(hdr[:])
		bpfBuf.Write(frame)
		aligned := BPFWordAlign(18 + len(frame))
		if pad := aligned - (18 + len(frame)); pad > 0 {
			bpfBuf.Write(make([]byte, pad))
		}
	}

	records, err := ParseBPFBuffer(bpfBuf.Bytes(), LinkTypeEthernet)
	if err != nil || len(records) != 2 {
		t.Fatalf("ParseBPFBuffer() = (%d, %v), want 2", len(records), err)
	}
	raw := bpfBuf.Bytes()
	if !bytes.Equal(raw[records[0].PayloadOffset:records[0].PayloadOffset+records[0].PayloadLength], f1) {
		t.Fatal("BPF record 0 payload mismatch")
	}
	if !bytes.Equal(raw[records[1].PayloadOffset:records[1].PayloadOffset+records[1].PayloadLength], f2) {
		t.Fatal("BPF record 1 payload mismatch")
	}
}

func TestLiveCaptureBounds(t *testing.T) {
	var badBPF [18]byte
	badBPF[16] = 10
	if _, err := ParseBPFBuffer(badBPF[:], LinkTypeEthernet); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("ParseBPFBuffer(hdrLen < 18) err = %v, want ErrInvalidPacket", err)
	}
	if _, err := OpenLive("", LiveOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("OpenLive(\"\") err = %v, want ErrInvalidHeader", err)
	}
	if _, err := OpenLive("lo0", LiveOptions{SnapLen: MaxSnapLen + 1}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("OpenLive(oversize snaplen) err = %v, want ErrInvalidHeader", err)
	}
}

func TestBPFFilterBuildersAndEvalBPF(t *testing.T) {
	tcp443 := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 20}, 51234, 443, 1, 0, TCPFlagSYN, nil)
	udp53 := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 10}, [4]byte{8, 8, 8, 8}, 51234, 53, []byte("dns"))

	// 1. BPFFilterTCPPort(443)
	progTCP443 := BPFFilterTCPPort(443)
	if snap, ok := EvalBPF(progTCP443, tcp443); !ok || snap == 0 {
		t.Fatalf("EvalBPF(BPFFilterTCPPort(443), tcp443) = (%d, %v), want accept", snap, ok)
	}
	if _, ok := EvalBPF(progTCP443, udp53); ok {
		t.Fatal("EvalBPF(BPFFilterTCPPort(443), udp53) accepted UDP packet")
	}

	// 2. BPFFilterUDPPort(53)
	progUDP53 := BPFFilterUDPPort(53)
	if _, ok := EvalBPF(progUDP53, udp53); !ok {
		t.Fatal("EvalBPF(BPFFilterUDPPort(53), udp53) rejected UDP port 53")
	}
	if _, ok := EvalBPF(progUDP53, tcp443); ok {
		t.Fatal("EvalBPF(BPFFilterUDPPort(53), tcp443) accepted TCP packet")
	}

	// 3. BPFFilterIPProtocol
	if _, ok := EvalBPF(BPFFilterIPProtocol(IPProtoTCP), tcp443); !ok {
		t.Fatal("BPFFilterIPProtocol(TCP) rejected TCP frame")
	}
	if _, ok := EvalBPF(BPFFilterIPProtocol(IPProtoUDP), tcp443); ok {
		t.Fatal("BPFFilterIPProtocol(UDP) accepted TCP frame")
	}

	// 4. BPFFilterIPv4Host
	hostFilter := BPFFilterIPv4Host(netip.MustParseAddr("198.51.100.20"))
	if _, ok := EvalBPF(hostFilter, tcp443); !ok {
		t.Fatal("BPFFilterIPv4Host rejected matching dst IPv4")
	}
	if _, ok := EvalBPF(hostFilter, udp53); ok {
		t.Fatal("BPFFilterIPv4Host accepted non-matching IPv4")
	}

	// 5. EvalBPF safety: division by zero and out-of-bounds packet load return (0, false).
	divZero := []BPFInstruction{
		{Code: bpfClassALU | 0x30 | bpfSrcK, K: 0},
		{Code: bpfClassRET | bpfSrcK, K: 65535},
	}
	if _, ok := EvalBPF(divZero, tcp443); ok {
		t.Fatal("EvalBPF(divZero) should fail safely")
	}
}
