package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
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
