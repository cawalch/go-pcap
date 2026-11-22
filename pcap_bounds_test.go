package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestNewRejectsInvalidAndNonPCAPInputs(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrNotPCAP) {
		t.Fatalf("New(nil) err = %v, want ErrNotPCAP", err)
	}
	if _, err := New([]byte("MZ\x90\x00")); !errors.Is(err, ErrNotPCAP) || !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("New(PE) err = %v, want ErrNotPCAP + ErrInvalidMagic", err)
	}
	if _, err := NewWithLength([]byte{1, 2, 3, 4}, 2); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("NewWithLength(smaller fileSize) err = %v, want ErrInvalidHeader", err)
	}

	// Classic PCAP with bad version 1.0.
	badVer := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, nil)
	binary.LittleEndian.PutUint16(badVer[4:6], 1)
	if _, err := New(badVer); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("New(bad version) err = %v, want ErrInvalidHeader", err)
	}

	// Classic PCAP with SnapLen exceeding MaxSnapLen.
	badSnap := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, MaxSnapLen+1, nil)
	if _, err := New(badSnap); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("New(oversize snaplen) err = %v, want ErrInvalidHeader", err)
	}
}

func TestClassicPCAPTruncationAndAnomalies(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 80, 1, 1, TCPFlagSYN, []byte("abcd"))
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 32, [][]byte{f1})

	// 1. SnapLen (32) < CaptureLen (len(f1) = 58) triggers CaptureLenExceedsSnapLen.
	cap, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !cap.Anomalies().CaptureLenExceedsSnapLen {
		t.Fatalf("Anomalies() = %+v, want CaptureLenExceedsSnapLen", cap.Anomalies())
	}

	// 2. Truncate 5 bytes off the end of the packet payload.
	truncated := raw[:len(raw)-5]
	truncCap, err := New(truncated)
	if err != nil {
		t.Fatalf("New(truncated) error = %v", err)
	}
	if !truncCap.InputTruncated() || !truncCap.Anomalies().TruncatedPacketBlock {
		t.Fatalf("truncated Capture: InputTruncated=%v, Anomalies=%+v", truncCap.InputTruncated(), truncCap.Anomalies())
	}
	extent, ok := truncCap.DeclaredExtent()
	if !ok || extent != uint64(len(raw)) {
		t.Fatalf("DeclaredExtent() = (%d, %v), want (%d, true)", extent, ok, len(raw))
	}
	if truncCap.PacketCount != 0 {
		t.Fatalf("PacketCount = %d, want 0 complete packets", truncCap.PacketCount)
	}

	// 3. Append 6 trailing garbage bytes (< 16-byte packet header).
	trailing := append(bytes.Clone(raw), 1, 2, 3, 4, 5, 6)
	trailCap, err := New(trailing)
	if err != nil {
		t.Fatalf("New(trailing) error = %v", err)
	}
	if !trailCap.InputTruncated() || !trailCap.Anomalies().TrailingBytes {
		t.Fatalf("trailing Capture: InputTruncated=%v, Anomalies=%+v", trailCap.InputTruncated(), trailCap.Anomalies())
	}
}

func TestPCAPNGBoundsAndMalformedBlocks(t *testing.T) {
	f1 := buildEthernetIPv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 80, 1, 1, TCPFlagSYN, nil)
	valid := buildPCAPNGFixture(binary.LittleEndian, []byte("SECRET"), [][]byte{f1})

	// 1. Corrupt trailing block length in the first SHB.
	badTrail := bytes.Clone(valid)
	shbLen := binary.LittleEndian.Uint32(badTrail[4:8])
	binary.LittleEndian.PutUint32(badTrail[shbLen-4:shbLen], shbLen+4)
	if _, err := New(badTrail); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("New(mismatched trailing block length) err = %v, want ErrInvalidBlock", err)
	}

	// 2. Block length smaller than minimum 12 bytes.
	smallBlock := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(smallBlock[4:8], 8)
	if _, err := New(smallBlock); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("New(blockLen < 12) err = %v, want ErrInvalidBlock", err)
	}

	// 3. Truncated trailing EPB block marks InputTruncated without failing New.
	truncNG := valid[:len(valid)-10]
	cap, err := New(truncNG)
	if err != nil {
		t.Fatalf("New(truncated EPB) err = %v", err)
	}
	if !cap.InputTruncated() || !cap.Anomalies().TruncatedPacketBlock {
		t.Fatalf("truncated PCAPNG: InputTruncated=%v, Anomalies=%+v", cap.InputTruncated(), cap.Anomalies())
	}

	// 4. EPB referencing missing interface ID returns ErrInvalidPacket.
	var badEPBBuf bytes.Buffer
	// Copy only the SHB from valid.
	badEPBBuf.Write(valid[:shbLen])
	var epbBody [20]byte
	binary.LittleEndian.PutUint32(epbBody[0:4], 0) // Interface 0 does not exist yet
	appendPCAPNGBlock(&badEPBBuf, binary.LittleEndian, BlockTypeEnhancedPacket, epbBody[:])
	if _, err := New(badEPBBuf.Bytes()); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("New(EPB without IDB) err = %v, want ErrInvalidPacket", err)
	}
}
