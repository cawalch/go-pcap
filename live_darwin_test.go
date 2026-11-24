//go:build darwin

package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDarwinBPFLinkType(t *testing.T) {
	for native, want := range map[uint32]LinkType{
		syscall.DLT_NULL:             LinkTypeNull,
		syscall.DLT_EN10MB:           LinkTypeEthernet,
		syscall.DLT_RAW:              LinkTypeRaw,
		syscall.DLT_IEEE802_11:       LinkTypeIEEE80211,
		syscall.DLT_LINUX_SLL:        LinkTypeLinuxSLL,
		syscall.DLT_IEEE802_11_RADIO: LinkTypeIEEE80211RadioTap,
		228:                          LinkTypeIPv4,
		229:                          LinkTypeIPv6,
		276:                          LinkTypeLinuxSLL2,
	} {
		if got, err := darwinBPFLinkType(native); err != nil || got != want {
			t.Errorf("Darwin DLT %d = (%d, %v), want %d", native, got, err, want)
		}
	}
	for _, native := range []uint32{101, 0x10001} {
		if got, err := darwinBPFLinkType(native); err == nil || got != LinkTypeUnknown {
			t.Errorf("unmapped Darwin DLT %d = (%d, %v)", native, got, err)
		}
	}
}

func TestLiveDarwinRawLinkType(t *testing.T) {
	linkType, err := darwinBPFLinkType(syscall.DLT_RAW)
	if err != nil {
		t.Fatal(err)
	}
	frame := buildEthernetIPv4UDPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 4321, []byte("raw IP"))[14:]
	const hdrLen = 18
	batch := make([]byte, BPFWordAlign(hdrLen+len(frame)))
	binary.LittleEndian.PutUint32(batch[0:4], 1_900_000_000)
	binary.LittleEndian.PutUint32(batch[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(batch[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint16(batch[16:18], hdrLen)
	copy(batch[hdrLen:], frame)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	lc := &LiveCapture{file: r, linkType: linkType, snapLen: DefaultLiveSnapLen, buf: make([]byte, len(batch))}
	defer func() { _ = lc.Close() }()
	if _, err := w.Write(batch); err != nil {
		t.Fatal(err)
	}
	rec, packet, err := lc.ReadPacket()
	if err != nil || rec.LinkType != LinkTypeRaw || !bytes.Equal(packet, frame) {
		t.Fatalf("raw live record = (%+v, %x, %v)", rec, packet, err)
	}
	decoded, err := DecodeFrame(packet, rec.LinkType)
	if err != nil || decoded.IPVersion != 4 || decoded.DstPort != 4321 {
		t.Fatalf("decode raw live record = (%+v, %v)", decoded, err)
	}
	var out bytes.Buffer
	writer, err := NewPCAPWriter(&out, lc.LinkType(), lc.SnapLen())
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacketWithOriginalLen(rec.TimestampNs, packet, rec.OriginalLen); err != nil {
		t.Fatal(err)
	}
	if fileType := binary.LittleEndian.Uint32(out.Bytes()[20:24]); fileType != 101 {
		t.Fatalf("classic PCAP link type = %d, want 101", fileType)
	}
}

func TestLiveCaptureConcurrentCloseUnblocksReadPacket(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(pair[1]) }()
	if err := syscall.SetNonblock(pair[0], true); err != nil {
		_ = syscall.Close(pair[0])
		t.Fatal(err)
	}
	r := os.NewFile(uintptr(pair[0]), "capture-socket")

	lc := &LiveCapture{
		file:     r,
		linkType: LinkTypeEthernet,
		snapLen:  DefaultLiveSnapLen,
		buf:      make([]byte, 4096),
	}

	done := make(chan error, 1)
	go func() {
		_, _, readErr := lc.ReadPacket()
		done <- readErr
	}()

	time.Sleep(10 * time.Millisecond)
	if err := lc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// Second Close is idempotent.
	if err := lc.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	// Stats after Close must return ErrInvalidHeader.
	if _, err := lc.Stats(); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("Stats() after Close() error = %v, want ErrInvalidHeader", err)
	}

	select {
	case readErr := <-done:
		if readErr == nil {
			t.Fatal("ReadPacket() succeeded after concurrent Close(), want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket() remained blocked after concurrent Close()")
	}
}
