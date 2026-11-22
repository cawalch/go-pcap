//go:build windows

package pcap

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func openLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestLiveCaptureWindowsReadAndConcurrentClose(t *testing.T) {
	// Verify datagram reads respect the BPF snapshot length.
	conn := openLoopbackUDP(t)
	lc := &LiveCapture{
		conn:     conn,
		linkType: LinkTypeIPv4,
		snapLen:  1500,
		filter:   []BPFInstruction{{Code: bpfClassRET | bpfSrcK, K: 4}},
		buf:      make([]byte, 1500),
	}
	defer func() { _ = lc.Close() }()

	sender, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := sender.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	rec, payload, err := lc.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if rec.CaptureLen != 4 || rec.OriginalLen != 6 || !bytes.Equal(payload, []byte("abcd")) {
		t.Fatalf("ReadPacket() = (cap=%d orig=%d payload=%q), want (4, 6, \"abcd\")", rec.CaptureLen, rec.OriginalLen, payload)
	}

	// 2. Verify concurrent Close cancels a blocked ReadPacket cleanly.
	conn2 := openLoopbackUDP(t)
	lc2 := &LiveCapture{
		conn:     conn2,
		linkType: LinkTypeIPv4,
		snapLen:  1500,
		buf:      make([]byte, 1500),
	}
	done := make(chan error, 1)
	go func() {
		_, _, readErr := lc2.ReadPacket()
		done <- readErr
	}()

	time.Sleep(10 * time.Millisecond)
	if err := lc2.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := lc2.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
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

// pausedReadConn delays submission until Close has returned.
type pausedReadConn struct {
	net.Conn
	entered chan struct{}
	resume  chan struct{}
}

func (c *pausedReadConn) Read(b []byte) (int, error) {
	close(c.entered)
	<-c.resume
	return c.Conn.Read(b)
}

func TestLiveCaptureWindowsCloseBeforeReceive(t *testing.T) {
	conn := &pausedReadConn{Conn: openLoopbackUDP(t), entered: make(chan struct{}), resume: make(chan struct{})}
	lc := &LiveCapture{conn: conn, buf: make([]byte, 64)}
	done := make(chan error, 1)
	go func() {
		_, _, err := lc.ReadPacket()
		done <- err
	}()
	<-conn.entered
	err := lc.Close()
	close(conn.resume)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("read after close: got %v, want ErrInvalidHeader", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read blocked after close")
	}
}
