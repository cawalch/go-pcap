//go:build windows

package pcap

import (
	"bytes"
	"net"
	"syscall"
	"testing"
	"time"
)

func openLoopbackUDPSocket(t *testing.T) (syscall.Handle, int) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("Socket() error = %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = syscall.Closesocket(fd)
		t.Fatalf("Bind() error = %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		_ = syscall.Closesocket(fd)
		t.Fatalf("Getsockname() error = %v", err)
	}
	return fd, sa.(*syscall.SockaddrInet4).Port
}

func TestLiveCaptureWindowsReadAndConcurrentClose(t *testing.T) {
	// 1. Verify WSARecv path receives datagrams and respects EvalBPF snaplen.
	fd, port := openLoopbackUDPSocket(t)
	lc := &LiveCapture{
		fd:       fd,
		linkType: LinkTypeIPv4,
		snapLen:  1500,
		filter:   []BPFInstruction{{Code: bpfClassRET | bpfSrcK, K: 4}},
		buf:      make([]byte, 1500),
	}
	defer func() { _ = lc.Close() }()

	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
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
	fd2, _ := openLoopbackUDPSocket(t)
	lc2 := &LiveCapture{
		fd:       fd2,
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
