//go:build linux && 386

package pcap

import (
	"runtime"
	"syscall"
	"unsafe"
)

const sysSetsockoptCall = 14

func attachLinuxBPFFilter(fd int, fprog *syscall.SockFprog) error {
	args := struct {
		fd, level, option uintptr
		fprog             *syscall.SockFprog
		size              uintptr
	}{
		fd:     uintptr(fd),
		level:  uintptr(syscall.SOL_SOCKET),
		option: uintptr(syscall.SO_ATTACH_FILTER),
		fprog:  fprog,
		size:   unsafe.Sizeof(*fprog),
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SOCKETCALL,
		sysSetsockoptCall,
		uintptr(unsafe.Pointer(&args)),
		0,
	)
	runtime.KeepAlive(fprog)
	if errno != 0 {
		return errno
	}
	return nil
}

func getPacketStatistics(fd int, counters *[3]uint32, size *uint32) syscall.Errno {
	const sysGetsockoptCall = 15
	// The socketcall argument vector contains two pointers to kernel outputs.
	args := struct {
		fd, level, option uintptr
		counters          *[3]uint32
		size              *uint32
	}{uintptr(fd), syscall.SOL_PACKET, syscall.PACKET_STATISTICS, counters, size}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, sysGetsockoptCall, uintptr(unsafe.Pointer(&args)), 0)
	return errno
}
