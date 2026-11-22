//go:build linux && 386

package pcap

import (
	"syscall"
	"unsafe"
)

const sysSetsockoptCall = 14

func attachLinuxBPFFilter(fd int, fprog *syscall.SockFprog) error {
	args := [5]uintptr{
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(fprog)),
		unsafe.Sizeof(*fprog),
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SOCKETCALL,
		sysSetsockoptCall,
		uintptr(unsafe.Pointer(&args[0])),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func getPacketStatistics(fd int, counters *[2]uint32, size *uint32) syscall.Errno {
	const sysGetsockoptCall = 15
	// The socketcall argument vector contains two pointers to kernel outputs.
	args := struct {
		fd, level, option uintptr
		counters          *[2]uint32
		size              *uint32
	}{uintptr(fd), syscall.SOL_PACKET, syscall.PACKET_STATISTICS, counters, size}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, sysGetsockoptCall, uintptr(unsafe.Pointer(&args)), 0)
	return errno
}
