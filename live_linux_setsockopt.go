//go:build linux && !386

package pcap

import (
	"syscall"
	"unsafe"
)

func attachLinuxBPFFilter(fd int, fprog *syscall.SockFprog) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(fprog)),
		unsafe.Sizeof(*fprog),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func getPacketStatistics(fd int, counters *[3]uint32, size *uint32) syscall.Errno {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		syscall.SOL_PACKET, syscall.PACKET_STATISTICS, uintptr(unsafe.Pointer(counters)),
		uintptr(unsafe.Pointer(size)), 0)
	return errno
}
