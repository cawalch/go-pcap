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
