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
