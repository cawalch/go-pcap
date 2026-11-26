//go:build linux

package pcap

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestLiveLinuxLinkDump(t *testing.T) {
	const flags = syscall.IFF_UP | syscall.IFF_RUNNING | syscall.IFF_LOOPBACK | syscall.IFF_MULTICAST
	loopback := linuxLinkFixture("lo", 5, 772, flags, 65536)
	can := linuxLinkFixture("can0", 7, 280, syscall.IFF_NOARP, 16)
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}}
	links, err := parseLinuxLiveLinks([]syscall.NetlinkMessage{loopback, can, done})
	if err != nil || len(links) != 2 {
		t.Fatalf("links = %v, %v", links, err)
	}
	want := linuxLiveLink{
		device:       LiveDevice{Name: "lo", Index: 5, MTU: 65536, Flags: net.FlagUp | net.FlagRunning | net.FlagLoopback | net.FlagMulticast},
		hardwareType: 772,
	}
	if links[0] != want {
		t.Fatalf("loopback = %+v, want %+v", links[0], want)
	}
	if links[1].device != (LiveDevice{Name: "can0", Index: 7, MTU: 16}) || links[1].hardwareType != 280 {
		t.Fatalf("unexpected CAN link: %+v", links[1])
	}
	if kind, err := linuxARPHRDLinkType(links[1].hardwareType); kind != LinkTypeUnknown || !errors.Is(err, ErrUnsupportedDataLink) {
		t.Fatalf("CAN mapping returned %d, %v", kind, err)
	}
}

func TestLiveLinuxLinkDumpMalformed(t *testing.T) {
	loopback := linuxLinkFixture("lo", 5, 772, syscall.IFF_LOOPBACK, 65536)
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}}
	for _, tc := range []struct {
		name string
		msg  syscall.NetlinkMessage
	}{
		{"short header", syscall.NetlinkMessage{Header: loopback.Header, Data: loopback.Data[:8]}},
		{"missing name", syscall.NetlinkMessage{Header: loopback.Header, Data: loopback.Data[:syscall.SizeofIfInfomsg]}},
		{"unaligned trailing attribute", syscall.NetlinkMessage{Header: loopback.Header, Data: loopback.Data[:len(loopback.Data)-1]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if links, err := parseLinuxLiveLinks([]syscall.NetlinkMessage{loopback, tc.msg, done}); links != nil || !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("links = %v, %v", links, err)
			}
		})
	}
	done.Header.Flags = 0x10 // NLM_F_DUMP_INTR.
	if links, err := parseLinuxLiveLinks([]syscall.NetlinkMessage{loopback, done}); links != nil || !errors.Is(err, syscall.EINTR) {
		t.Fatalf("interrupted dump returned %v, %v", links, err)
	}
	done.Header.Flags = 0
	status := -int32(syscall.ENOBUFS)
	done.Data = binary.NativeEndian.AppendUint32(nil, uint32(status))
	if links, err := parseLinuxLiveLinks([]syscall.NetlinkMessage{loopback, done}); links != nil || !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("failed dump returned %v, %v", links, err)
	}
}

func linuxLinkFixture(name string, index uint32, hardware uint16, flags, mtu uint32) syscall.NetlinkMessage {
	value := append([]byte(name), 0)
	nameAttrLen := syscall.SizeofRtAttr + len(value)
	nameAttrAligned := (nameAttrLen + 3) &^ 3
	wire := make([]byte, syscall.SizeofIfInfomsg+nameAttrAligned+8)
	ne := binary.NativeEndian
	ne.PutUint16(wire[2:4], hardware)
	ne.PutUint32(wire[4:8], index)
	ne.PutUint32(wire[8:12], flags)
	nameAttr := wire[syscall.SizeofIfInfomsg:]
	ne.PutUint16(nameAttr[:2], uint16(nameAttrLen))
	ne.PutUint16(nameAttr[2:4], syscall.IFLA_IFNAME)
	copy(nameAttr[4:], value)
	mtuAttr := nameAttr[nameAttrAligned:]
	ne.PutUint16(mtuAttr[:2], 8)
	ne.PutUint16(mtuAttr[2:4], syscall.IFLA_MTU)
	ne.PutUint32(mtuAttr[4:8], mtu)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWLINK}, Data: wire}
}
