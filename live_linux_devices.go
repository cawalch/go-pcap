//go:build linux

package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"syscall"
)

type linuxLiveLink struct {
	device       LiveDevice
	hardwareType uint16
}

func platformLiveDevices() ([]LiveDevice, error) {
	links, err := readLinuxLiveLinks()
	if err != nil {
		return nil, err
	}
	devices := make([]LiveDevice, 0, len(links))
	for _, link := range links {
		d := link.device
		kind, err := linuxARPHRDLinkType(link.hardwareType)
		d.LinkType, d.HasLinkType = kind, err == nil
		devices = append(devices, d)
	}
	return devices, nil
}

func readLinuxLiveLinks() ([]linuxLiveLink, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	return parseLinuxLiveLinks(msgs)
}

func parseLinuxLiveLinks(msgs []syscall.NetlinkMessage) ([]linuxLiveLink, error) {
	const dumpInterrupted = 0x10 // NLM_F_DUMP_INTR from linux/netlink.h.
	links := make([]linuxLiveLink, 0, len(msgs))
	for _, m := range msgs {
		if m.Header.Flags&dumpInterrupted != 0 {
			return nil, os.NewSyscallError("rtnetlink link dump", syscall.EINTR)
		}
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			if len(m.Data) >= 4 {
				status := int32(binary.NativeEndian.Uint32(m.Data))
				if status < 0 {
					return nil, os.NewSyscallError("rtnetlink link dump", syscall.Errno(-int64(status)))
				}
			}
			return links, nil
		case syscall.RTM_NEWLINK:
			link, err := parseLinuxLiveLink(&m)
			if err != nil {
				return nil, err
			}
			links = append(links, link)
		}
	}
	return nil, os.NewSyscallError("rtnetlink link dump", syscall.EINVAL)
}

func parseLinuxLiveLink(m *syscall.NetlinkMessage) (linuxLiveLink, error) {
	// Attributes are aligned to four bytes. Validate the envelope before
	// passing it to ParseNetlinkRouteAttr, which assumes the attribute padding.
	if len(m.Data) < syscall.SizeofIfInfomsg || len(m.Data)%syscall.RTA_ALIGNTO != 0 {
		return linuxLiveLink{}, os.NewSyscallError("rtnetlink link record", syscall.EINVAL)
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return linuxLiveLink{}, os.NewSyscallError("parsenetlinkrouteattr", err)
	}
	// Linux ifinfomsg stores type, index, and flags in native byte order.
	link := linuxLiveLink{
		device: LiveDevice{
			Index: int(int32(binary.NativeEndian.Uint32(m.Data[4:8]))),
			Flags: linuxInterfaceFlags(binary.NativeEndian.Uint32(m.Data[8:12])),
		},
		hardwareType: binary.NativeEndian.Uint16(m.Data[2:4]),
	}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case syscall.IFLA_IFNAME:
			if end := bytes.IndexByte(attr.Value, 0); end > 0 {
				link.device.Name = string(attr.Value[:end])
			}
		case syscall.IFLA_MTU:
			if len(attr.Value) == 4 {
				mtu := binary.NativeEndian.Uint32(attr.Value)
				if mtu <= math.MaxInt32 {
					link.device.MTU = int(mtu)
				}
			}
		}
	}
	if link.device.Index <= 0 || link.device.Name == "" {
		return linuxLiveLink{}, os.NewSyscallError("rtnetlink link record", syscall.EINVAL)
	}
	return link, nil
}

func linuxInterfaceFlags(raw uint32) net.Flags {
	var out net.Flags
	for _, flag := range [...]struct {
		mask uint32
		flag net.Flags
	}{
		{syscall.IFF_UP, net.FlagUp},
		{syscall.IFF_RUNNING, net.FlagRunning},
		{syscall.IFF_BROADCAST, net.FlagBroadcast},
		{syscall.IFF_LOOPBACK, net.FlagLoopback},
		{syscall.IFF_POINTOPOINT, net.FlagPointToPoint},
		{syscall.IFF_MULTICAST, net.FlagMulticast},
	} {
		if raw&flag.mask != 0 {
			out |= flag.flag
		}
	}
	return out
}

func linuxARPHRDLinkType(hardwareType uint16) (LinkType, error) {
	const (
		arphrdEther    = 1
		arphrdMetricom = 23
		arphrdLoopback = 772
	)
	switch hardwareType {
	case arphrdEther, arphrdLoopback, arphrdMetricom:
		return LinkTypeEthernet, nil
	default:
		return LinkTypeUnknown, fmt.Errorf("%w: ARPHRD type %d", ErrUnsupportedDataLink, hardwareType)
	}
}
