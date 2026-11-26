//go:build !linux

package pcap

import "net"

func platformLiveDevices() ([]LiveDevice, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	devices := make([]LiveDevice, 0, len(ifaces))
	for _, iface := range ifaces {
		devices = append(devices, LiveDevice{
			Name: iface.Name, Index: iface.Index, MTU: iface.MTU, Flags: iface.Flags, LinkType: LinkTypeUnknown,
		})
	}
	if err := liveDeviceLinkTypes(devices); err != nil {
		return nil, err
	}
	return devices, nil
}
