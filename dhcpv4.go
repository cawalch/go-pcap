package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
)

// DHCPv4MessageType is the value of DHCP option 53.
type DHCPv4MessageType uint8

// Address-assignment messages recognized by [Capture.DHCPv4].
const (
	DHCPv4Discover DHCPv4MessageType = 1
	DHCPv4Offer    DHCPv4MessageType = 2
	DHCPv4Request  DHCPv4MessageType = 3
	DHCPv4ACK      DHCPv4MessageType = 5
	DHCPv4NAK      DHCPv4MessageType = 6
)

const (
	maxDHCPv4Bytes   = 4096
	maxDHCPv4Options = 128
	maxDHCPv4Records = 4096
)

// ErrDHCPv4Limit indicates that a capture exceeds the DHCPv4 observation or scan byte limit.
var ErrDHCPv4Limit = errors.New("DHCPv4 scan exceeds limit")

// DHCPv4Record describes one observed DHCPv4 datagram. ClientAddr, YourAddr,
// NextServerAddr and RelayAddr come from the fixed BOOTP header. A zero header
// address is absent. YourAddr is the offered address in an Offer and the
// assigned address in an allocation ACK. RequestedAddr and ServerIdentifier
// come from options 50 and 54. Missing addresses have an invalid netip.Addr.
type DHCPv4Record struct {
	PacketIndex        int
	TimestampNs        int64
	InterfaceID        uint32
	MessageType        DHCPv4MessageType
	TransactionID      uint32
	HardwareType       uint8
	ClientHardwareAddr net.HardwareAddr
	ClientIdentifier   []byte
	ClientAddr         netip.Addr
	YourAddr           netip.Addr
	NextServerAddr     netip.Addr
	RelayAddr          netip.Addr
	RequestedAddr      netip.Addr
	ServerIdentifier   netip.Addr
	LeaseSeconds       uint32
	HasLease           bool
	Hostname           string
	HasHostname        bool
}

// DHCPv4 returns address-assignment observations in packet order. It skips
// malformed, fragmented and oversized datagrams. It returns [ErrDHCPv4Limit]
// above 4096 records or 64 MiB of candidate datagrams.
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) DHCPv4(data []byte) ([]DHCPv4Record, error) {
	return scanDHCPv4(ipFrameSource{capture: c, data: data})
}

// DHCPv4FromReaderAt reads the observations described by [Capture.DHCPv4]
// under the additional [MaxReaderAtScanBytes] read budget.
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) DHCPv4FromReaderAt(r io.ReaderAt) ([]DHCPv4Record, error) {
	return scanDHCPv4(ipFrameSource{capture: c, reader: r, needsPayload: func(f Frame, _ []byte) bool { return isDHCPv4(&f) }})
}

func isDHCPv4(f *Frame) bool {
	return f.IPVersion == 4 && f.IPProtocol == IPProtoUDP && !f.Anomalies.IPFragment &&
		!f.Anomalies.TruncatedLayer && !f.Anomalies.IPTotalLengthExceedsFrame &&
		f.PayloadLength >= 240 && f.PayloadLength <= maxDHCPv4Bytes &&
		(f.SrcPort == 67 && (f.DstPort == 68 || f.DstPort == 67) || f.SrcPort == 68 && f.DstPort == 67)
}

func scanDHCPv4(source ipFrameSource) ([]DHCPv4Record, error) {
	var records []DHCPv4Record
	remaining := MaxReaderAtScanBytes
	err := source.walk(func(pkt PacketRecord, f Frame, data []byte) error {
		if !isDHCPv4(&f) {
			return nil
		}
		remaining -= len(data)
		if remaining < 0 {
			return ErrDHCPv4Limit
		}
		rec, ok := parseDHCPv4(data)
		if !ok {
			return nil
		}
		if len(records) == maxDHCPv4Records {
			return ErrDHCPv4Limit
		}
		rec.PacketIndex, rec.TimestampNs, rec.InterfaceID = pkt.Index, pkt.TimestampNs, pkt.InterfaceID
		records = append(records, rec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func parseDHCPv4(data []byte) (DHCPv4Record, bool) {
	if len(data) < 240 || len(data) > maxDHCPv4Bytes || binary.BigEndian.Uint32(data[236:240]) != 0x63825363 {
		return DHCPv4Record{}, false
	}
	op, htype, hlen := data[0], data[1], int(data[2])
	if (op != 1 && op != 2) || hlen > 16 || (hlen > 0 && (htype == 0 || htype == 1 && hlen != 6)) {
		return DHCPv4Record{}, false
	}

	var opts dhcpv4Options
	if !opts.read(data[240:], true) ||
		opts.overload&1 != 0 && !opts.read(data[108:236], false) ||
		opts.overload&2 != 0 && !opts.read(data[44:108], false) {
		return DHCPv4Record{}, false
	}
	r := opts.record
	switch r.MessageType {
	case DHCPv4Discover, DHCPv4Request:
		if op != 1 {
			return DHCPv4Record{}, false
		}
	case DHCPv4Offer, DHCPv4ACK, DHCPv4NAK:
		if op != 2 {
			return DHCPv4Record{}, false
		}
	default:
		return DHCPv4Record{}, false
	}
	addr := func(b []byte) netip.Addr {
		a := netip.AddrFrom4([4]byte(b))
		if a.IsUnspecified() {
			return netip.Addr{}
		}
		return a
	}
	r.ClientAddr, r.YourAddr = addr(data[12:16]), addr(data[16:20])
	r.NextServerAddr, r.RelayAddr = addr(data[20:24]), addr(data[24:28])
	r.TransactionID = binary.BigEndian.Uint32(data[4:8])
	r.HardwareType = htype
	if hw := data[28 : 28+hlen]; len(bytes.Trim(hw, "\x00")) > 0 {
		r.ClientHardwareAddr = bytes.Clone(hw)
	}
	r.ClientIdentifier = bytes.Clone(opts.clientID)
	r.Hostname = string(opts.hostname)
	return r, true
}

type dhcpv4Options struct {
	record             DHCPv4Record
	clientID, hostname []byte
	overload           byte
	count              int
}

func (o *dhcpv4Options) read(data []byte, main bool) bool {
	for len(data) > 0 {
		code := data[0]
		data = data[1:]
		switch code {
		case 0:
			continue
		case 255:
			return true
		}
		o.count++
		if o.count > maxDHCPv4Options || len(data) < 1 || int(data[0]) > len(data)-1 {
			return false
		}
		n := int(data[0])
		v := data[1 : 1+n]
		data = data[1+n:]
		switch code {
		case 12:
			if !o.record.HasHostname {
				o.hostname = v
				o.record.HasHostname = true
			}
		case 50, 54:
			if n != 4 {
				return false
			}
			a := &o.record.RequestedAddr
			if code == 54 {
				a = &o.record.ServerIdentifier
			}
			if !a.IsValid() {
				*a = netip.AddrFrom4([4]byte(v))
			}
		case 51:
			if n != 4 {
				return false
			}
			if !o.record.HasLease {
				o.record.LeaseSeconds = binary.BigEndian.Uint32(v)
				o.record.HasLease = true
			}
		case 52:
			if !main || n != 1 || v[0] < 1 || v[0] > 3 {
				return false
			}
			if o.overload == 0 {
				o.overload = v[0]
			}
		case 53:
			if n != 1 || v[0] == 0 {
				return false
			}
			if o.record.MessageType == 0 {
				o.record.MessageType = DHCPv4MessageType(v[0])
			}
		case 61:
			if n < 2 {
				return false
			}
			if o.clientID == nil {
				o.clientID = v
			}
		}
	}
	return false // A field without an End marker may have been truncated.
}
