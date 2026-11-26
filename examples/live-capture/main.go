// Command live-capture writes packets selected by a capture filter to PcapNG.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/cawalch/go-pcap"
)

func main() {
	iface := flag.String("i", "", "capture interface")
	count := flag.Int("c", 1, "number of packets to capture")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: live-capture -i interface [-c count] 'ip and port 53' > capture.pcapng")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *iface == "" || *count < 1 || *count > pcap.MaxPackets || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := capture(*iface, flag.Arg(0), *count, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func capture(iface, expression string, count int, out io.Writer) error {
	devices, err := pcap.LiveDevices()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(devices, func(d pcap.LiveDevice) bool { return d.Name == iface })
	if i < 0 {
		return fmt.Errorf("unknown capture interface %q", iface)
	}
	linkType := devices[i].LinkType
	program, err := pcap.CompileBPFFilter(expression, linkType)
	if err != nil {
		return err
	}
	input, err := pcap.OpenLive(iface, pcap.LiveOptions{BPFFilter: program, Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	if input.LinkType() != linkType {
		return fmt.Errorf("capture datalink changed from %v to %v", linkType, input.LinkType())
	}
	writer, err := pcap.NewPCAPNGWriter(out, pcap.PCAPNGWriterOptions{
		LinkType: linkType, LinkTypeSet: true, SnapLen: input.SnapLen(), InterfaceName: iface,
	})
	if err != nil {
		return err
	}
	for range count {
		record, data, err := input.ReadPacket()
		if err != nil {
			return err
		}
		if err := writer.WritePacket(record, data); err != nil {
			return err
		}
	}
	return nil
}
