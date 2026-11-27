// Command dns-transactions pairs observed unicast DNS questions and replies.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/cawalch/go-pcap"
	"github.com/cawalch/go-pcap/examples/internal/captureinput"
)

func main() {
	var opts options
	flag.BoolVar(&opts.icmp, "icmp", false, "report ICMP errors quoting observed DNS flows")
	flag.BoolVar(&opts.tcpZeroWindow, "tcp-zero-window", false, "report zero TCP receive windows on unicast port 53 flows")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dns-transactions [-icmp] [-tcp-zero-window] {capture.pcap[ng][.gz]|-}")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), os.Stdin, os.Stdout, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	icmp          bool
	tcpZeroWindow bool
}

func run(path string, stdin io.Reader, out io.Writer, opts options) error {
	input, err := captureinput.Open(path, stdin)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	records, err := input.Capture.DNSTransactionsFromReaderAt(input.File)
	if err != nil {
		return err
	}
	var quoted []pcap.ICMPFlowErrorSummary
	if opts.icmp {
		quoted, err = input.Capture.ICMPFlowErrorsFromReaderAt(input.File)
		if err != nil {
			return err
		}
	}
	var zeroWindows []pcap.TCPZeroWindowSummary
	if opts.tcpZeroWindow {
		zeroWindows, err = input.Capture.TCPZeroWindowsFromReaderAt(input.File)
		if err != nil {
			return err
		}
	}
	if err := report(out, records); err != nil {
		return err
	}
	if err := reportICMPErrors(out, records, quoted); err != nil {
		return err
	}
	return reportTCPZeroWindows(out, zeroWindows)
}

func reportTCPZeroWindows(out io.Writer, groups []pcap.TCPZeroWindowSummary) error {
	for _, group := range groups {
		src, dst := group.Source, group.Destination
		if (src.Port() != 53 && dst.Port() != 53) || src.Addr().IsMulticast() || dst.Addr().IsMulticast() {
			continue
		}
		_, err := fmt.Fprintf(out, "flow=%d tcp_zero_window_src=%s tcp_zero_window_dst=%s count=%d first_zero_window_frame=%d last_zero_window_frame=%d\n",
			group.FlowIndex, src, dst, group.Count, group.FirstPacketIndex+1, group.LastPacketIndex+1)
		if err != nil {
			return err
		}
	}
	return nil
}

func reportICMPErrors(out io.Writer, records []pcap.DNSTransaction, quoted []pcap.ICMPFlowErrorSummary) error {
	if len(quoted) == 0 {
		return nil
	}
	dnsFlows := make(map[int]bool)
	for _, row := range records {
		for _, record := range []*pcap.DNSRecord{row.Query, row.Reply} {
			if record != nil {
				dnsFlows[record.FlowIndex] = true
			}
		}
	}
	for _, group := range quoted {
		if !dnsFlows[group.FlowIndex] {
			continue
		}
		src := netip.AddrPortFrom(group.Quote.SrcAddr, group.Quote.SrcPort)
		dst := netip.AddrPortFrom(group.Quote.DstAddr, group.Quote.DstPort)
		_, err := fmt.Fprintf(out, "flow=%d icmp_ip=%d icmp_type=%d icmp_code=%d quoted_src=%s quoted_dst=%s count=%d first_error_frame=%d last_error_frame=%d\n",
			group.FlowIndex, group.Quote.IPVersion, group.Type, group.Code, src, dst, group.Count,
			group.FirstPacketIndex+1, group.LastPacketIndex+1)
		if err != nil {
			return err
		}
	}
	return nil
}

func report(out io.Writer, rows []pcap.DNSTransaction) error {
	for _, row := range rows {
		record, role := row.Query, "query"
		if record == nil {
			record, role = row.Reply, "reply"
		}
		m := &record.Message
		line := fmt.Sprintf("flow=%d %s_frame=%d id=%04x", record.FlowIndex, role, record.PacketIndex+1, m.TransactionID)
		if row.Pairing != pcap.DNSUnsupported {
			q := m.Questions[0]
			line += fmt.Sprintf(" name=%q type=%d class=%d", q.Name, q.Type, q.Class)
			if m.IsResponse {
				line += fmt.Sprintf(" header_rcode=%d", m.RCode)
			}
		}
		switch row.Pairing {
		case pcap.DNSPaired:
			elapsed := "unknown"
			if duration, ok := row.Elapsed(); ok {
				elapsed = duration.String()
			}
			line += fmt.Sprintf(" reply_frame=%d header_rcode=%d elapsed=%s", row.Reply.PacketIndex+1, row.Reply.Message.RCode, elapsed)
		case pcap.DNSNoQueryObserved:
			line += " no_query_observed"
		case pcap.DNSNoReplyObserved:
			line += " no_reply_observed"
		case pcap.DNSAmbiguous:
			line += " ambiguous"
		case pcap.DNSUnsupported:
			line += " unsupported"
		}
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}
