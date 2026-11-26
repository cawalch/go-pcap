// Command dns-transactions pairs observed unicast DNS questions and replies.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

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
	records, err := input.Capture.DNSFromReaderAt(input.File)
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

func reportICMPErrors(out io.Writer, records []pcap.DNSRecord, quoted []pcap.ICMPFlowErrorSummary) error {
	if len(quoted) == 0 {
		return nil
	}
	dnsFlows := make(map[int]bool)
	for _, record := range records {
		if (record.SrcPort == 53 || record.DstPort == 53) && !record.SrcAddr.IsMulticast() && !record.DstAddr.IsMulticast() {
			dnsFlows[record.FlowIndex] = true
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

type key struct {
	flow             int
	client, resolver netip.AddrPort
	id               uint16
	question         pcap.DNSQuestion
}

func report(out io.Writer, records []pcap.DNSRecord) error {
	// An entry holds the index of an outstanding query. After overlapping
	// identical queries, later messages with that key cannot be paired safely.
	const ambiguous = -1
	pending := make(map[key]int)
	type observation struct{ base, outcome string }
	lines := make([]observation, len(records))
	for i, r := range records {
		m := r.Message
		client := netip.AddrPortFrom(r.SrcAddr, r.SrcPort)
		resolver := netip.AddrPortFrom(r.DstAddr, r.DstPort)
		role := "query"
		if m.IsResponse {
			client, resolver = resolver, client
			role = "reply"
		}
		if resolver.Port() != 53 || resolver.Addr().IsMulticast() || client.Addr().IsMulticast() {
			continue
		}
		base := fmt.Sprintf("flow=%d %s_frame=%d id=%04x", r.FlowIndex, role, r.PacketIndex+1, m.TransactionID)
		if m.Opcode != 0 || m.QuestionCount != 1 || len(m.Questions) != 1 || m.Anomalies.Any() {
			lines[i] = observation{base, "unsupported"}
			continue
		}
		q := m.Questions[0]
		base += fmt.Sprintf(" name=%q type=%d class=%d", q.Name, q.Type, q.Class)
		q.Name = asciiLower(q.Name)
		k := key{r.FlowIndex, client, resolver, m.TransactionID, q}
		prior, exists := pending[k]
		if !m.IsResponse {
			if !exists {
				pending[k] = i
				lines[i] = observation{base, "no_reply_observed"}
				continue
			}
			if prior != ambiguous {
				lines[prior].outcome = "ambiguous"
				pending[k] = ambiguous
			}
			lines[i] = observation{base, "ambiguous"}
			continue
		}
		rcode := fmt.Sprintf(" header_rcode=%d", m.RCode)
		switch {
		case !exists:
			lines[i] = observation{base + rcode, "no_query_observed"}
		case prior == ambiguous:
			lines[i] = observation{base + rcode, "ambiguous"}
		default:
			delete(pending, k)
			start := records[prior].TimestampNs
			elapsed := "unknown"
			if start > 0 && r.TimestampNs >= start {
				elapsed = time.Duration(r.TimestampNs - start).String()
			}
			lines[prior].outcome = fmt.Sprintf("reply_frame=%d%s elapsed=%s", r.PacketIndex+1, rcode, elapsed)
		}
	}
	for _, line := range lines {
		if line.base != "" {
			if _, err := fmt.Fprintln(out, line.base, line.outcome); err != nil {
				return err
			}
		}
	}
	return nil
}

func asciiLower(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
