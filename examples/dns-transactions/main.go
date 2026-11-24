// Command dns-transactions pairs observed unicast DNS questions and replies.
package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/cawalch/go-pcap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dns-transactions capture.pcap[ng]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	c, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		return err
	}
	records, err := c.DNSFromReaderAt(f)
	if err != nil {
		return err
	}
	return report(out, records)
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
