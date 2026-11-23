# go-pcap

go-pcap is a Go library for answering questions about captured network traffic.
Read a PCAP or PcapNG file to find which endpoints exchanged packets, which
names they queried, or which TLS settings they offered. You can also capture
packets from a local interface and write captures for another tool to inspect.

The library uses the Go standard library, builds without cgo or libpcap, and
requires Go 1.26 or later. The API is experimental and can change before v1.0.
[Release guide](docs/releases.md) · [Changelog](CHANGELOG.md)

## Start with a question

| Use case | What to inspect |
| --- | --- |
| Match a connection in a capture to a network sensor log | Group packets from both directions with `Flows`. For IPv4 or IPv6 TCP and UDP, `flow.CommunityID(seed)` produces a join key for tools using the same seed. Compare timestamps when a host reuses a port. [Flow summaries](docs/parsing.md#aggregate-5-tuple-flows) |
| Troubleshoot name resolution | Use `DNS` to inspect questions, answers, and response codes. Follow a record's packet index back to the capture to inspect its timing. UDP fragments and DNS messages split across TCP segments are supported. [DNS guide](docs/parsing.md#parse-dns-messages-and-tunneling-metrics) |
| Associate a guest or IoT address with a device | Match DHCP observations to flow timestamps and the capture interface. Use lease and controller logs to confirm the association. [Deployment troubleshooting example](docs/parsing.md#trace-a-guest-connection-and-a-tls-proxy) |
| Compare clients reaching a service | Inspect TLS ClientHello or QUIC Initial records for visible server names, offered protocols, and JA4 fingerprints. Clients with similar configurations can share a fingerprint. [TLS handshakes](docs/parsing.md#parse-tls-handshakes-and-ja4-fingerprints) · [QUIC Initials](docs/parsing.md#decrypt-quic-initial-packets) |
| Investigate an application or authentication failure | Inspect HTTP requests and responses, SSH handshakes, Kerberos principals and encryption types, SMB share paths, or RDP negotiation. Use `Web` for TLS, HTTP/1, and HTTP/2 records from one TCP reassembly. Matching key logs can recover application bytes for supported TLS suites. [Offline TLS decryption](docs/parsing.md#decrypt-tls-12-and-tls-13-streams-offline) · [Windows protocols](docs/parsing.md#parse-smb2-ntlmssp-kerberos-v5-and-rdp-messages) |
| Hand one connection to another analyst | Select a flow by its index and call `ExtractFlowPCAPNG`. The export carries interface metadata and can include capture-wide name records and decryption secrets. Check those before sharing. [Capture export](docs/parsing.md#write-captures) |
| Collect traffic on a host | Use `OpenLive` with a packet filter, read packets, and pass them to a PCAP or PcapNG writer. On Linux and macOS, `Stats` reports kernel capture drops. [Live capture](docs/parsing.md#capture-live-interface-traffic) |

## Inspect a capture file

From a Go module, install the library with `go get github.com/cawalch/go-pcap@v0.1.0`.
Save this program as `main.go` and run `go run . sample.pcapng`. It also accepts
classic PCAP. It reads container metadata first, then prints one line per
bidirectional flow. An open file implements `io.ReaderAt`, so the example can
inspect a capture larger than the scan's byte budget when the selected reads fit.

```go
package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/cawalch/go-pcap"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: inspect CAPTURE")
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	c, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s packets=%d truncated=%t\n", c.Format, c.PacketCount, c.InputTruncated())

	flows, err := c.FlowsFromReaderAt(f)
	if err != nil {
		log.Fatal(err)
	}
	for _, flow := range flows {
		fmt.Printf("proto=%d %s -> %s packets=%d\n", flow.Protocol,
			netip.AddrPortFrom(flow.SrcAddr, flow.SrcPort),
			netip.AddrPortFrom(flow.DstAddr, flow.DstPort), flow.PacketCount)
	}
}
```

## Choose an input

- **Bytes already in memory.** Call `New(data)` and pass the same bytes to
  `Packets`, `Flows`, or a protocol method. For gzip input, call
  `DecompressCapture` first and use the returned bytes throughout.
- **A seekable file or other random-access source.** Call `NewFromReaderAt`
  with the source and its size. Keep the source available and its contents
  stable. `PacketSeqFromReaderAt` lets you stop iteration early. Flows, DNS,
  TLS, QUIC, DHCPv4 and neighbor discovery have dedicated ReaderAt methods
  with per-call read limits.
- **File metadata only.** `Open(path)` reads the entire file and returns a
  metadata snapshot. Use `NewFromReaderAt` when whole-file loading is costly.

A `Capture` holds container metadata. Packet records identify byte ranges in
the original input. Frame decoding identifies the network and transport headers. Flow analysis groups packets by protocol and endpoint pair. Protocol methods
can then reassemble the bytes needed for a message that spans packets. A gap
in the capture can leave a handshake or message incomplete.
[Reader limits and anomalies](docs/parsing.md) · [Architecture and roadmap](docs/architecture.md)

## API and references

- [Exported types and methods](https://pkg.go.dev/github.com/cawalch/go-pcap) · [Runnable Go examples](example_test.go)
- [PCAP file format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/) · [PcapNG blocks and options](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)
- [Community ID v1 specification and test vectors](https://github.com/corelight/community-id-spec) · [Fingerprint reference fixtures and upstream baselines](testdata/foxio/README.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [License](LICENSE)
