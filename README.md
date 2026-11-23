# go-pcap

go-pcap is a Go library for answering questions about captured network traffic.
Read a PCAP or PcapNG file to find which endpoints exchanged packets, which
names they queried, or which TLS settings they offered. You can also capture
packets from a local interface and write captures for another tool to inspect.

The library uses the Go standard library, builds without cgo or libpcap, and
requires Go 1.26 or later. The API is experimental and can change before v1.0.
[v0.1.1 release](https://github.com/cawalch/go-pcap/releases/tag/v0.1.1) · [Platform verification](CHANGELOG.md#platform-verification)

## Quick start with a guest Wi-Fi capture

The sample contains 14 packets seen on a guest network. The client queried
DNS, exchanged 11 packets with one HTTPS endpoint, and sent a single SYN to another. Download the synthetic
[guest.pcapng](testdata/deployments/guest.pcapng) into an empty directory.
In that directory, initialize a Go module and install the release.

```sh
go mod init example.com/inspect
go get github.com/cawalch/go-pcap@v0.1.1
```

Save the program below as `main.go` and run `go run . guest.pcapng`.
It prints the endpoints and packet count for each bidirectional flow.

```text
pcapng packets=14 truncated=false
proto=17 192.0.2.14:53000 -> 192.0.2.53:53 packets=2
proto=6 192.0.2.14:50000 -> 198.51.100.80:443 packets=11
proto=6 192.0.2.14:50001 -> 198.51.100.81:443 packets=1
```

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

## Start with a question

| Question | Where to start |
| --- | --- |
| Which sensor log entry matches this flow? | Join TCP or UDP flows by `CommunityID`. [Flow summaries](docs/parsing.md#aggregate-5-tuple-flows) |
| Which names did the client look up? | Inspect questions and answers with `DNS`. [DNS records](docs/parsing.md#parse-dns-messages-and-tunneling-metrics) |
| Which device requested this address? | Read lease observations with `DHCPv4`. [Address assignments](docs/parsing.md#dhcpv4-address-assignments) |
| What did the client offer during the handshake? | Inspect server names and fingerprints with `TLS` or `QUIC`. [TLS handshakes](docs/parsing.md#parse-tls-handshakes-and-ja4-fingerprints) |
| What did the web client request? | Use `Web` for HTTP/1, HTTP/2 and TLS records. [Web traffic and decryption](docs/parsing.md#parse-http-messages-and-carve-payloads) |
| How do I share one connection? | Call `ExtractFlowPCAPNG`. Check for capture-wide names and decryption secrets before sharing. [Flow export](docs/parsing.md#write-captures) |
| How do I collect packets on a host? | Open an interface with `OpenLive`. [Live capture](docs/parsing.md#capture-live-interface-traffic) |

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

For a worked example of correlating records across a guest network and a TLS
proxy, see the [deployment walkthrough](docs/parsing.md#trace-a-guest-connection-and-a-tls-proxy).

## API and references

[Consumer API compatibility](docs/compatibility.md) covers record order, input and payload ownership, limits, and error handling.

- [Package overview](doc.go) · [Runnable Go examples](example_test.go)
- [PCAP file format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/) · [PcapNG blocks and options](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)
- [Community ID v1 specification and test vectors](https://github.com/corelight/community-id-spec)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Architecture and roadmap](docs/architecture.md)

## Licenses and attribution

Original go-pcap code uses the [MIT license](LICENSE). FoxIO publishes JA4 TLS
client fingerprinting under BSD-3-Clause and the other JA4+ methods under the
FoxIO License 1.1, which restricts monetization. The distribution includes
the [third-party notices and terms](NOTICE), [Go HPACK license](LICENSE-hpack)
and [fingerprint fixture provenance](testdata/foxio/README.md).
