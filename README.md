# go-pcap

Package `pcap` reads, writes, and analyzes PCAP and PcapNG. Inspect packets,
flows, DNS, TLS, QUIC, HTTP, and enterprise protocols. Supported analyses
identify original packet evidence and bounded partial results. Live capture
uses native OS interfaces.

Requires Go 1.26 or later. The module uses the standard library and builds
without cgo or libpcap. The API is experimental before v1.0.
[Latest release](https://github.com/cawalch/go-pcap/releases/latest) ·
[Coverage](docs/capabilities.md) · [Package documentation](doc.go)

## Quick start with a packet capture

Install the library in a Go module.

```sh
go get github.com/cawalch/go-pcap@v0.2.0
```

This program opens a capture and counts its flows.

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cawalch/go-pcap"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: inspect CAPTURE")
	}
	if err := inspect(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func inspect(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	capture, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		return err
	}
	flows, err := capture.FlowsFromReaderAt(f)
	if err != nil {
		return err
	}
	fmt.Printf("%d packets, %d flows, truncated=%t\n",
		capture.PacketCount, len(flows), capture.InputTruncated())
	return nil
}
```

Save the program as `main.go` and run `go run . client.pcapng` with the
[14-packet sample](testdata/deployments/client.pcapng). It reports
`14 packets, 3 flows, truncated=false`.

## Start with a question

| Task | Guide |
| --- | --- |
| Match flows or diagnose DNS replies | [Flows](docs/parsing.md#aggregate-5-tuple-flows) · [DNS transactions](docs/parsing.md#diagnose-dns-transactions) |
| Inspect TLS names and certificates | [Handshake evidence](docs/parsing.md#locate-a-hello-or-certificate-chain-in-the-original-packets) · [ECH](docs/parsing.md#interpret-server-names-with-ech) |
| Decode HTTP and locate original packets | [HTTP analysis](docs/parsing.md#parse-http-messages-and-carve-payloads) · [HTTP/3 evidence](docs/parsing.md#recover-keyed-http3-request-streams) |
| Collect or share traffic | [Live capture](docs/parsing.md#capture-live-interface-traffic) · [Writers and exports](docs/parsing.md#write-captures) |

## Share packets from one flow

Pass the zero-based flow index from `Flows` and the original input to
`ExtractFlowPacketsPCAPNG`. This export omits names, process information,
and secrets. The original endpoints and payloads remain in packet bytes.
[Runnable example](example_test.go) · [Export options](docs/parsing.md#write-captures)

## Choose an input

- Use `New` for bytes and pass the same contents to later scans.
- Use `NewFromReaderAt` for a seekable source. Keep its contents stable.
- Use `Open` for a metadata snapshot. It reads the whole file.
- Use `DecompressCapture` for bounded gzip input or
  [stage larger or non-seekable inputs](docs/parsing.md#read-compressed-or-non-seekable-input).

## API and references

[Parsing guide](docs/parsing.md) · [Compatibility](docs/compatibility.md) ·
[Runnable examples](example_test.go) · [Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md)

## Licenses and attribution

Original code uses the [MIT license](LICENSE). JA4 TLS client fingerprinting
uses BSD-3-Clause. Other JA4+ methods have separate terms.
[Third-party notices](NOTICE) · [HPACK license](LICENSE-hpack) ·
[Fingerprint inventory](docs/fingerprints.md)
