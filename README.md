# go-pcap

go-pcap is a Go library for reading Portable Packet Capture (PCAP) and PCAP Next
Generation (PcapNG) files, decoding network frames, and extracting flow and
protocol metadata. It uses only the Go standard library and requires Go 1.26 or
later.

The library is an experimental MVP. The API can change before v1.0.0. See the
[release guide](docs/releases.md), [changelog](CHANGELOG.md), and
[architecture guide](docs/architecture.md) for versioning, release history, and
design scope.

## Supported features

- Read classic PCAP (little-endian and big-endian, microsecond and nanosecond
  timestamps) and PcapNG containers, including Section Header Blocks (SHBs),
  Interface Description Blocks (IDBs), Enhanced Packet Blocks (EPBs), Simple
  Packet Blocks (SPBs), Decryption Secrets Blocks (DSBs), Name Resolution Blocks
  (NRBs), Interface Statistics Blocks (ISBs), and Darwin Process Event Blocks
  (DPEBs).
- Extract PcapNG DSB payloads (such as embedded Transport Layer Security (TLS)
  key logs), NRB IPv4 and IPv6 hostname mappings, ISB capture counters, and EPB
  process attribution (process ID, thread ID, user ID, process name, command
  arguments, and container ID).
- Inspect declared capture extents, truncation state, and structural container
  anomalies without retaining the input buffer.
- Decode Layer 2 through Layer 4 (L2–L4) frames and tunnel encapsulations
  (`Ethernet`, `802.1Q` and `802.1ad` virtual local area networks (VLANs),
  Multi-Protocol Label Switching (`MPLS`), Point-to-Point Protocol over Ethernet
  (`PPPoE`), Generic Routing Encapsulation (`GRE`), Virtual Extensible LAN
  (`VXLAN`), Generic Network Virtualization Encapsulation (`Geneve`), `Linux SLL`
  and `SLL2`, BSD `Loopback`/`Null`, `Raw IP`, `IPv4`, `IPv6` with extension
  headers, `TCP`, `UDP`, and `ICMPv4`/`ICMPv6`) without heap allocations.
- Aggregate deterministic 5-tuple flow summaries, compute FoxIO `JA4T`, `JA4TS`,
  and `JA4L` (latency and hop-count distance) TCP fingerprints, reassemble
  fragmented IPv4 and IPv6 datagrams (`DefragmentIP`), and reassemble bounded
  directional TCP byte streams with sequence-gap and overlap-conflict anomaly
  detection.
- Decode Domain Name System (DNS) messages over UDP (including fragmented UDP
  datagrams) and TCP with bounded RFC 1035 label compression pointer resolution,
  and compute per-domain DNS tunneling metrics (`DNSLabelEntropy` and
  `Capture.DNSDomainStats`).
- Decode TLS 1.2 and TLS 1.3 handshakes and X.509 certificate chains (including
  encrypted TLS 1.3 server certificates when `SERVER_HANDSHAKE_TRAFFIC_SECRET` is
  present), and compute FoxIO `JA4`, `JA4S`, and `JA4X` fingerprints.
- Decrypt Quick UDP Internet Connections (QUIC) v1 (RFC 9001) and v2 (RFC 9369)
  Initial UDP packets, reassemble multi-packet `CRYPTO` frames, and extract the
  embedded TLS 1.3 `ClientHello` and `JA4` fingerprint.
- Decrypt TLS 1.2 (`CLIENT_RANDOM` master secrets) and TLS 1.3 application
  streams offline using PcapNG DSBs or caller-supplied `SSLKEYLOGFILE` material.
- Decode HTTP/1.x requests and responses and HTTP/2 frames across cleartext and
  decrypted TLS streams, compute FoxIO `JA4H` and HTTP/2 `SETTINGS` fingerprints,
  and carve `Content-Length`, `chunked`, or HTTP/2 `DATA` stream payloads.
- Decode Secure Shell (SSH) handshakes (`HASSH`, `HASSHServer`, and FoxIO
  `JA4SSH`), Server Message Block (SMB) v2/v3 and NT LAN Manager Security
  Support Provider (NTLMSSP) negotiation tokens, Kerberos v5 (`AS-REQ`,
  `TGS-REQ`, and `KRB-ERROR` with RC4-HMAC `etype 23` detection), Remote Desktop
  Protocol (RDP) TPKT/X.224 negotiation PDUs, and statistical
  Command-and-Control (C2) beacon periodicity and Producer-Consumer Ratio (PCR)
  metrics.

The library doesn't perform active network probing, certificate revocation
checks, or operating-system trust store validation. For large files, use
`NewFromReaderAt`, `Capture.PacketsFromReaderAt`,
`Capture.PacketPayloadFromReaderAt`, `Capture.FlowsFromReaderAt`,
`Capture.DNSFromReaderAt`, `Capture.TLSFromReaderAt`, and
`Capture.QUICFromReaderAt` to read bounded container metadata, packet records,
flows, and handshake records from an `io.ReaderAt` without loading the entire
capture into memory. To write PcapNG files or capture live packets from a local
interface using standard-library system calls (`CGO_ENABLED=0`), use
`NewPCAPNGWriter` and `OpenLive` (with `BPFFilterTCPPort`, `BPFFilterUDPPort`,
`BPFFilterIPProtocol`, `BPFFilterIPv4Host`, and `EvalBPF`).

## Install the library

In your Go module, install the library:

```sh
go get github.com/cawalch/go-pcap
```

For reproducible builds, commit the resulting `go.mod` and `go.sum` files. Go
records a version that identifies the selected commit.

## Parse a capture

The following program reads a PCAP or PcapNG file, prints its container
metadata and 5-tuple flows, and lists any TLS handshakes and HTTP requests
(including HTTP requests decrypted from embedded PcapNG DSB key logs). Save it
as `main.go`:

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
		log.Fatal("Usage: inspect FILE")
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	capture, err := pcap.New(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Format: %s (packets: %d, secrets: %d, truncated: %v)\n",
		capture.Format, capture.PacketCount, len(capture.Secrets), capture.InputTruncated())

	flows, err := capture.Flows(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, flow := range flows {
		fmt.Printf("Flow proto=%d %s:%d -> %s:%d packets=%d bytes=%d ja4t=%s\n",
			flow.Protocol, flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort,
			flow.PacketCount, flow.ClientBytes+flow.ServerBytes, flow.ClientJA4T)
	}

	tlsRecords, err := capture.TLS(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, rec := range tlsRecords {
		if rec.Handshake.HasClientHello {
			ch := rec.Handshake.ClientHello
			fmt.Printf("TLS %s:%d -> %s:%d sni=%s ja4=%s\n",
				rec.SrcAddr, rec.SrcPort, rec.DstAddr, rec.DstPort, ch.SNI, ch.JA4)
		}
	}

	httpRecords, err := capture.HTTP(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, rec := range httpRecords {
		if !rec.IsResponse {
			fmt.Printf("HTTP %s %s%s (decrypted=%v, body=%d bytes, ja4h=%s)\n",
				rec.Request.Method, rec.Request.Host, rec.Request.Path,
				rec.IsDecrypted, rec.Request.BodyLength, rec.Request.JA4H)
		}
	}
}
```

To run the program, replace `sample.pcapng` with the path to your capture file:

```sh
go run . sample.pcapng
```

`New` validates the capture container, records interface descriptors, name
resolution entries, interface statistics, process events, and decryption
secrets, and scans block bounds. To read packets, flows, streams, or protocol
records, call the corresponding method with the original bytes. For container
metadata alone, `Open(path)` reads the entire file and calls `New`.

## Use the parsed metadata

`New` copies container header values, interface descriptors, and DSB secrets
without retaining the input buffer. Keep the buffer if you need to read packets,
flows, or application protocols. A `Capture` doesn't require a `Close` call. You
can read it from multiple goroutines if you don't modify its exported fields.

A successful container parse doesn't mean every packet in the file is complete.
Use `Capture.InputTruncated` or `Capture.DeclaredExtent` to check whether the
input is shorter than its declared packet records or PcapNG blocks. If you have
only a stream prefix, use `NewWithLength` to supply the full stream length.

The [parsing guide](docs/parsing.md) explains buffer ownership, work limits,
errors, and protocol dissectors. Use the
[API reference](https://pkg.go.dev/github.com/cawalch/go-pcap) for individual
types and methods.

| Task | API | Details |
| --- | --- | --- |
| Parse container metadata, interfaces, NRBs, ISBs, and DSB secrets | `New`, `NewWithLength`, `NewFromReaderAt`, `Open` | [Container parsing](docs/parsing.md#parse-capture-containers) |
| Write PcapNG blocks, NRBs, ISBs, DSB secrets, and process-tagged packets | `NewPCAPNGWriter`, `PCAPNGWriter.WritePacket`, `PCAPNGWriter.WriteDecryptionSecrets`, `PCAPNGWriter.WriteNameResolution`, `PCAPNGWriter.WriteInterfaceStats` | [Write PcapNG](docs/parsing.md#write-pcapng-captures) |
| Capture live interface packets without CGO or libpcap | `OpenLive`, `LiveCapture.ReadPacket`, `ParseBPFBuffer`, `BPFFilterTCPPort`, `BPFFilterUDPPort`, `BPFFilterIPProtocol`, `BPFFilterIPv4Host`, `EvalBPF` | [Live capture](docs/parsing.md#capture-live-interface-traffic) |
| Check truncation, extents, and container anomalies | `Capture.DeclaredExtent`, `Capture.InputTruncated`, `Capture.Anomalies` | [Bounds and anomalies](docs/parsing.md#inspect-truncation-and-anomalies) |
| Stream or enumerate bounded packet records and payload slices | `Capture.PacketSeq`, `Capture.Packets`, `Capture.PacketPayload`, `Capture.PacketsFromReaderAt` | [Packet records](docs/parsing.md#read-packet-records) |
| Decode L2–L4 frames, tunnels, IP fragments, and JA4T/JA4L fingerprints | `DecodeFrame`, `DefragmentIP`, `Frame.JA4T`, `JA4T`, `JA4L` | [Frame decoding](docs/parsing.md#decode-l2-l4-frames-and-tunnels) |
| Aggregate deterministic 5-tuple flows | `Capture.Flows`, `Capture.FlowsFromReaderAt` | [Flow aggregation](docs/parsing.md#aggregate-5-tuple-flows) |
| Reassemble bounded TCP byte streams | `Capture.Streams`, `ReassembleTCP` | [TCP reassembly](docs/parsing.md#reassemble-tcp-streams) |
| Parse DNS messages and compute DNS tunneling metrics | `Capture.DNS`, `Capture.DNSFromReaderAt`, `Capture.HasDNSQuery`, `Capture.DNSDomainStats`, `ParseDNS`, `DNSLabelEntropy` | [DNS messages](docs/parsing.md#parse-dns-messages-and-tunneling-metrics) |
| Parse TLS handshakes, X.509 certificates, and JA4/JA4S/JA4X | `Capture.TLS`, `Capture.TLSFromReaderAt`, `Capture.TLSWithKeyLog`, `Capture.HasTLSJA4`, `Capture.HasTLSSNI`, `ParseTLSRecords`, `JA4XFromDER` | [TLS handshakes](docs/parsing.md#parse-tls-handshakes-and-ja4-fingerprints) |
| Decrypt QUIC v1/v2 Initial packets and extract inner TLS 1.3 JA4 | `Capture.QUIC`, `Capture.QUICFromReaderAt`, `Capture.HasQUICJA4`, `Capture.HasQUICSNI`, `DecryptQUICInitial`, `ParseQUICInitialPacket` | [QUIC Initial](docs/parsing.md#decrypt-quic-initial-packets) |
| Decrypt TLS 1.2 and TLS 1.3 streams offline via PcapNG DSB or keylog | `Capture.DecryptedTLSStreams`, `Capture.TLSKeyLog`, `DecryptTLS13Records`, `DecryptTLS12Records`, `ParseTLSKeyLog` | [TLS decryption](docs/parsing.md#decrypt-tls-12-and-tls-13-streams-offline) |
| Parse HTTP/1.x and HTTP/2, compute JA4H and SETTINGS fingerprints, and carve payloads | `Capture.HTTP`, `Capture.HTTP2`, `ParseHTTPRequest`, `ParseHTTPResponse`, `ParseHTTP2Frames` | [HTTP and carving](docs/parsing.md#parse-http-messages-and-carve-payloads) |
| Parse SSH handshakes and compute HASSH, HASSHServer, and JA4SSH | `Capture.SSH`, `ParseSSHHandshake`, `JA4SSH` | [SSH handshakes](docs/parsing.md#parse-ssh-handshakes-and-hassh) |
| Parse SMB2/3, NTLMSSP, Kerberos v5, and RDP negotiation metadata | `Capture.SMB`, `Capture.Kerberos`, `Capture.RDP`, `ParseSMB2Message`, `ParseNTLMSSP`, `ParseKRB5`, `ParseRDPNegotiation` | [SMB2, NTLM, Kerberos, and RDP](docs/parsing.md#parse-smb2-ntlmssp-kerberos-v5-and-rdp-messages) |
| Compute C2 beacon timing regularity and flow PCR scores | `Capture.Beacons`, `ComputeBeaconStats` | [Beacon analytics](docs/parsing.md#compute-c2-beacon-and-flow-statistics) |

## Integrate with an application

Your application controls file reads, input size limits, cancellation, and cache
lifetime. Parsing is synchronous. `Open` reads the entire file without a size
limit or cancellation support; use `New` or `NewFromReaderAt` if you need to
control those reads.

Keep scanner adapters in the consuming project. go-pcap is independent of
go-yara and other scanners. YARA fields, undefined values, scan-state reset, and
rule evaluation belong in the adapter.

## Contribute

See [Contributing](CONTRIBUTING.md) for validation commands, feature scope, and
documentation style. Tests use synthetic in-memory fixtures and require no
external packet captures, sibling repositories, or network access after you
install Go.

## References

- [API reference](https://pkg.go.dev/github.com/cawalch/go-pcap)
- [Parsing guide](docs/parsing.md)
- [Architecture, roadmap, and YARA integration](docs/architecture.md)
- [Release guide](docs/releases.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [MIT license](LICENSE)
