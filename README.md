# go-pcap

go-pcap is a Go library for reading packet captures (PCAP and PcapNG), decoding
network frames, and extracting flow and protocol metadata. It uses only the Go
standard library and requires Go 1.26 or later.

The library is an experimental MVP. The API can change before v1.0.0. See the
[architecture and roadmap](docs/architecture.md) and
[parsing guide](docs/parsing.md) for design goals, work limits, and the
`go-yara` `import "pcap"` integration specification.

## Supported features

- Read classic PCAP (little-endian and big-endian, microsecond and nanosecond
  timestamps) and PcapNG containers (`SHB`, `IDB`, `EPB`, `SPB`, and `DSB`).
- Extract PcapNG Decryption Secrets Blocks (`DSB`, such as embedded TLS key
  logs from `ecapture`, `ptcpdump`, or Wireshark) and Enhanced Packet Block
  process attribution (`ProcessID`, `ThreadID`, interface names, and packet
  flags).
- Inspect declared capture extents, truncation state, and structural container
  anomalies without retaining the input buffer.
- Enumerate bounded packet records with zero-copy payload offset and length
  spans into the caller's slice.
- Decode L2–L4 frames (`Ethernet`, `802.1Q`/`802.1ad` VLANs, `Linux SLL`/`SLL2`,
  `Loopback`/`Null`, `Raw IP`, `IPv4`, `IPv6` with extension headers, `TCP` with
  SYN options, `UDP`, and `ICMPv4`/`ICMPv6`) using a stack-allocated layer
  cursor that performs zero heap allocations per frame.
- Aggregate deterministic 5-tuple flow summaries (`Flows`) with directional
  packet and byte counts, unioned TCP flags, `ClientJA4T` / `ServerJA4TS` TCP
  fingerprints, first-seen process attribution, and frame anomaly rollups.
- Reassemble bounded directional TCP byte streams (`Streams`, `ReassembleTCP`)
  with sequence-gap, midstream-pickup, retransmission, and overlap-conflict
  anomaly detection.
- Decode DNS messages over UDP and TCP (`ParseDNS`, `Capture.DNS`,
  `Capture.HasDNSQuery`) with bounded RFC 1035 label compression pointer
  resolution.
- Decode TLS 1.2 and TLS 1.3 handshakes and X.509 certificate chains
  (`ParseTLSRecords`, `ParseTLSClientHello`, `ParseTLSServerHello`,
  `Capture.TLS`, `Capture.HasTLSJA4`, `Capture.HasTLSSNI`) and compute FoxIO
  **JA4, JA4S, JA4X, and JA4T** fingerprints.
- Decrypt QUIC v1 (RFC 9001) and QUIC v2 (RFC 9369) Initial UDP packets
  (`ParseQUICInitialPacket`, `DecryptQUICInitial`, `Capture.QUIC`,
  `Capture.HasQUICJA4`, `Capture.HasQUICSNI`), reassemble multi-packet `CRYPTO`
  frames, and extract embedded TLS 1.3 `ClientHello` and `q13...` **JA4**
  fingerprints.
- Decrypt TLS 1.3 application streams offline (`ParseTLSKeyLog`,
  `DecryptTLS13Records`, `Capture.DecryptedTLSStreams`) using PcapNG Decryption
  Secrets Blocks (`DSB`) or caller-supplied `SSLKEYLOGFILE` secrets.
- Decode HTTP/1.x requests and responses across cleartext and DSB-decrypted TLS
  streams (`ParseHTTPRequest`, `ParseHTTPResponse`, `Capture.HTTP`), compute
  FoxIO **JA4H** fingerprints, and carve `Content-Length` or `chunked` body
  payloads.
- Decode SSH handshakes (`ParseSSHHandshake`, `Capture.SSH`) and compute
  **HASSH** and **HASSHServer** fingerprints.
- Decode SMB2/3 Negotiate and Session Setup messages and embedded NTLMSSP tokens
  (`ParseSMB2Message`, `ParseNTLMSSP`, `Capture.SMB`).
- Compute C2 beacon timing periodicity, payload uniformity, and directional
  Producer-Consumer Ratio (PCR) metrics (`ComputeBeaconStats`, `Capture.Beacons`).
- Read large captures via `io.ReaderAt` (`NewFromReaderAt`,
  `Capture.PacketsFromReaderAt`, `Capture.PacketPayloadFromReaderAt`), write
  PcapNG captures with `DSB` and process metadata (`NewPCAPNGWriter`), and
  capture live interface traffic with `CGO_ENABLED=0` standard-library syscalls
  (`OpenLive`, `ParseBPFBuffer`).

## Install the library

In your Go module, install the library:

```sh
go get github.com/cawalch/go-pcap
```

## Parse a capture

The following program reads a PCAP or PcapNG file, prints its container
metadata, and summarizes its network flows. Save it as `main.go`:

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

	fmt.Printf("Format: %s (packets: %d, truncated: %v)\n",
		capture.Format, capture.PacketCount, capture.InputTruncated())

	flows, err := capture.Flows(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, flow := range flows {
		fmt.Printf("proto=%d %s:%d -> %s:%d packets=%d bytes=%d\n",
			flow.Protocol, flow.SrcAddr, flow.SrcPort, flow.DstAddr, flow.DstPort,
			flow.PacketCount, flow.ClientBytes+flow.ServerBytes)
	}
}
```

`New` validates the capture container, records interface descriptors and
decryption secrets, and scans block bounds without retaining the input buffer.
Keep the buffer if you need to call `Packets` or `Flows`. A `Capture` doesn't
require a `Close` call and can be read concurrently from multiple goroutines if
you don't modify its exported fields.

## Use the parsed metadata

| Task | API | Details |
| --- | --- | --- |
| Parse container metadata, interfaces, and `DSB` secrets | `New`, `NewWithLength`, `NewFromReaderAt`, `Open` | [Container parsing](docs/parsing.md#parse-capture-containers) |
| Write PcapNG blocks, `DSB` secrets, and process-tagged packets | `NewPCAPNGWriter`, `PCAPNGWriter.WritePacket`, `PCAPNGWriter.WriteDecryptionSecrets` | [Write PcapNG](docs/parsing.md#write-pcapng-captures) |
| Capture live interface packets without CGO or libpcap | `OpenLive`, `LiveCapture.ReadPacket`, `ParseBPFBuffer` | [Live capture](docs/parsing.md#capture-live-interface-traffic) |
| Check truncation, extents, and container anomalies | `Capture.DeclaredExtent`, `Capture.InputTruncated`, `Capture.Anomalies` | [Bounds and anomalies](docs/parsing.md#inspect-truncation-and-anomalies) |
| Enumerate bounded packet records and zero-copy payload slices | `Capture.Packets`, `Capture.PacketPayload`, `Capture.PacketsFromReaderAt` | [Packet records](docs/parsing.md#read-packet-records) |
| Decode L2–L4 frames with zero heap allocations | `DecodeFrame`, `Frame.JA4T`, `JA4T` | [Frame decoding](docs/parsing.md#decode-l2-l4-frames) |
| Aggregate deterministic 5-tuple flows | `Capture.Flows` | [Flow aggregation](docs/parsing.md#aggregate-5-tuple-flows) |
| Reassemble bounded TCP byte streams | `Capture.Streams`, `ReassembleTCP` | [TCP reassembly](docs/parsing.md#reassemble-tcp-streams) |
| Parse DNS queries and resource records | `Capture.DNS`, `Capture.HasDNSQuery`, `ParseDNS` | [DNS messages](docs/parsing.md#parse-dns-messages) |
| Parse TLS handshakes, X.509 certificates, and JA4/JA4S/JA4X | `Capture.TLS`, `Capture.HasTLSJA4`, `Capture.HasTLSSNI`, `ParseTLSRecords`, `JA4XFromDER` | [TLS handshakes](docs/parsing.md#parse-tls-handshakes-and-ja4-fingerprints) |
| Decrypt QUIC v1/v2 Initial packets and extract inner TLS 1.3 JA4 | `Capture.QUIC`, `Capture.HasQUICJA4`, `Capture.HasQUICSNI`, `DecryptQUICInitial`, `ParseQUICInitialPacket` | [QUIC Initial](docs/parsing.md#decrypt-quic-initial-packets) |
| Decrypt TLS 1.3 streams offline via PcapNG `DSB` or keylog | `Capture.DecryptedTLSStreams`, `Capture.TLSKeyLog`, `DecryptTLS13Records`, `ParseTLSKeyLog` | [TLS decryption](docs/parsing.md#decrypt-tls-13-streams-offline) |
| Parse HTTP/1.x, compute JA4H, and carve payloads | `Capture.HTTP`, `ParseHTTPRequest`, `ParseHTTPResponse` | [HTTP and carving](docs/parsing.md#parse-http-messages-and-carve-payloads) |
| Parse SSH handshakes and compute HASSH / HASSHServer | `Capture.SSH`, `ParseSSHHandshake` | [SSH handshakes](docs/parsing.md#parse-ssh-handshakes-and-hassh) |
| Parse SMB2/3 and NTLMSSP negotiation/challenge metadata | `Capture.SMB`, `ParseSMB2Message`, `ParseNTLMSSP` | [SMB2 and NTLM](docs/parsing.md#parse-smb2-and-ntlmssp-messages) |
| Compute C2 beacon timing regularity and flow PCR scores | `Capture.Beacons`, `ComputeBeaconStats` | [Beacon analytics](docs/parsing.md#compute-c2-beacon-and-flow-statistics) |

## Integrate with an application

Your application controls file reads, input size limits, cancellation, and cache
lifetime. Parsing is synchronous. `Open` reads the entire file without a size
limit; use `New` if you need to control those reads.

Keep scanner adapters in the consuming project. go-pcap is independent of
go-yara and other scanners. YARA fields, undefined values, scan-state reset, and
rule evaluation belong in the adapter.

## References

- [Architecture, roadmap, and YARA `pcap` grammar](docs/architecture.md)
- [Parsing guide and work limits](docs/parsing.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [MIT license](LICENSE)
