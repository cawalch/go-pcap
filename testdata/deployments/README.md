# Deployment capture fixtures

[generate.py](generate.py) builds the synthetic captures and the input for
the Apple tcpdump fixture from fixed inputs with Python 3.13.18. It uses the Python standard library,
documentation IP addresses, `.example` names, and locally administered MAC
addresses. The repository license covers the generator and captures.

Run these commands from the repository root. Normal Go tests use the checked-in
captures and expectations in [deployment_test.go](../../deployment_test.go).
Python and the reference decoder are only needed to regenerate or review them.

```sh
python3 testdata/deployments/generate.py
go test -run '^TestDeploymentCaptures$' -v .
```

## Independent decoder

Reference output comes from TShark 4.6.10 (commit `eac916f07299`) with name
resolution disabled and an empty TLS key log setting. Run the following
commands from this directory.

```sh
for capture in client iot proxy; do
  tshark -n -o tls.keylog_file: -r "$capture.pcapng" -T fields \
    -e frame.number -e frame.interface_name -e frame.cap_len -e frame.len \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.stream \
    -e udp.srcport -e udp.dstport -e udp.stream -e _ws.col.Info
done
for capture in client iot; do
  tshark -n -r "$capture.pcapng" -Y dns -T fields \
    -e frame.number -e dns.id -e dns.flags.response -e dns.flags.rcode \
    -e dns.qry.type -e dns.qry.name -e dns.a
done
for capture in client proxy; do
  tshark -n -o tls.keylog_file: -r "$capture.pcapng" -Y tls -T fields \
    -e frame.number -e tcp.stream -e tls.handshake.type \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.extensions_alpn_str \
    -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite \
    -e tls.record.opaque_type
done
tshark -n -r iot.pcapng -Y dhcp -T fields \
  -e frame.number -e dhcp.option.dhcp -e dhcp.id -e dhcp.hw.mac_addr \
  -e dhcp.ip.your -e dhcp.option.dhcp_server_id -e dhcp.option.ip_address_lease_time
tshark -n -r iot.pcapng -Y 'udp.stream == 3' -T fields \
  -e frame.number -e udp.payload
tshark -n -r proxy.pcapng -Y frame.darwin.process_info.pid -T fields \
  -e frame.number -e frame.darwin.process_info.pid -e frame.darwin.process_info.pname
```

Frame numbers here are TShark's one-based numbers. Go packet indices start at
zero. The packet counts are 14 for `client`, 12 for `proxy`, and 6 for `iot`.

| Capture | TShark stream membership | go-pcap export selection |
| --- | --- | --- |
| Client | UDP 0 has frames 1 and 3. TCP 0 has frames 2, 4–8. TCP 1 reuses its tuple in frames 9, 11–14. TCP 2 has only frame 10, a SYN. | Flow 1 has frames 2, 4–9, 11–14, the union of TCP streams 0 and 1. Frame 13 has 58 captured bytes and an original length of 76 bytes. |
| Proxy | TCP 0 on `proxy-client` has frames 1, 3, 5, 7, 9, 11. TCP 1 on `proxy-origin` has frames 2, 4, 6, 8, 10, 12. | Flow 1 has the six origin-facing frames. Frame 8 references the synthetic Darwin process entry `4242 fixture-proxy`. The export retains that attribution and remaps the selected interface to index 0. |
| IoT | UDP 0 has frame 1. UDP 1 has frame 2. UDP 2 has frames 3 and 5. UDP 3 has frames 4 and 6. | Flow 3 has opaque UDP payloads `d391ee0102` and `d391ee0304` in frames 4 and 6. |

| Capture | Query and reply frames | Transaction ID | A question | A answer |
| --- | --- | --- | --- | --- |
| Client | 1, 3 | `0x1020` | `trace.example` | `198.51.100.80` |
| IoT | 3, 5 | `0x1020` | `collector.example` | `203.0.113.7` |

Both DNS responses have response code 0. IoT frames 1 and 2 are a DHCP Discover
and Offer for transaction `0x31514159` and MAC `02:00:00:00:00:2a`. Server
`203.0.113.1` offers `203.0.113.42` for 3600 seconds.

| Capture and leg | ClientHello frame | ServerHello frame | ClientHello server name | Offered ALPN | Selected version and cipher |
| --- | --- | --- | --- | --- | --- |
| Client | 6 | 7 | `trace.example` | `h2` | TLS 1.3, `0x1301` |
| Proxy, client facing | 7 | 9 | `app.example` | `h2` | TLS 1.3, `0x1301` |
| Proxy, origin facing | 8 | 10 | `origin.example` | `http/1.1` | TLS 1.3, `0x1302` |

Application-Layer Protocol Negotiation (ALPN) offers appear in each
ClientHello. In these TLS 1.3 examples the negotiated ALPN and certificate
chains are unavailable in the passive view. Proxy frames 11 and 12 have TLS
outer content type 23 and contain synthetic placeholders for opaque records.
The files have no decryption secrets. The tests expect empty negotiated ALPN,
certificate chains, and decrypted proxy streams.

See the [worked troubleshooting example](../../docs/parsing.md#trace-a-client-connection-and-a-tls-proxy)
for capture points and how to correlate the results with logs.

## Apple PKTAP process fixture

Apple tcpdump 4.99.1 (Apple version 161, libpcap 1.10.1) converted the generated
`darwin-pktap.pcap` to `darwin-pktap.pcapng`. This uses offline input and
requires no capture privileges. The generated packets, addresses, and
process names are synthetic. Apple tcpdump records its own platform and
application details in the section header.

Run these commands from this directory on macOS to reproduce the conversion
and inspect its attribution.

```sh
/usr/sbin/tcpdump -nn -r darwin-pktap.pcap -P -w darwin-pktap.pcapng
/usr/sbin/tcpdump -nn -k -r darwin-pktap.pcapng
tshark -n -r darwin-pktap.pcapng -T fields \
  -e frame.number -e frame.darwin.process_info.pid \
  -e frame.darwin.process_info.pname -e frame.darwin.sc \
  -e frame.darwin.flow_id -e frame.darwin.trace_tag
```

Packets 1 and 2 have primary PID `16232` and name `fixture-proxy`. Apple
tcpdump also shows effective PID `7447` and name `fixture-client` on packet 1.
Packet 3 has no process. Packet 4 has the name `fixture-name` with no PID.
Apple tcpdump omits its PID and TShark displays the raw value `4294967295`.
All four packets carry service class 7, flow ID 101, and trace tag 42. The Go
tests check these attribution boundaries and verify that flow export preserves
the original process entries.

TShark 4.6.10 (`eac916f07299`) decodes all four source PCAP frames as
`pktap:pcap_pktdata:eth:ethertype:ip:udp`, with embedded DLT 1 (Ethernet) and
`192.0.2.2:5000 → 198.51.100.2:6000`. The converted PcapNG uses Ethernet
interfaces and presents the same four UDP tuples.

```sh
tshark -n -r darwin-pktap.pcap -T fields -e frame.number -e frame.protocols \
  -e ip.src -e ip.dst -e udp.srcport -e udp.dstport
```

## DNS transaction fixture

`dns-transactions.pcap` contains 13 Ethernet frames with classic PCAP
microsecond timestamps. Regenerate it with the same script. Inspect the DNS
IDs, echoed questions, header response codes, and timestamps with TShark:

```sh
tshark -n -r dns-transactions.pcap -T fields -e frame.number -e dns.id \
  -e dns.qry.name -e dns.flags.rcode -e dns.response_to -e dns.time
```

The four unambiguous pairs have elapsed times of 8 ms, 5 ms, 1.2 s and 6 ms
in query order. TShark associates frame 11 with frame 9. Frame 10 carries
the same question and ID, so the go-pcap example leaves the pair ambiguous.
See the [transaction walkthrough](../../docs/parsing.md#diagnose-dns-transactions).

## HTTP/1 transaction fixture

`http1-transactions.pcapng` contains 20 synthetic Ethernet frames across two
interfaces. Regenerate it with the same script. Run TShark in two-pass mode
to inspect reassembly and request and response observations.

```sh
tshark -2 -n -r http1-transactions.pcapng -T fields \
  -e frame.number -e tcp.stream -e tcp.segment -e tcp.analysis.lost_segment \
  -e http.request.method -e http.request.uri -e http.response.code \
  -e http.request_in -e http.response_in -e http.file_data
```

- TCP stream 0 starts at frame 2. Frames 5, 6, and 8 supply the request
  `POST /upload`. Frame 7 carries `100 Continue`. Frame 8 also starts
  `GET /pipelined` immediately after the four-byte upload body.
- TShark reassembles the gzip response across frames 10 and 11 and decodes
  it to `upload accepted\n`. Frame 11 also carries the next response,
  `204 No Content`.
- TCP stream 1 starts at frame 13 and reuses the same tuple. The independent
  pair `GET /reused` spans frames 16 and 17. The server response in frame
  20 follows a TCP sequence gap with two pending requests. TShark links it
  to `/after-gap`. The Go tests expect ambiguous pairing because the gap
  hides response framing.

## HTTP/2 frame fixture

`http2-frames.pcapng` contains 10 Ethernet frames with one prior-knowledge
cleartext HTTP/2 connection. TShark 4.6.10 (commit `eac916f07299`) produces
the following frame numbers, HTTP/2 types, stream IDs, and flags. Run the
command from the repository root.

```sh
tshark -n -d tcp.port==80,http2 -r testdata/deployments/http2-frames.pcapng \
  -Y http2.type -T fields -e frame.number -e http2.type -e http2.streamid -e http2.flags
```

```text
4	4	0	0x00
5	4,4	0,0	0x00,0x01
6	4,1	0,1	0x01,0x04
7	1	3	0x01
8	9,0	3,1	0x04,0x09
9	1,1	3,1	0x05,0x04
10	0	1	0x01
```

The client sends stream 1's POST headers before stream 3's GET headers, then
ends stream 1 with the padded DATA in frame 8. Its unpadded bytes are `pcap`.
Stream 3 reuses stream 1's indexed `:authority`. The HEADERS in frame 7
carries END_STREAM. Its header block ends with END_HEADERS on the
CONTINUATION in frame 8. The server ends stream 3 with a 204 in frame 9
and stream 1 with the DATA `ok` in frame 10.

The [Go tests](../../http2_frame_test.go) check directional frame and DATA
offsets, decoded headers, and stream completion without invoking TShark.

## HTTP/2 transaction fixture

`http2-transactions.pcapng` contains 14 Ethernet frames. Frame 3 belongs to a separate TCP connection
on the `unrelated` interface. Frame 7 starts POST
requests on streams 1 and 3 at TCP payload offsets 0 and 50. Stream 3
references the authority inserted by stream 1. TShark 4.6.10 (commit
`eac916f07299`) reports the following fields. Run from the repository root.

```sh
tshark -2 -n -d tcp.port==80,http2 -r testdata/deployments/http2-transactions.pcapng \
  -Y 'http2.streamid > 0' -T fields -e frame.number -e http2.streamid \
  -e http2.header.name -e http2.header.value -e http2.data.data
```

```text
7   1,3  :method,:scheme,:path,:authority,x-tag,x-tag,:method,:scheme  POST,http,/one,trace.example,a,b,POST,http
8   3,1  :path,:authority  /two,trace.example  616c
9   3                                          62657461
10  1                                          616c706861
11  3,3  :status  201                          74776f
12  1    :status  103
13  1,1  :status  200                          6f6e65
14  1    x-end    ok                           6f6e65
```

The request bodies are `alpha` and `beta`. The server returns `201` and `two`
on stream 3 before sending `103`, then `200` and `one`, on stream 1. The
last frame carries the trailer `x-end: ok`. With two-pass dissection, TShark
reports the reassembled entity at completion, including on the trailer frame.

### Reopen the stream 3 export

`ExtractHTTP2TransactionPCAPNG` for the request at packet 6, TCP payload
offset 50, stream 3, writes nine original frames (one-based frame numbers
1, 2, 4–9 and 11). Frames 7–9 and 11 contribute directly to this exchange.
The additional frames supply the TCP opening, preface and SETTINGS. Frame 7
also contains stream 1's indexed authority. Source comments and the synthetic
secrets block are omitted.

Run the same TShark 4.6.10 command on the source and the exported file, here
named `selected.pcapng`.

```sh
for capture in testdata/deployments/http2-transactions.pcapng selected.pcapng; do
  tshark -2 -n -d tcp.port==80,http2 -r "$capture" \
    -Y 'http2.streamid == 3' -T fields -e frame.number -e http2.streamid \
    -e http2.header.name -e http2.header.value -e http2.data.data
done
```

The source yields frames 7, 8, 9 and 11. The export yields frames 6, 7, 8 and
9, with the same decoded fields. Stream 3 has method `POST`, path `/two`,
authority `trace.example`, request DATA `62657461` (`beta`), final status
`201` and response DATA `74776f` (`two`). The shared frames also show stream
1's `/one` headers and DATA `616c`.
