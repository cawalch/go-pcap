# Deployment capture fixtures

[generate.py](generate.py) creates deterministic synthetic traffic with
Python 3.13.18. The inputs use documentation addresses and `.example`
names. Normal Go tests read the checked-in files.
[Tagged workflow fixtures](qualified.md)

Run the generator and tests from the repository root.

```sh
python3 testdata/deployments/generate.py
go test -run '^TestDeploymentCaptures$' -v .
```

## Independent decoder

These observations use TShark 4.6.10 (`eac916f07299`). TShark frame
numbers are one-based. Go packet indices start at zero. From this
directory, list transports and stream IDs.

```sh
for capture in client proxy iot; do
  tshark -n -o tls.keylog_file: -r "$capture.pcapng" -T fields \
    -e frame.number -e frame.interface_name -e frame.cap_len -e frame.len \
    -e ip.src -e ip.dst -e tcp.stream -e udp.stream -e _ws.col.Info
done
```

| Capture | Evidence |
| --- | --- |
| Client, 14 frames | DNS frames 1 and 3 resolve `trace.example` to `198.51.100.80`. TCP streams 0 and 1 reuse a tuple and form Go flow 1 (frames 2, 4–9, 11–14). Frame 13 captures 58 of 76 bytes. Frame 10 is a separate SYN. |
| Proxy, 12 frames | Client-facing TCP frames 1, 3, 5, 7, 9, 11 and origin-facing frames 2, 4, 6, 8, 10, 12. Exporting flow 1 keeps the origin-facing frames and frame 8's synthetic PID `4242` (`fixture-proxy`). |
| IoT, 6 frames | DHCP Discover and Offer in frames 1–2, transaction `0x31514159`. Frames 3 and 5 resolve `collector.example` to `203.0.113.7`. Go flow 3 retains opaque UDP bytes `d391ee0102` and `d391ee0304` from frames 4 and 6. |

| Leg | ClientHello / ServerHello | Offered name and ALPN | Selected suite |
| --- | --- | --- | --- |
| Client | 6 / 7 | `trace.example`, `h2` | TLS 1.3 `0x1301` |
| Proxy client | 7 / 9 | `app.example`, `h2` | TLS 1.3 `0x1301` |
| Proxy origin | 8 / 10 | `origin.example`, `http/1.1` | TLS 1.3 `0x1302` |

The captures have no keys. Negotiated ALPN and certificate chains are
unavailable. Proxy frames 11 and 12 are synthetic opaque TLS records.
[Capture-point guide](../../docs/parsing.md#trace-a-client-connection-and-a-tls-proxy)

## Apple PKTAP process fixture

On macOS, convert the generated input with Apple tcpdump 4.99.1 (Apple
version 161, libpcap 1.10.1). Run from this directory.

```sh
/usr/sbin/tcpdump -nn -r darwin-pktap.pcap -P -w darwin-pktap.pcapng
/usr/sbin/tcpdump -nn -k -r darwin-pktap.pcapng
tshark -n -r darwin-pktap.pcapng -T fields \
  -e frame.number -e frame.darwin.process_info.pid \
  -e frame.darwin.process_info.pname -e frame.darwin.sc \
  -e frame.darwin.flow_id -e frame.darwin.trace_tag
```

Frames 1–2 have PID 16232 and name `fixture-proxy`. Frame 1 also has
effective PID 7447 (`fixture-client`). Frame 3 has no process. Frame 4
has a name and no PID, which TShark displays as raw `4294967295`. The
four source packets contain Ethernet UDP with the same tuple and
test service class 7, flow ID 101, and trace tag 42.

## DNS transaction fixture

```sh
tshark -n -r dns-transactions.pcap -T fields -e frame.number -e dns.id \
  -e dns.qry.name -e dns.flags.rcode -e dns.response_to -e dns.time
```

Four unambiguous pairs take 8 ms, 5 ms, 1.2 s, and 6 ms in query order.
TShark links frame 11 to frame 9. Go reports the pair as ambiguous because
frame 10 repeats the question and ID. [Go diagnostic](../../docs/parsing.md#diagnose-dns-transactions)

## HTTP/1 transaction fixture

```sh
tshark -2 -n -r http1-transactions.pcapng -T fields \
  -e frame.number -e tcp.stream -e tcp.analysis.lost_segment \
  -e http.request.method -e http.request.uri -e http.response.code \
  -e http.request_in -e http.response_in -e http.file_data
```

- Frames 5, 6, and 8 carry `POST /upload` with body `data`. Frame 7 is
  `100 Continue`. Frame 8 also starts `GET /pipelined`.
- Frames 10 and 11 carry the gzip response `upload accepted\n`. Frame 11
  also carries `204 No Content` for the next request.
- Frame 13 opens the reused tuple. Frames 16–17 carry `GET /reused`.
  TShark links frame 20 to `/after-gap`. Go reports ambiguous pairing
  because two requests are pending and a gap hides response framing.

## HTTP/2 frame fixture

```sh
tshark -n -d tcp.port==80,http2 -r http2-frames.pcapng \
  -Y http2.type -T fields -e frame.number -e http2.type -e http2.streamid -e http2.flags
```

Stream 1's request ends in frame 8 with padded DATA `pcap`. Stream 3 uses
its indexed authority. Frames 7 and 8 supply stream 3's HEADERS and
CONTINUATION, and frame 9 ends it with 204. Frame 10 ends stream 1 with
DATA `ok`. [Go frame tests](../../http2_frame_test.go)

## HTTP/2 transaction fixture

```sh
tshark -2 -n -d tcp.port==80,http2 -r http2-transactions.pcapng \
  -Y 'http2.streamid > 0' -T fields -e frame.number -e http2.streamid \
  -e http2.header.name -e http2.header.value -e http2.data.data
```

Frame 7 starts POST requests for streams 1 and 3 at payload offsets 0
and 50. Stream 3 uses stream 1's authority. Request bodies are `alpha`
and `beta`. Stream 3 returns 201 and `two` in frame 11. Stream 1 returns
103, then 200 and `one` in frames 12–13, followed by `x-end: ok`.

### Reopen the stream 3 export

Select the request at packet index 6, offset 50, stream 3. The export keeps
source frames 1, 2, 4–9, and 11 and omits capture comments and secrets.
Reuse the command above with `http2.streamid == 3` on both files. Source
frames 7, 8, 9, and 11 map to output frames 6, 7, 8, and 9. Both show
POST `/two`, authority `trace.example`, body `beta`, status 201, and
response `two`. Shared packets retain some stream 1 bytes.
