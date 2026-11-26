# TLS record provenance reference

The existing `rfc8448-0rtt.pcapng` fixture uses the public test secrets from
[RFC 8448, section 4](https://www.rfc-editor.org/rfc/rfc8448#section-4). The
matching key log is embedded in a PcapNG Decryption Secrets Block. Run these
commands from the repository root with TShark 4.6.10 (commit `eac916f07299`).

```sh
tshark --log-level error -n -o tls.keylog_file: -r testdata/rfc8448-0rtt.pcapng \
  -Y 'tls.record.content_type == 23' -T fields \
  -e frame.number -e ip.src -e tcp.seq -e tcp.len -e tls.record.length
```

```text
2	192.0.2.1	518	28	23
7	192.0.2.1	630	72	67
8	192.0.2.2	204	72	67
```

TShark reports one-based frame numbers and relative TCP sequence numbers.
The five-byte TLS header is included in the TCP length. The Go test asserts
zero-based packet indices 1, 6, and 7, with wire intervals `[517, 545)` and
`[629, 701)` for the client and `[203, 275)` for the server.

```sh
tshark --log-level error -n -o tls.keylog_file: -r testdata/rfc8448-0rtt.pcapng \
  -q -z follow,tls,raw,0
```

```text
Node 0: 192.0.2.1:40000
Node 1: 192.0.2.2:443
414243444546
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031
	000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031
```

The first client record holds six bytes of authenticated early data. The next
client record holds 50 bytes at client plaintext offsets `[6, 56)`. The server
record holds 50 bytes at server plaintext offsets `[0, 50)`. Authentication
with the early traffic key leaves server acceptance unknown.

Run the Go checks without TShark using `go test -run '^TestTLSRecordProvenance' .`.
The split-record tests build TLS 1.2 and TLS 1.3 captures in memory with test-only
keys.

## HTTP/2 over TLS

`keyed-http2.pcapng` contains a TLS 1.3 AES-GCM connection with embedded
test keys and negotiated ALPN `h2`. The two requests share a TLS record. The
upload DATA frame spans two records. The response trailer's record spans two
packets. `TestKeyedHTTP2Transactions` reconstructs this file, verifies
the same frame and record relationships for TLS 1.2, and checks slice and
ReaderAt parity. Run `go test -run '^TestKeyedHTTP2' .` for the Go checks.

Run TShark 4.6.10 (commit `eac916f07299`) from the repository root.

```sh
tshark -2 -n -o tls.keylog_file: -r testdata/keyed-http2.pcapng \
  -Y 'http2.streamid > 0' -T fields -e frame.number -e http2.streamid \
  -e http2.header.name -e http2.header.value -e http2.data.data
```

| Frame | Stream IDs | Decoded headers or DATA |
| --- | --- | --- |
| 8 | 1, 3 | POST `/one`, GET `/two`, both with scheme `https` and authority `test` |
| 10 | 1 | `75706c6f6164` (`upload`) |
| 11 | 3, 1, 1 | Status 204, then interim 103 and final 200 |
| 12 | 1 | `646f776e6c6f6164` (`download`) |
| 14 | 1 | Trailer `x-end: ok` and reassembled `download` |

## Export a keyed HTTP/2 exchange

`keyed-http2-export.pcapng` contains 13 original packets and a synthetic TLS
key log. Stream 1 inserts `:authority: test` in one client record. The request
on stream 3 references that entry in a later record. Both responses start in
the same TLS record. The Go tests regenerate the fixture, isolate an opening
that reuses the tuple and stream IDs, and check that truncation at the final
TLS record preserves a partial body.

Export stream 3 using
[the keyed HTTP/2 export example](../docs/parsing.md#export-a-keyed-http2-exchange-as-ciphertext).
The selected file contains source frames 1–12. Use a fresh profile with
TShark 4.6.10 (commit `eac916f07299`). Set `selected` to the exported file.

```sh
proofdir=$(mktemp -d)
mkdir "$proofdir/profile"
export WIRESHARK_CONFIG_DIR="$proofdir/profile"
unset SSLKEYLOGFILE
source_capture=testdata/keyed-http2-export.pcapng
editcap --extract-secrets "$source_capture" "$proofdir/test.keys"
for capture in "$source_capture" "$selected"; do
  tshark -2 -n -o "tls.keylog_file:$proofdir/test.keys" -r "$capture" \
    -Y 'http2.streamid > 0' -T fields -e frame.number -e http2.streamid \
    -e http2.header.name -e http2.header.value -e http2.data.data
done
tshark -2 -n -o tls.keylog_file: -r "$selected" -Y http2 -T fields -e frame.number
```

| Frame | Stream IDs | Expected in both captures |
| --- | --- | --- |
| 8 | 1 | GET `/` and authority `test` |
| 9 | 3 | GET `/two` and authority `test` |
| 10 | 1, 3 | Status 200 for both streams |
| 11–12 | 3 | Body `7265706c79` (`reply`) |

Source frame 13 completes stream 1 and is absent from the export.
The last command emits no HTTP/2 frames. The Go tests also verify the output
has zero Decryption Secrets Blocks.

## Pipelined HTTP/1 over TLS

`keyed-http1.pcapng` contains a synthetic TLS 1.2 AES-GCM exchange and a DSB
holding its test-only master secret. `keyed-http1-tls13.pcapng` uses TLS 1.3
with HTTP/1.1 in EncryptedExtensions and embedded test traffic secrets.
`TestKeyedHTTP1Pipeline` reconstructs both files and checks each record's
wire range, logical application range and
original packet indices. Run both versions without TShark:

```sh
go test -run '^TestKeyedHTTP1|^ExampleCapture_KeyedHTTP1' .
```

With TShark 4.6.10 (commit `eac916f07299`), use the embedded keys to decode
request paths, status codes and the response body. Both captures produce the
same results:

```sh
for capture in testdata/keyed-http1.pcapng testdata/keyed-http1-tls13.pcapng; do
  tshark -n -o tls.keylog_file: -r "$capture" \
    -Y http.request -T fields -e frame.number -e http.request.uri
  tshark -n -o tls.keylog_file: -r "$capture" \
    -Y http.response -T fields -e frame.number -e http.response.code -e http.file_data
done
```

```text
6	/first,/second
7	103,204
11	201	7265706c79
```

Both requests start in the record carried by packet index 5. Their offsets
inside the plaintext record are 0 and 46. The 103 and final 204 share packet
index 6. The 201 response spans three records in packets 7, 8–9, and 10. Its
body is `reply`.

## Packet-only export across a TLS 1.3 KeyUpdate

`keyed-http1-export.pcapng` has two pipelined GET requests, a server KeyUpdate
between the first final response and the second response, a third request
after the selected response, and unrelated TCP and UDP packets. Its test
traffic keys are embedded in a Decryption Secrets Block. The source has
two interfaces, a marked packet comment and capture metadata.
`TestExtractKeyedHTTP1Epoch` reconstructs the fixture, checks the exact
exported packets and options, and reopens the export with its separate keys.

Reproduce the export from the repository root with TShark and Editcap 4.6.10
(commit `eac916f07299`). Use a fresh Wireshark profile.

```sh
proofdir=$(mktemp -d)
mkdir "$proofdir/profile"
export WIRESHARK_CONFIG_DIR="$proofdir/profile"
unset SSLKEYLOGFILE
source_capture=testdata/keyed-http1-export.pcapng
selected="$proofdir/selected.pcapng"
go run ./examples/keyed-http1-export "$source_capture" /second > "$selected"
editcap --extract-secrets "$source_capture" "$proofdir/test.keys"
for capture in "$source_capture" "$selected"; do
  tshark -n -o "tls.keylog_file:$proofdir/test.keys" -r "$capture" -Y http.request \
    -T fields -e frame.number -e http.request.method -e http.request.uri
  tshark -n -o "tls.keylog_file:$proofdir/test.keys" -r "$capture" -Y http.response \
    -T fields -e frame.number -e http.response.code -e http.file_data
  tshark -n -o "tls.keylog_file:$proofdir/test.keys" -r "$capture" -Y 'tls.handshake.type == 24' \
    -T fields -e frame.number -e tls.handshake.type
done
tshark -n -o tls.keylog_file: -r "$selected" -Y http -T fields -e frame.number
```

| Evidence | Source frame and values | Exported frame and values |
| --- | --- | --- |
| Pipelined requests | 7, GET `/first` and GET `/second` | 6, GET `/first` and GET `/second` |
| Informational and first final response | 8, 103 and 204 | 7, 103 and 204 |
| Server KeyUpdate | 9, handshake type 24 | 8, handshake type 24 |
| Second final response | 13, 201 and body `7265706c79` | 11, 201 and body `7265706c79` |
| Later request | 14, GET `/later` | Absent |

The final command emits zero HTTP frames. The second response body decodes to
`reply` with the separate test key log.
