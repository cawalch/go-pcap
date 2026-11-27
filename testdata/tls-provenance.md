# TLS record provenance reference

The fixtures use public or synthetic keys in PcapNG Decryption Secrets
Blocks. Run TShark 4.6.10 (`eac916f07299`) from the repository root.
TShark reports one-based frames. Go packet indices start at zero.

`rfc8448-0rtt.pcapng` uses [RFC 8448 test secrets](https://www.rfc-editor.org/rfc/rfc8448#section-4).
The records in frames 2, 7, and 8 have wire ranges `[517,545)` and
`[629,701)` for the client and `[203,275)` for the server. The first
record authenticates six client early-data bytes. This leaves server
acceptance unknown. The next two records each recover 50 bytes.

```sh
tshark -n -o tls.keylog_file: -r testdata/rfc8448-0rtt.pcapng \
  -Y 'tls.record.content_type == 23' -T fields \
  -e frame.number -e ip.src -e tcp.seq -e tcp.len -e tls.record.length
tshark -n -o tls.keylog_file: -r testdata/rfc8448-0rtt.pcapng -q -z follow,tls,raw,0
go test -run '^TestTLSRecordProvenance' .
```

## HTTP/2 over TLS

In `keyed-http2.pcapng`, the requests share a record, upload DATA crosses
two records, and the response trailer crosses a packet boundary.

```sh
tshark -2 -n -o tls.keylog_file: -r testdata/keyed-http2.pcapng \
  -Y 'http2.streamid > 0' -T fields -e frame.number -e http2.streamid \
  -e http2.header.name -e http2.header.value -e http2.data.data
go test -run '^TestKeyedHTTP2' .
```

| Frame | Streams | Evidence |
| --- | --- | --- |
| 8 | 1, 3 | POST `/one`, GET `/two`, authority `test` |
| 10 | 1 | `upload` |
| 11 | 3, 1 | 204 for stream 3, then 103 and 200 for stream 1 |
| 12, 14 | 1 | `download`, then trailer `x-end: ok` |

## Export a keyed HTTP/2 exchange

The [Go example](../extract_keyed_http2_test.go) shows selection and
reopening. Export stream 3 from `keyed-http2-export.pcapng` and set
`selected` to the output path. The export keeps source frames 1–12,
including stream 1's indexed authority and a shared response record.
Frame 13, which completes stream 1, is omitted.

Use a fresh profile so only the supplied test key log can decrypt the
export. Reuse the fields from the previous section to compare both files.

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
tshark -n -o tls.keylog_file: -r "$selected" -Y http2 -T fields -e frame.number
```

Both files show stream 3's GET `/two` in frame 9, status 200 in frame 10,
and body `reply` in frames 11–12. The last command emits no HTTP/2 frames.

## Pipelined HTTP/1 over TLS

`keyed-http1.pcapng` (TLS 1.2) and `keyed-http1-tls13.pcapng` decode to the
same requests and responses. Frame 6 contains `/first` and `/second` at
plaintext offsets 0 and 46. Frame 7 contains 103 and 204. The final 201
response spans records in frames 8, 9–10, and 11 with body `reply`.

```sh
go test -run '^TestKeyedHTTP1|^ExampleCapture_KeyedHTTP1' .
for capture in testdata/keyed-http1.pcapng testdata/keyed-http1-tls13.pcapng; do
  tshark -n -o tls.keylog_file: -r "$capture" -Y http -T fields \
    -e frame.number -e http.request.uri -e http.response.code -e http.file_data
done
```

## Packet-only export across a TLS 1.3 KeyUpdate

Use a fresh profile as above. Export the second transaction and supply the
source's test secrets separately.

```sh
source_capture=testdata/keyed-http1-export.pcapng
selected="$proofdir/selected.pcapng"
go run ./examples/keyed-http1-export "$source_capture" /second > "$selected"
editcap --extract-secrets "$source_capture" "$proofdir/test.keys"
for capture in "$source_capture" "$selected"; do
  tshark -n -o "tls.keylog_file:$proofdir/test.keys" -r "$capture" \
    -Y 'http || tls.handshake.type == 24' -T fields -e frame.number \
    -e http.request.uri -e http.response.code -e http.file_data -e tls.handshake.type
done
tshark -n -o tls.keylog_file: -r "$selected" -Y http -T fields -e frame.number
```

| Evidence | Source frame | Exported frame |
| --- | --- | --- |
| GET `/first` and `/second` | 7 | 6 |
| 103 and 204 | 8 | 7 |
| KeyUpdate | 9 | 8 |
| 201 and body `reply` | 13 | 11 |
| GET `/later` | 14 | Absent |

The last command emits no HTTP frames. `TestExtractKeyedHTTP1Epoch` checks
packet bytes, options, and replay with separate keys.
