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
