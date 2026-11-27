# TLS reference captures

## TLS 1.2 AES-CBC

`tls12-cbc.pcapng` holds eight OpenSSL 4.1.0 loopback handshakes. Each request
is `GET /response HTTP/1.0` with host `example.test`. Each response has status
200, a content length of 11, and body `cbc fixture`. The capture includes the
fixture connections' `CLIENT_RANDOM` lines in a TLS Decryption Secrets Block.

The generator used temporary self-signed RSA-2048 and P-256 certificates and
a static response file, then ran the following commands for each suite.
`SUITE` is the OpenSSL cipher name in the table.

```sh
printf 'HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\ncbc fixture' > response
openssl s_server -quiet -HTTP -naccept 1 -tls1_2 -no_ticket \
  -accept 127.0.0.1:8443 -cert fixture.crt -key fixture.key \
  -cipher "$SUITE:@SECLEVEL=0"
printf 'GET /response HTTP/1.0\r\nHost: example.test\r\n\r\n' |
  openssl s_client -quiet -tls1_2 -no_ticket -keylogfile fixture.keys \
    -connect 127.0.0.1:8443 -cipher "$SUITE:@SECLEVEL=0"
```

Run the server and client in separate processes. For MAC-then-encrypt rows
add `-no_etm` at both ends. The fixture records the TLS bytes relayed between
the two loopback sockets and wraps them in synthetic Ethernet, IPv4, and TCP
headers. Client ports start at 40000, the server port is 443, and the IP
addresses are 192.0.2.1 and 198.51.100.2. The TCP bytes retain their direction
and order. Convert the classic PCAP and embed the combined key log with
`editcap --inject-secrets tls,fixture.keys fixture.pcap tls12-cbc.pcapng`.

| Stream | OpenSSL cipher | TLS suite ID | Record layout |
| --- | --- | --- | --- |
| 0 | `AES128-SHA` | `0x002f` | Encrypt then MAC |
| 1 | `AES256-SHA` | `0x0035` | MAC then encrypt |
| 2 | `AES256-SHA256` | `0x003d` | Encrypt then MAC |
| 3 | `ECDHE-ECDSA-AES128-SHA` | `0xc009` | MAC then encrypt |
| 4 | `ECDHE-RSA-AES128-SHA` | `0xc013` | Encrypt then MAC |
| 5 | `ECDHE-RSA-AES256-SHA` | `0xc014` | MAC then encrypt |
| 6 | `ECDHE-RSA-AES128-SHA256` | `0xc027` | MAC then encrypt |
| 7 | `ECDHE-ECDSA-AES256-SHA384` | `0xc024` | Encrypt then MAC |

TShark 4.6.10 (commit `eac916f07299`) reports ServerHello extension 22 on each
encrypt-then-MAC connection. It decrypts `/response` and its 200 response in
all eight streams.

```sh
tshark -n -r tls12-cbc.pcapng \
  -Y 'tls.handshake.type == 2 || http.request || http.response' -T fields \
  -e tcp.stream -e tls.handshake.ciphersuite -e tls.handshake.extension.type \
  -e http.request.uri -e http.response.code
```

## TLS AES-GCM and ChaCha20-Poly1305

`cipher-coverage.pcapng` holds four OpenSSL 4.1.0 loopback exchanges.
The relay retains the original TLS byte order and wraps the records in
synthetic Ethernet, IP and TCP headers. Test-only secrets are embedded in
a Decryption Secrets Block. The OpenSSL client requests `/response` and
receives status 200 with body `cipher fixture` in all four exchanges.

Regenerate the fixture with OpenSSL 4.1.0 and Python 3.13.18. TLS randoms and
TCP segmentation can change between generations.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/tls/generate-cipher-coverage.py
```

TShark 4.6.10 (commit `eac916f07299`) reports the following frame numbers
in the checked-in fixture.

| TLS version | Selected cipher | ServerHello frame | Request frame | Response frame |
| --- | --- | --- | --- | --- |
| 1.2 | ECDHE_RSA with AES-128-GCM (`0xc02f`) | 4 | 7 | 8 |
| 1.2 | ECDHE_RSA with ChaCha20-Poly1305 (`0xcca8`) | 13 | 16 | 17 |
| 1.3 | AES-128-GCM (`0x1301`) | 24 | 26 | 27 |
| 1.3 | ChaCha20-Poly1305 (`0x1303`) | 34 | 36 | 37 |

```sh
tshark -n -o tls.keylog_file: -r testdata/tls/cipher-coverage.pcapng \
  -Y 'tls.handshake.type == 2 || http.request || http.response' -T fields \
  -e frame.number -e tcp.stream -e tls.handshake.ciphersuite \
  -e http.request.uri -e http.response.code -e http.file_data
go test -count=1 -run '^TestTLS12AndTLS13CipherCoverage$' .
```

The Go test checks all four observed cipher IDs and finds a matching
secret for each exchange. It recovers the two AES-GCM transactions when
their secrets are available and verifies the direct decryptors' errors for
the ChaCha20 suites. Without the secrets, capture analysis returns no
application transactions.
