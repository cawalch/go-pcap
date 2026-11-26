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
