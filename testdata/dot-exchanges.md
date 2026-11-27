# Pipelined DNS over TLS

Python 3.13.18 with OpenSSL 3.5.9 generated this TLS 1.3 exchange using a client
and server connected by memory BIOs. Both negotiated the `dot` ALPN. The generator
wrote their ciphertext to synthetic IPv4/TCP packets on port 853. The
capture uses documentation addresses and an ephemeral test certificate.
The key log contains traffic secrets for this fixture.

The client sent two queries before either reply. The server replied to
`two.example` first. The first query's length prefix crosses TLS record
boundaries, and the second TLS record crosses packet boundaries and also
contains the entire second query.

Regenerate from the repository root with Python 3 and OpenSSL. A fresh
handshake changes the TLS ciphertext and secrets.

```sh
fixture_tmp=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=resolver.example -addext subjectAltName=DNS:resolver.example \
  -keyout "$fixture_tmp/key.pem" -out "$fixture_tmp/cert.pem"
python3 testdata/generate_dot.py testdata "$fixture_tmp/cert.pem" "$fixture_tmp/key.pem"
rm "$fixture_tmp/cert.pem" "$fixture_tmp/key.pem"
rmdir "$fixture_tmp"
```

To independently verify the DNS IDs, names, and answers, run TShark as below.
Version 4.6.10 decoded the queries in frame 9, followed by replies in frames
10 and 11. TShark uses one-based frame numbers. The library uses zero-based
packet indices and includes every packet that contributed to a complete
authenticated TLS record.

```sh
tshark -r testdata/dot-exchanges.pcap \
  -o tls.keylog_file:testdata/dot-exchanges.keys -d tcp.port==853,tls \
  -Y dns -T fields -e frame.number -e dns.id -e dns.qry.name -e dns.a
```
