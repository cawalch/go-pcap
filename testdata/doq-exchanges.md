# DNS-over-QUIC endpoint reference

Synthetic aioquic 1.3.0 endpoints negotiate `doq` and complete two lookups
in reverse reply order. The generator asserts both queries and answers.

Run these commands with aioquic 1.3.0 and a temporary PEM certificate and key.
The other QUIC fixture generator shows how to create the temporary pair.

```sh
python3 testdata/generate_doq.py testdata "$fixture_dir/cert.pem" "$fixture_dir/key.pem"
tshark -n -o "tls.keylog_file:$PWD/testdata/doq-exchanges.keys" \
  -r testdata/doq-exchanges.pcap -T fields -e frame.number \
  -e quic.stream.stream_id -e dns.qry.name -e dns.a \
  -e tls.handshake.extensions_alpn_str
```

TShark 4.6.10 locates the authenticated server selection on frame 2. Stream 0
contains `one.example` on frame 6 and answer `192.0.2.10` on frame 9.
Stream 4 contains `two.example` on frame 7 and answer `192.0.2.11` on frame 8.
Go packet indices are zero-based.

The capture is 4,569 bytes. After open, both seekable sources read 9,088
bytes in 43 calls. The slice scan uses the existing bytes. Both return the
same rows. Retained names, addresses, and packet indices account for 106
bytes on 64-bit Go or 90 bytes on 32-bit Go, excluding container and
transient memory.

With dnspython 2.9.2, run the loopback resolver check using the same
temporary certificate and key.

```sh
python3 testdata/check_doq_resolver.py "$fixture_dir/cert.pem" "$fixture_dir/key.pem"
```
