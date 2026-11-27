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

## ChaCha20-Poly1305 comparison

Regenerate `doq-chacha20.pcap` and `doq-chacha20.keys` with the same generator
and certificate. The endpoints verify the selected suite and both DNS
exchanges.

```sh
python3 testdata/generate_doq.py testdata "$fixture_dir/cert.pem" "$fixture_dir/key.pem" --chacha20
tshark -n -o "tls.keylog_file:$PWD/testdata/doq-chacha20.keys" \
  -r testdata/doq-chacha20.pcap -Y 'tls.handshake.type == 2 || dns' -T fields \
  -e frame.number -e tls.handshake.ciphersuite -e quic.stream.stream_id \
  -e dns.qry.name -e dns.a
```

TShark 4.6.10 reports suite `0x1303` on frame 2. It reports the same queries,
stream IDs, and replies as the AES-GCM capture. The query frames are 7 and 8,
and the reply frames are 9 and 10.
