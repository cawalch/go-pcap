# DNS-over-QUIC endpoint reference

Two in-memory aioquic 1.3.0 endpoints negotiate `doq`. The generator asserts
that the server receives both length-framed queries and that the client
receives both expected replies. The second reply completes first. The capture
and key log contain only synthetic example traffic.

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

The capture is 4,569 bytes. The seekable scan reads 9,088 bytes in 43 calls
on both counting memory and real-file inputs, before counting source
opening. The slice scan uses the existing input bytes. Both return two rows
with the same decoded DNS fields and original packet references. The rows
retain decoded messages and packet indices. Authenticated QUIC frame and
stream bytes are transient during the scan.

The two results retain 84 bytes of query and reply question names, IPv4
answer data, and packet indices on a 64-bit Go runtime, or 68 bytes on a
32-bit runtime. This counts logical field content and excludes Go container
overhead, result metadata and transient decoder memory. Both input paths
return identical content.

To exercise an independent resolver client, install dnspython 2.9.2
alongside aioquic 1.3.0 and pass the same temporary certificate and key to the
loopback diagnostic. It starts a temporary DoQ responder, makes two actual
DoQ lookups with dnspython and checks the answers above.

```sh
python3 testdata/check_doq_resolver.py "$fixture_dir/cert.pem" "$fixture_dir/key.pem"
```
