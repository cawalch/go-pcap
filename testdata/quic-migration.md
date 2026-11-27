# Keyed QUIC address change reference

Synthetic aioquic 1.3.0 endpoints negotiate DNS over QUIC or HTTP/3 with
AES-128-GCM. They exchange application data before and after a client IP
change. The DNS fixture also changes the client port on the original IP
without rotating the connection ID. Each endpoint checks the received
messages. The captures and TLS key logs contain synthetic data.

Before this change, the Go scans recovered two DNS exchanges and one HTTP/3
exchange. Both the slice and ReaderAt APIs now recover three DNS exchanges
and two HTTP/3 exchanges. The server endpoint remains fixed.

To regenerate the references, install aioquic 1.3.0 in a Python environment.
Generate a temporary certificate and key from the repository root.

```sh
fixture_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=fixture.example \
  -keyout "$fixture_dir/key.pem" -out "$fixture_dir/cert.pem"
python3 testdata/generate_quic_migration.py "$fixture_dir" \
  "$fixture_dir/cert.pem" "$fixture_dir/key.pem"
```

Compare a checked-in reference with TShark 4.6.10. Set `alpn` to
`doq` or `h3`.

```sh
alpn=doq
tshark -n -o "tls.keylog_file:$PWD/testdata/quic-migration-$alpn.keys" \
  -r "testdata/quic-migration-$alpn.pcap" -T fields \
  -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport \
  -e quic.connection.number -e quic.packet_number -e quic.dcid \
  -e quic.nci.sequence -e quic.path_challenge.data -e quic.path_response.data \
  -e quic.stream.stream_id -e dns.qry.name -e dns.a \
  -e http3.headers.path -e http3.headers.status -e http3.data
```

TShark attributes the migrated request and reply on frames 14 and 15 to
the original connection. Both destination IDs were issued in frames 4 and 5.
The challenge on frame 15 matches the response on frame 16. In the DNS
capture, frames 10 and 11 use the new client port and the original IDs.
Go packet indices are zero-based.

The Go tests hide issuance and opening packets, reorder observations, and
change the IP header on a copy of a previously observed packet. The scan
cannot establish the new IP if the capture omits issuance of the new
destination IDs. Later packets can still authenticate if issuance was
captured and the packet number and keys remain usable. Coalesced datagrams
on a changed IP and changes to the server endpoint are outside this scope.
The scan does not verify endpoint path validation. A packet whose first
observation has a rewritten IP header can still authenticate.
