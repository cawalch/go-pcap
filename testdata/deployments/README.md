# Deployment capture fixtures

[generate.py](generate.py) builds these PcapNG files byte for byte from fixed,
synthetic inputs with Python 3.13.18. It uses the Python standard library,
documentation IP addresses, `.example` names, and locally administered MAC
addresses. The repository license covers the generator and captures.

Run these commands from the repository root. Normal Go tests use the checked-in
captures and expectations in [deployment_test.go](../../deployment_test.go).
Python and the reference decoder are only needed to regenerate or review them.

```sh
python3 testdata/deployments/generate.py
go test -run '^TestDeploymentCaptures$' -v .
```

## Independent decoder

Reference output comes from TShark 4.6.10 (commit `eac916f07299`) with name
resolution disabled and an empty TLS key log setting. Run the following
commands from this directory.

```sh
for capture in client iot proxy; do
  tshark -n -o tls.keylog_file: -r "$capture.pcapng" -T fields \
    -e frame.number -e frame.interface_name -e frame.cap_len -e frame.len \
    -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.stream \
    -e udp.srcport -e udp.dstport -e udp.stream -e _ws.col.Info
done
for capture in client iot; do
  tshark -n -r "$capture.pcapng" -Y dns -T fields \
    -e frame.number -e dns.id -e dns.flags.response -e dns.flags.rcode \
    -e dns.qry.type -e dns.qry.name -e dns.a
done
for capture in client proxy; do
  tshark -n -o tls.keylog_file: -r "$capture.pcapng" -Y tls -T fields \
    -e frame.number -e tcp.stream -e tls.handshake.type \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.extensions_alpn_str \
    -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite \
    -e tls.record.opaque_type
done
tshark -n -r iot.pcapng -Y dhcp -T fields \
  -e frame.number -e dhcp.option.dhcp -e dhcp.id -e dhcp.hw.mac_addr \
  -e dhcp.ip.your -e dhcp.option.dhcp_server_id -e dhcp.option.ip_address_lease_time
tshark -n -r iot.pcapng -Y 'udp.stream == 3' -T fields \
  -e frame.number -e udp.payload
tshark -n -X 'read_format:MIME Files Format' -r proxy.pcapng -T fields \
  -e pcapng.darwin.process_id -e pcapng.darwin.process_name
```

Frame numbers here are TShark's one-based numbers. Go packet indices start at
zero. The packet counts are 14 for `client`, 12 for `proxy`, and 6 for `iot`.

| Capture | TShark stream membership | go-pcap export selection |
| --- | --- | --- |
| Client | UDP 0 has frames 1 and 3. TCP 0 has frames 2, 4–8. TCP 1 reuses its tuple in frames 9, 11–14. TCP 2 has only frame 10, a SYN. | Flow 1 has frames 2, 4–9, 11–14, the union of TCP streams 0 and 1. Frame 13 has 58 captured bytes and an original length of 76 bytes. |
| Proxy | TCP 0 on `proxy-client` has frames 1, 3, 5, 7, 9, 11. TCP 1 on `proxy-origin` has frames 2, 4, 6, 8, 10, 12. | Flow 1 has the six origin-facing frames. Frame 8 references the synthetic Darwin process entry `4242 fixture-proxy`. The export retains that attribution and remaps the selected interface to index 0. |
| IoT | UDP 0 has frame 1. UDP 1 has frame 2. UDP 2 has frames 3 and 5. UDP 3 has frames 4 and 6. | Flow 3 has opaque UDP payloads `d391ee0102` and `d391ee0304` in frames 4 and 6. |

| Capture | Query and reply frames | Transaction ID | A question | A answer |
| --- | --- | --- | --- | --- |
| Client | 1, 3 | `0x1020` | `trace.example` | `198.51.100.80` |
| IoT | 3, 5 | `0x1020` | `collector.example` | `203.0.113.7` |

Both DNS responses have response code 0. IoT frames 1 and 2 are a DHCP Discover
and Offer for transaction `0x31514159` and MAC `02:00:00:00:00:2a`. Server
`203.0.113.1` offers `203.0.113.42` for 3600 seconds.

| Capture and leg | ClientHello frame | ServerHello frame | ClientHello server name | Offered ALPN | Selected version and cipher |
| --- | --- | --- | --- | --- | --- |
| Client | 6 | 7 | `trace.example` | `h2` | TLS 1.3, `0x1301` |
| Proxy, client facing | 7 | 9 | `app.example` | `h2` | TLS 1.3, `0x1301` |
| Proxy, origin facing | 8 | 10 | `origin.example` | `http/1.1` | TLS 1.3, `0x1302` |

Application-Layer Protocol Negotiation (ALPN) offers appear in each
ClientHello. In these TLS 1.3 examples the negotiated ALPN and certificate
chains are unavailable in the passive view. Proxy frames 11 and 12 have TLS
outer content type 23 and contain synthetic placeholders for opaque records.
The files have no decryption secrets. The tests expect empty negotiated ALPN,
certificate chains, and decrypted proxy streams.

See the [worked troubleshooting example](../../docs/parsing.md#trace-a-client-connection-and-a-tls-proxy)
for capture points and how to correlate the results with logs.
