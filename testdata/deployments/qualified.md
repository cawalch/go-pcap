# Independent reference for tagged workflows

[generate_qualified.py](generate_qualified.py) creates synthetic Ethernet
captures. TLS uses Python 3.13.18 memory endpoints with OpenSSL 3.5.9 and
a temporary `match.example` certificate from OpenSSL 4.1.0. TLS randoms
and certificate bytes can differ when regenerated.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/deployments/generate_qualified.py
```

Run TShark 4.6.10 (`eac916f07299`) from the repository root. Frame numbers
are one-based. Go packet indices start at zero.

## TLS configuration

`tls-names.pcapng` contains no embedded secrets. Each TLS 1.2 connection
exposes the certificate. The TLS 1.3 connection exposes its ClientHello.
The endpoints completed all three exchanges.

```sh
tshark -n -o tls.keylog_file: -r testdata/deployments/tls-names.pcapng \
  -Y 'tls.handshake.type == 1 || tls.handshake.type == 11' -T fields \
  -e frame.number -e tcp.stream -e tls.handshake.extensions_server_name -e x509ce.dNSName
```

| TCP stream | ClientHello frame and SNI | Certificate frame and SAN | Observed comparison |
| --- | --- | --- | --- |
| 0 | 3, `match.example` | 4, `match.example` | true and known |
| 1 | 9, `different.example` | 10, `match.example` | false and known |
| 2 | 16, `opaque.example` | Encrypted | unknown |

The [external tagged tests](../consumer/qualified/README.md) run the
same capture through go-pcap and go-yara. Certificate comparison concerns
the visible name and leaf DNS SAN. Trust decisions require other evidence.

## Enterprise metadata

`enterprise-qualified.pcapng` contains a Kerberos UDP error, RDP request,
LDAP Bind, DCE/RPC Bind and LDAPS Bind. The generator embeds test-only
secrets for LDAPS. The TLS server endpoint checks that the decrypted
application message matches the request the client sent.

```sh
tshark -n -o tls.keylog_file: -r testdata/deployments/enterprise-qualified.pcapng \
  -Y 'kerberos || rdp || ldap || dcerpc' -T fields \
  -e frame.number -e kerberos.error_code -e kerberos.realm -e rdp.rt_cookie \
  -e rdp.negReq.requestedProtocols -e ldap.name -e dcerpc.cn_bind_to_uuid
```

| Source frame | Protocol | Observed evidence |
| --- | --- | --- |
| 1 | Kerberos UDP | Error code 25 and service realm `FIXTURE.EXAMPLE` |
| 4 | RDP request | Cookie `mstshash=fixture` and TLS requested |
| 7 | LDAP Bind | Name `cn=reader` |
| 10 | DCE/RPC Bind | Interface `e1af8308-5d1f-11c9-91a4-08002b14a0fa` |
| 19 | LDAPS Bind | Name `cn=reader`, decodable with the embedded keys |

The Go test also uses a capture snapshot with its secrets cleared.
That snapshot produces zero LDAPS requests. The 7,072-byte capture is
checked from a byte slice for Kerberos and RDP, and from both a byte
slice and a seekable file for the other protocols. Including open, the
seekable scan reads 4,745 bytes in 148 calls for LDAP and 7,810 bytes in
152 calls each for DCE/RPC and LDAPS.

## DNS and HTTP

See the [DNS retry](README.md#dns-transaction-fixture) and
[HTTP/1 gap](README.md#http1-transaction-fixture) controls for cases where
the independent decoder pairs frames differently.

## Recheck the existing keyed QUIC captures

The v1 and v2 captures record synthetic aioquic 1.3.0 endpoints. The
capture has no embedded keys. The key-log entries are in the checked-in
vector file. The command below assembles the two directional test entries
per version in a temporary directory. TShark emits client STREAM data on
frame 6 with packet number 5, and server STREAM data on frame 7 with packet
number 3. The decoded data is `fixture-version_1-client` and
`fixture-version_1-server`, with corresponding `version_2` names.

```sh
python3 - <<'PY'
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

vectors = json.loads(Path("testdata/quic-1rtt-vectors.json").read_text())
with TemporaryDirectory() as temp:
    keylog = Path(temp, "fixture.keys")
    for version in (1, 2):
        prefix = f"version_{version}-"
        keylog.write_text("\n".join(v["key_log"] for v in vectors if v["name"].startswith(prefix)))
        subprocess.run([
            "tshark", "-n", "-o", f"tls.keylog_file:{keylog}",
            "-r", f"testdata/quic-1rtt-v{version}.pcap", "-Y", "quic.stream_data",
            "-T", "fields", "-e", "frame.number", "-e", "quic.packet_number", "-e", "quic.stream_data",
        ], check=True)
PY
```
