"""Generate TLS name and enterprise qualification captures from local fixtures."""

from pathlib import Path
from struct import pack
import ssl
import subprocess
import tempfile
from uuid import UUID

import generate as wire


CLIENT = "192.0.2.15"
SERVER = "198.51.100.82"


def tcp_open(port, service):
    connection = wire.TCP(CLIENT, SERVER, port, 1000, 2000)
    connection.ports = (port, service)
    return connection, [
        connection.send(False, wire.SYN),
        connection.send(True, wire.SYN | wire.ACK),
    ]


def tls_exchange(directory, port, service, name, version, request=b"", keylog=None):
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The fixture intentionally includes a syntactically valid mismatched name.
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(directory / "certificate.pem", directory / "key.pem")
    if keylog:
        client_context.keylog_filename = keylog
    for ctx in (client_context, server_context):
        ctx.minimum_version = version
        ctx.maximum_version = version
    server_context.num_tickets = 0

    incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    endpoints = [
        client_context.wrap_bio(incoming[0], outgoing[0], server_hostname=name),
        server_context.wrap_bio(incoming[1], outgoing[1], server_side=True),
    ]
    connection, frames = tcp_open(port, service)

    def transfer(sender):
        protected = outgoing[sender].read()
        incoming[1 - sender].write(protected)
        for offset in range(0, len(protected), 1200):
            frames.append(connection.send(bool(sender), wire.ACK | wire.PSH, protected[offset:offset + 1200]))

    complete = [False, False]
    for _ in range(16):
        for sender, endpoint in enumerate(endpoints):
            if not complete[sender]:
                try:
                    endpoint.do_handshake()
                    complete[sender] = True
                except ssl.SSLWantReadError:
                    pass
                transfer(sender)
        if all(complete):
            break
    if not all(complete):
        raise RuntimeError("the fixture TLS handshake did not complete")
    if request:
        endpoints[0].write(request)
        transfer(0)
        if endpoints[1].read(len(request)) != request:
            raise RuntimeError("the fixture TLS server received different application bytes")
    return frames


def ber(tag, body):
    length = len(body)
    size = bytes([length]) if length < 128 else bytes([0x81, length])
    return bytes([tag]) + size + body


def kerberos_error():
    def explicit(number, tag, body):
        return ber(0xa0 + number, ber(tag, body))

    realm = b"FIXTURE.EXAMPLE"
    principal = explicit(0, 2, b"\x02") + explicit(1, 48, ber(27, b"krbtgt") + ber(27, realm))
    fields = b"".join((
        explicit(0, 2, b"\x05"), explicit(1, 2, b"\x1e"),
        explicit(4, 24, b"20231114221320Z"), explicit(5, 2, b"\0"),
        explicit(6, 2, b"\x19"), explicit(9, 27, realm), explicit(10, 48, principal),
    ))
    return ber(0x7e, ber(48, fields))


def ldap_bind():
    return ber(48, ber(2, b"\x01") + ber(0x60, ber(2, b"\x03") + ber(4, b"cn=reader") + ber(0x80, b"")))


def rdp_request():
    payload = b"Cookie: mstshash=fixture\r\n" + pack("<BBHI", 1, 0, 8, 1)
    x224 = bytes([6 + len(payload), 0xe0]) + bytes(5) + payload
    return pack("!BBH", 3, 0, 4 + len(x224)) + x224


def rpc_bind():
    interface = UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa").bytes_le
    ndr = UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le
    body = pack("<HHIB3xHBB", 4280, 4280, 0, 1, 0, 1, 0)
    body += interface + pack("<HH", 3, 0) + ndr + pack("<I", 2)
    return bytes.fromhex("05000b0310000000") + pack("<HHI", 16 + len(body), 0, 1) + body


def write(name, frames, blocks=b""):
    wire.write_pcapng(name, ["client"], [(0, frame, None, b"") for frame in frames], extra_blocks=blocks)


def main():
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
            "-subj", "/CN=match.example", "-addext", "subjectAltName=DNS:match.example",
            "-keyout", "key.pem", "-out", "certificate.pem", "-days", "1",
        ], cwd=directory, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        names = []
        for index, (name, version) in enumerate((
            ("match.example", ssl.TLSVersion.TLSv1_2),
            ("different.example", ssl.TLSVersion.TLSv1_2),
            ("opaque.example", ssl.TLSVersion.TLSv1_3),
        )):
            names.extend(tls_exchange(directory, 41000 + index, 443, name, version))
        write("tls-names", names)

        enterprise = [wire.udp(SERVER, CLIENT, 88, 42000, kerberos_error())]
        for index, (service, payload) in enumerate(((3389, rdp_request()), (389, ldap_bind()), (135, rpc_bind()))):
            connection, frames = tcp_open(42001 + index, service)
            enterprise.extend(frames)
            enterprise.append(connection.send(False, wire.PSH | wire.ACK, payload))
        keylog = directory / "fixture.keys"
        enterprise.extend(tls_exchange(directory, 42004, 636, "match.example", ssl.TLSVersion.TLSv1_3, ldap_bind(), keylog))
        keys = keylog.read_bytes()
        dsb = wire.block(0x0a, pack("<2I", 0x544c534b, len(keys)) + wire.pad(keys))
        write("enterprise-qualified", enterprise, dsb)


if __name__ == "__main__":
    main()
