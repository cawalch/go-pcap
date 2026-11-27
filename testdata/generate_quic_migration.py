"""Generate authenticated DoQ and HTTP/3 address changes with aioquic 1.3.0."""

from io import StringIO
from pathlib import Path
import ssl
import struct
import sys

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import CipherSuite

from deployments import generate as wire


def capture(output, certificate, key, protocol):
    original = ("192.0.2.1", 45678)
    rebound = ("192.0.2.1", 45679)
    migrated = ("198.51.100.1", 45680)
    server_addr = ("192.0.2.2", 853 if protocol == "doq" else 443)
    client_addr, now = original, 1.0
    keys = StringIO()
    settings = dict(alpn_protocols=[protocol], cipher_suites=[CipherSuite.AES_128_GCM_SHA256])
    client = QuicConnection(configuration=QuicConfiguration(
        is_client=True, verify_mode=ssl.CERT_NONE, secrets_log_file=keys, **settings
    ))
    config = QuicConfiguration(is_client=False, **settings)
    config.load_cert_chain(certificate, key)
    client.connect(server_addr, now=now)
    initial = client.datagrams_to_send(now=now)[0][0]
    cid = pull_quic_header(Buffer(data=initial), 8).destination_cid
    server = QuicConnection(configuration=config, original_destination_connection_id=cid)
    packets = [(original, server_addr, initial)]
    server.receive_datagram(initial, original, now=now)

    def send(sender, receiver, src):
        nonlocal now
        now += 0.05
        for data, dst in sender.datagrams_to_send(now=now):
            assert dst in (original, rebound, migrated, server_addr), dst
            packets.append((src, dst, data))
            receiver.receive_datagram(data, src, now=now)

    def settle():
        for _ in range(8):
            send(client, server, client_addr)
            send(server, client, server_addr)

    def events(peer):
        while (event := peer.next_event()) is not None:
            yield event

    def doq(label, address):
        stream = client.get_next_available_stream_id()
        query = b"\0\0" + wire.dns(label)[2:]
        reply = b"\0\0" + wire.dns(label, address)[2:]
        for sender, receiver, src, message in (
            (client, server, client_addr, query), (server, client, server_addr, reply)
        ):
            data = struct.pack("!H", len(message)) + message
            sender.send_stream_data(stream, data, end_stream=True)
            send(sender, receiver, src)
            received = [event for event in events(receiver) if isinstance(event, StreamDataReceived)]
            assert [(event.stream_id, event.data, event.end_stream) for event in received] == [
                (stream, data, True)
            ], received
        settle()

    def h3(label):
        stream = client.get_next_available_stream_id()
        request = [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"fixture.example"), (b":path", b"/" + label),
        ]
        client_http.send_headers(stream, request, end_stream=True)
        send(client, server, client_addr)
        received = [e for event in events(server) for e in server_http.handle_event(event)]
        assert received == [HeadersReceived(request, stream, True)], received
        server_http.send_headers(stream, [(b":status", b"200")])
        server_http.send_data(stream, label, end_stream=True)
        send(server, client, server_addr)
        received = [e for event in events(client) for e in client_http.handle_event(event)]
        assert received == [HeadersReceived([(b":status", b"200")], stream, False),
                            DataReceived(label, stream, True)], received
        settle()

    settle()
    assert client.tls.alpn_negotiated == server.tls.alpn_negotiated == protocol
    if protocol == "doq":
        doq("original.example", "192.0.2.10")
        client_addr = rebound
        doq("rebound.example", "192.0.2.11")
        client.change_connection_id()
        client_addr = migrated
        doq("migrated.example", "192.0.2.12")
    else:
        client_http, server_http = H3Connection(client), H3Connection(server)
        settle()
        h3(b"original")
        client.change_connection_id()
        client_addr = migrated
        h3(b"migrated")

    stem = f"quic-migration-{protocol}"
    with (output / f"{stem}.pcap").open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for i, (src, dst, data) in enumerate(packets):
            ip = wire.udp(src[0], dst[0], src[1], dst[1], data)[14:]
            out.write(struct.pack("<IIII", 1723720305, i * 1000, len(ip), len(ip)) + ip)
    (output / f"{stem}.keys").write_text(keys.getvalue())


if __name__ == "__main__":
    output, cert, key = map(Path, sys.argv[1:])
    for alpn in ("doq", "h3"):
        capture(output, cert, key, alpn)
