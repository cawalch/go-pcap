"""Generate synthetic TLS HTTP/2 and QUIC HTTP/3 DoH observations."""

from base64 import urlsafe_b64encode
from io import StringIO
from pathlib import Path
import ssl
import sys

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import CipherSuite
from h2.config import H2Configuration
from h2.connection import H2Connection

from deployments import generate as wire


MEDIA = b"application/dns-message"
CLIENT, SERVER = "192.0.2.1", "198.51.100.2"


def dns(name, address=None):
    # Reuse the fixture encoder, with RFC 8484's recommended ID of zero.
    return b"\0\0" + wire.dns(name, address)[2:]


def fixture_exchanges():
    for method, label, status, address in [
        (b"GET", "one", b"200", "192.0.2.10"),
        (b"POST", "two", b"200", "192.0.2.11"),
        (b"GET", "error", b"503", None),
        (b"POST", "partial", b"200", "192.0.2.12"),
        (b"GET", "ordinary", b"200", None),
    ]:
        name = label + ".example"
        query = dns(name)
        path = b"/dns-query"
        if label == "ordinary":
            path = b"/ordinary"
        elif method == b"GET":
            path += b"?dns=" + urlsafe_b64encode(query).rstrip(b"=")
        request = [
            (b":method", method), (b":scheme", b"https"),
            (b":authority", b"resolver.example"), (b":path", path),
        ]
        if method == b"POST":
            request.append((b"content-type", MEDIA))
        response = [(b":status", status)]
        answer = None
        if address is not None:
            response.append((b"content-type", MEDIA))
            answer = dns(name, address)
        yield request, query if method == b"POST" else None, response, answer, label == "partial"


def collect(events, stream):
    headers, data = [], b""
    for event in events:
        if getattr(event, "stream_id", None) == stream:
            headers.extend(getattr(event, "headers", ()))
            data += getattr(event, "data", b"")
    return headers, data


def exercise(client, server, send, send_headers, send_data, stream_ids):
    exchanges = dict(zip(stream_ids, fixture_exchanges()))
    # All requests arrive before any final response, which completes in reverse
    # order. Distinct names and identical IDs expose accidental DNS-ID pairing.
    for stream, (headers, body, _, _, _) in exchanges.items():
        send_headers(client, stream, headers, body is None)
        if body is not None:
            send_data(client, stream, body, True)
        assert collect(send(0), stream) == (headers, body or b"")
    for stream in reversed(exchanges):
        _, _, headers, answer, partial = exchanges[stream]
        send_headers(server, stream, headers, answer is None)
        if answer is not None:
            send_data(server, stream, answer[:12] if partial else answer, not partial)
        assert collect(send(1), stream) == (headers, (answer[:12] if partial else answer) or b"")


def http2(cert, key, keylog):
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.keylog_filename = keylog
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    server_context.num_tickets = 0
    for context in (client_context, server_context):
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])
    incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    tls = [
        client_context.wrap_bio(incoming[0], outgoing[0], server_hostname="resolver.example"),
        server_context.wrap_bio(incoming[1], outgoing[1], server_side=True),
    ]
    conn = wire.TCP(CLIENT, SERVER, 45000, 1000, 2000)
    frames = [conn.send(False, wire.SYN), conn.send(True, wire.SYN | wire.ACK)]

    def deliver(side):
        ciphertext = outgoing[side].read()
        incoming[1-side].write(ciphertext)
        for off in range(0, len(ciphertext), 1200):
            frames.append(conn.send(bool(side), wire.ACK | wire.PSH, ciphertext[off:off + 1200]))

    ready = [False, False]
    for _ in range(16):
        for side, endpoint in enumerate(tls):
            if not ready[side]:
                try:
                    endpoint.do_handshake()
                    ready[side] = True
                except ssl.SSLWantReadError:
                    pass
            deliver(side)
        if all(ready):
            break
    assert all(ready) and all(e.selected_alpn_protocol() == "h2" for e in tls)
    peers = [H2Connection(config=H2Configuration(client_side=(side == 0))) for side in range(2)]

    def send(side):
        data = peers[side].data_to_send()
        if not data:
            return []
        tls[side].write(data)
        deliver(side)
        return peers[1-side].receive_data(tls[1-side].read())

    for peer in peers:
        peer.initiate_connection()
    for side in (0, 1, 0):
        send(side)
    exercise(*peers, send, H2Connection.send_headers, H2Connection.send_data, range(1, 10, 2))
    return frames


def http3(cert, key):
    keylog = StringIO()
    config = dict(alpn_protocols=["h3"], cipher_suites=[CipherSuite.AES_128_GCM_SHA256])
    client = QuicConnection(configuration=QuicConfiguration(
        is_client=True, verify_mode=ssl.CERT_NONE, secrets_log_file=keylog, **config,
    ))
    server_config = QuicConfiguration(is_client=False, **config)
    server_config.load_cert_chain(cert, key)
    addresses = [(CLIENT, 45001), (SERVER, 443)]
    now = 1.0
    client.connect(addresses[1], now=now)
    initial = client.datagrams_to_send(now=now)[0][0]
    cid = pull_quic_header(Buffer(data=initial), 8).destination_cid
    server = QuicConnection(configuration=server_config, original_destination_connection_id=cid)
    peers = [client, server]
    frames = [wire.udp(CLIENT, SERVER, addresses[0][1], addresses[1][1], initial)]
    server.receive_datagram(initial, addresses[0], now=now)

    def deliver(side):
        nonlocal now
        now += 0.05
        src, dst = addresses[side], addresses[1-side]
        for packet, _ in peers[side].datagrams_to_send(now=now):
            frames.append(wire.udp(src[0], dst[0], src[1], dst[1], packet))
            peers[1-side].receive_datagram(packet, src, now=now)

    for _ in range(8):
        deliver(1)
        deliver(0)
    assert client.tls.alpn_negotiated == server.tls.alpn_negotiated == "h3"
    http = [H3Connection(p) for p in peers]

    def send(side):
        deliver(side)
        events = []
        while (event := peers[1-side].next_event()) is not None:
            events.extend(http[1-side].handle_event(event))
        return events

    for side in (0, 1, 0, 1):
        send(side)
    exercise(*http, send, H3Connection.send_headers, H3Connection.send_data, range(0, 20, 4))
    return frames, keylog.getvalue()


def main():
    out, cert, key = map(Path, sys.argv[1:])
    keylog = out / "doh-exchanges.keys"
    keylog.unlink(missing_ok=True)
    tcp = http2(cert, key, keylog)
    udp, quic_keys = http3(cert, key)
    with keylog.open("a") as log:
        log.write(quic_keys)
    frames = [(0, frame, None, b"") for frame in tcp + udp]
    wire.OUT = out
    wire.write_pcapng("doh-exchanges", ["mirror"], frames)


if __name__ == "__main__":
    main()
