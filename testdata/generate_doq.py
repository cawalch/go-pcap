"""Generate a two-query DNS-over-QUIC capture with aioquic 1.3.0."""

from argparse import ArgumentParser
from io import StringIO
from pathlib import Path
import socket
import ssl
import struct

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import CipherSuite

parser = ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
parser.add_argument("certificate", type=Path)
parser.add_argument("key", type=Path)
parser.add_argument("--chacha20", action="store_true")
args = parser.parse_args()

suite = CipherSuite.CHACHA20_POLY1305_SHA256 if args.chacha20 else CipherSuite.AES_128_GCM_SHA256
stem = "doq-chacha20" if args.chacha20 else "doq-exchanges"
a, b = ("192.0.2.1", 45678), ("192.0.2.2", 853)
settings = dict(alpn_protocols=["doq"], cipher_suites=[suite])
keys = StringIO()
client = QuicConnection(configuration=QuicConfiguration(
    is_client=True, verify_mode=ssl.CERT_NONE, secrets_log_file=keys, **settings
))
config = QuicConfiguration(is_client=False, **settings)
config.load_cert_chain(args.certificate, args.key)
now = 1.0
client.connect(b, now=now)
initial = client.datagrams_to_send(now=now)[0][0]
cid = pull_quic_header(Buffer(data=initial), 8).destination_cid
server = QuicConnection(configuration=config, original_destination_connection_id=cid)
packets = [(a, b, initial)]
server.receive_datagram(initial, a, now=now)


def send(sender, receiver, src, dst):
    for data, _ in sender.datagrams_to_send(now=now):
        packets.append((src, dst, data))
        receiver.receive_datagram(data, src, now=now)


def read_streams(peer):
    out = {}
    while (event := peer.next_event()) is not None:
        if isinstance(event, StreamDataReceived):
            out[event.stream_id] = out.get(event.stream_id, b"") + event.data
    return out


def framed(message):
    return struct.pack("!H", len(message)) + message


def messages(label, address):
    name = bytes([len(label)]) + label + b"\x07example\0"
    question = name + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton(address)
    return (
        framed(struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0) + question),
        framed(struct.pack("!HHHHHH", 0, 0x8180, 1, 1, 0, 0) + question + answer),
    )


for _ in range(10):
    now += 0.05
    send(server, client, b, a)
    send(client, server, a, b)
assert client.tls.alpn_negotiated == server.tls.alpn_negotiated == "doq"
assert client.tls.key_schedule.cipher_suite == server.tls.key_schedule.cipher_suite == suite
requests, replies = {}, {}
for label, address in [(b"one", "192.0.2.10"), (b"two", "192.0.2.11")]:
    stream_id = client.get_next_available_stream_id()
    requests[stream_id], replies[stream_id] = messages(label, address)
    client.send_stream_data(stream_id, requests[stream_id], end_stream=True)
    now += 0.05
    send(client, server, a, b)
assert read_streams(server) == requests
for stream_id in reversed(replies):
    server.send_stream_data(stream_id, replies[stream_id], end_stream=True)
    now += 0.05
    send(server, client, b, a)
assert read_streams(client) == replies

with (args.output / f"{stem}.pcap").open("wb") as out:
    out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for i, (src, dst, data) in enumerate(packets):
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(data), i, 0, 64, 17, 0,
                         socket.inet_aton(src[0]), socket.inet_aton(dst[0]))
        udp = struct.pack("!HHHH", src[1], dst[1], len(data) + 8, 0)
        frame = ip + udp + data
        out.write(struct.pack("<IIII", 1723720305, i * 1000, len(frame), len(frame)) + frame)
(args.output / f"{stem}.keys").write_text(keys.getvalue())
