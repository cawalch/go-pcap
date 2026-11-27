"""Generate offline QUIC v1 key-update packets with aioquic 1.3.0."""

from io import StringIO
from pathlib import Path
import socket
import ssl
import struct
import sys

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived
from aioquic.quic.packet import QuicProtocolVersion, pull_quic_header
from aioquic.tls import CipherSuite

output, cert, key = map(Path, sys.argv[1:4])
rotate = "--rotate" in sys.argv[4:]
stem = "quic-key-updates-rotated" if rotate else "quic-key-updates"
client_addr = ("192.0.2.1", 45678)
server_addr = ("192.0.2.2", 4433)
settings = dict(
    supported_versions=[QuicProtocolVersion.VERSION_1],
    cipher_suites=[CipherSuite.AES_128_GCM_SHA256],
    alpn_protocols=["fixture"],
)
key_log = StringIO()
client = QuicConnection(configuration=QuicConfiguration(
    is_client=True, verify_mode=ssl.CERT_NONE, secrets_log_file=key_log, **settings
))
server_config = QuicConfiguration(is_client=False, **settings)
server_config.load_cert_chain(cert, key)
now = 1.0
client.connect(server_addr, now=now)
initial = client.datagrams_to_send(now=now)[0][0]
odcid = pull_quic_header(Buffer(data=initial), 8).destination_cid
server = QuicConnection(configuration=server_config, original_destination_connection_id=odcid)
packets = [(client_addr, server_addr, initial)]
server.receive_datagram(initial, client_addr, now=now)


def send(sender, receiver, src, dst):
    for data, _ in sender.datagrams_to_send(now=now):
        packets.append((src, dst, data))
        receiver.receive_datagram(data, src, now=now)


def settle():
    global now
    for _ in range(10):
        now += 0.05
        send(server, client, server_addr, client_addr)
        send(client, server, client_addr, server_addr)


def send_message(message):
    global now
    now += 0.05
    stream = client.get_next_available_stream_id()
    client.send_stream_data(stream, message, end_stream=True)
    first = len(packets)
    send(client, server, client_addr, server_addr)
    assert len(packets) == first + 1
    received = b""
    while (event := server.next_event()) is not None:
        if isinstance(event, StreamDataReceived) and event.stream_id == stream:
            received += event.data
    assert received == message, (received, message)
    return first


settle()
first = send_message(b"generation-zero")
settle()
client.request_key_update()
if rotate:
    client.change_connection_id()
second = send_message(b"generation-one")
settle()
client.request_key_update()
third = send_message(b"generation-two")
settle()
# The endpoints saw their original order. The file also exercises an observed
# delay of an old-generation datagram and a damaged copy of the first update.
src, dst, early = packets[first]
packets.insert(second, (src, dst, packets[second][2][:-1] + bytes([packets[second][2][-1] ^ 1])))
packets.insert(second + 2, packets.pop(first))
print("Original endpoint indices (before perturbing the capture):", first, second, third)
with (output / f"{stem}.pcap").open("wb") as capture:
    capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for i, (src, dst, data) in enumerate(packets):
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 28 + len(data), i, 0, 64, 17, 0,
            socket.inet_aton(src[0]), socket.inet_aton(dst[0]),
        )
        udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(data), 0)
        frame = ip + udp + data
        capture.write(struct.pack("<IIII", 1723720305, i * 1000, len(frame), len(frame)) + frame)
(output / f"{stem}.keys").write_text(key_log.getvalue())
