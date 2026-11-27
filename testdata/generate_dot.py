"""Capture a pipelined DoT exchange from OpenSSL-backed Python TLS endpoints."""

from pathlib import Path
import socket
import ssl
import struct
import sys


def messages(txid, label, address):
    name = bytes([len(label)]) + label + b"\x07example\0"
    question = name + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton(address)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    reply = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
    return tuple(struct.pack("!H", len(data)) + data for data in (query, reply))


class Capture:
    def __init__(self, out):
        self.out = out
        self.seq = [10_000, 20_000]
        self.packets = 0
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))

    def packet(self, side, flags, data=b""):
        a, b = socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2")
        src, dst = (a, b) if side == 0 else (b, a)
        sport, dport = (45678, 853) if side == 0 else (853, 45678)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(data), self.packets,
                         0, 64, 6, 0, src, dst)
        ack = self.seq[1-side] if flags & 0x10 else 0
        tcp = struct.pack("!HHIIBBHHH", sport, dport, self.seq[side], ack, 0x50,
                          flags, 16384, 0, 0)
        frame = ip + tcp + data
        self.out.write(struct.pack("<IIII", 1723720305, self.packets * 1000,
                                   len(frame), len(frame)) + frame)
        self.seq[side] += len(data) + bool(flags & 2)
        self.packets += 1


output, certificate, key = map(Path, sys.argv[1:])
keylog = output / "dot-exchanges.keys"
keylog.unlink(missing_ok=True)
client = ssl.create_default_context(cafile=str(certificate))
client.keylog_filename = str(keylog)
server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server.load_cert_chain(certificate, key)
server.num_tickets = 0
contexts = (client, server)
incoming = (ssl.MemoryBIO(), ssl.MemoryBIO())
outgoing = (ssl.MemoryBIO(), ssl.MemoryBIO())
for ctx in contexts:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["dot"])
peers = (
    client.wrap_bio(incoming[0], outgoing[0], server_hostname="resolver.example"),
    server.wrap_bio(incoming[1], outgoing[1], server_side=True),
)
query1, reply1 = messages(0x101, b"one", "192.0.2.10")
query2, reply2 = messages(0x102, b"two", "192.0.2.11")

with (output / "dot-exchanges.pcap").open("wb") as out:
    capture = Capture(out)
    capture.packet(0, 0x02)
    capture.packet(1, 0x12)
    capture.packet(0, 0x10)

    def send(side, split=0):
        wire = outgoing[side].read()
        if wire:
            if split:
                capture.packet(side, 0x18, wire[:split])
                capture.packet(side, 0x18, wire[split:])
            else:
                capture.packet(side, 0x18, wire)
            incoming[1-side].write(wire)

    finished = [False, False]
    for _ in range(10):
        for side, peer in enumerate(peers):
            if finished[side]:
                continue
            try:
                peer.do_handshake()
            except ssl.SSLWantReadError:
                pass
            else:
                finished[side] = True
            send(side)
        if all(finished):
            break
    assert all(finished)
    assert all(peer.selected_alpn_protocol() == "dot" for peer in peers)

    # Split the first DNS length across two TLS records and split the second
    # record across two TCP packets. The second TLS record also contains query 2.
    for data, split in ((query1[:1], 0), (query1[1:] + query2, 11)):
        assert peers[0].write(data) == len(data)
        send(0, split)
        assert peers[1].read() == data
    for data in (reply2, reply1):
        assert peers[1].write(data) == len(data)
        send(1)
        assert peers[0].read() == data
