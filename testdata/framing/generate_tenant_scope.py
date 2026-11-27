"""Create one Ethernet mirror fixture with overlapping inner tuples."""

from itertools import zip_longest
from pathlib import Path
from struct import pack
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "deployments"))
import generate as capture


SCOPES = ("plain", "vlan11", "vlan12", "vni201", "vni202")
CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"


def scope_frame(scope, packet, reverse):
    if scope.startswith("vlan"):
        vlan = int(scope[4:])
        return packet[:12] + pack("!4H", 0x88A8, 100, 0x8100, vlan) + packet[12:]
    if scope.startswith("vni"):
        vni = int(scope[3:])
        first, second = "203.0.113.1", "203.0.113.2"
        src, dst = (second, first) if reverse else (first, second)
        header = b"\x08\0\0\0" + vni.to_bytes(3, "big") + b"\0"
        return capture.udp(src, dst, 46000, 4789, header + packet)
    return packet


def tcp_frames(scope):
    conn = capture.TCP(CLIENT, SERVER, 43000, 1000, 2000)
    conn.ports = (43000, 80)
    request = f"GET /{scope} HTTP/1.1\r\nHost: mirror.example\r\n\r\n".encode()
    response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(scope)}\r\n\r\n{scope}".encode()
    for reverse, flags, payload in (
        (False, capture.SYN, b""),
        (True, capture.SYN | capture.ACK, b""),
        (False, capture.ACK, b""),
        (False, capture.PSH | capture.ACK, request),
        (True, capture.PSH | capture.ACK, response),
    ):
        yield scope_frame(scope, conn.send(reverse, flags, payload), reverse)


def dns_fragments(scope, reverse=False):
    if reverse and scope == "vni202":
        return
    name = f"{scope}.mirror.example"
    if reverse:
        ip = f"198.51.100.{21 + SCOPES.index(scope)}"
        raw = capture.udp(SERVER, CLIENT, 53, 53000, capture.dns(name, ip))
    else:
        raw = capture.udp(CLIENT, SERVER, 53000, 53, capture.dns(name))
    ether, ip, datagram = raw[:14], raw[14:34], raw[34:]
    cut = 24
    for offset, fragment in ((0, datagram[:cut]), (cut, datagram[cut:])):
        flags_offset = 0x2000 if offset == 0 else offset // 8
        header = ip[:2] + pack("!3H", 20 + len(fragment), 77, flags_offset) + ip[8:10] + b"\0\0" + ip[12:]
        header = header[:10] + pack("!H", capture.checksum(header)) + header[12:]
        yield scope_frame(scope, ether + header + fragment, reverse)


def tls_frames(scope):
    conn = capture.TCP(CLIENT, SERVER, 43000, 3000, 4000)
    for reverse, flags in ((False, capture.SYN), (True, capture.SYN | capture.ACK), (False, capture.ACK)):
        yield scope_frame(scope, conn.send(reverse, flags), reverse)
    random_byte = 16 + SCOPES.index(scope)
    hello = capture.hello(f"{scope}.mirror.example", "h2", 0x1301, random_byte)
    flags = capture.PSH | capture.ACK
    yield scope_frame(scope, conn.send(False, flags, hello[:6]), False)
    tail = scope_frame(scope, conn.send(False, flags, hello[6:]), False)
    yield tail
    yield tail
    if scope != "vni202":
        hello = capture.hello("", "", 0x1301, random_byte + 16, from_server=True)
        yield scope_frame(scope, conn.send(True, flags, hello), True)


def main():
    frames = [frame for group in zip(*(tcp_frames(scope) for scope in SCOPES)) for frame in group]
    frames.extend(frame for group in zip(*(dns_fragments(scope) for scope in SCOPES)) for frame in group)
    frames.extend(frame for group in zip_longest(*(dns_fragments(scope, True) for scope in SCOPES))
                  for frame in group if frame is not None)
    frames.extend(frame for group in zip_longest(*(tls_frames(scope) for scope in SCOPES))
                  for frame in group if frame is not None)
    capture.OUT = HERE
    capture.write_pcapng("tenant-scope", ["mirror"], [(0, frame, None, b"") for frame in frames])


if __name__ == "__main__":
    main()
