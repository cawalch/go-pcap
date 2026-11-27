"""Generate fragmented TCP ClientHello and unfragmented control packets."""

import ipaddress
import struct
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return ~value & 0xFFFF


def vec(data):
    return struct.pack("!H", len(data)) + data


def hello():
    name = vec(b"fragment.example")
    sni = struct.pack("!H", 0) + vec(vec(b"\0" + name))
    body = b"\x03\x03" + bytes(range(32)) + b"\0"
    body += vec(b"\xc0\x2f") + b"\x01\0" + vec(sni)
    return b"\x16\x03\x01" + vec(b"\x01" + len(body).to_bytes(3, "big") + body)


def packets(v6):
    src = ipaddress.ip_address("2001:db8::1" if v6 else "192.0.2.1").packed
    dst = ipaddress.ip_address("2001:db8::2" if v6 else "198.51.100.2").packed
    ethernet = bytes.fromhex("02000000000202000000000186dd" if v6 else "0200000000020200000000010800")
    for case in range(3):
        sport = (42000 if v6 else 41000) + case
        tcp = struct.pack("!HHIIBBHHH", sport, 443, 100, 200, 0x50, 0x18, 1024, 0, 0) + hello()
        pseudo = src + dst + (struct.pack("!I3xB", len(tcp), 6) if v6 else struct.pack("!BBH", 0, 6, len(tcp)))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        chunks = [(0, False, tcp)] if case == 2 else [(0, True, tcp[:40])]
        if case == 0:
            chunks.append((40, False, tcp[40:]))
        for offset, more, chunk in chunks:
            if v6:
                fragment = struct.pack("!BBHI", 6, 0, offset | more, 50 + case) if case != 2 else b""
                ip = struct.pack("!IHBB", 6 << 28, len(fragment) + len(chunk), 44 if fragment else 6, 64)
                yield ethernet + ip + src + dst + fragment + chunk
            else:
                frag = (0x2000 if more else 0) | (offset // 8)
                ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(chunk), 50 + case, frag, 64, 6, 0) + src + dst
                ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
                yield ethernet + ip + chunk


def main():
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate([*packets(False), *packets(True)]):
        out += struct.pack("<IIII", 1700000000, index * 1000, len(packet), len(packet)) + packet
    Path(__file__).with_name("fragmented-tcp.pcap").write_bytes(out)


if __name__ == "__main__":
    main()
