"""Build the deployment captures using Python 3 and fixed, synthetic inputs."""

from pathlib import Path
from socket import inet_aton
from struct import pack


OUT = Path(__file__).resolve().parent
MAC_PREFIX = bytes.fromhex("0200000000")
SYN, ACK, PSH, RST = 2, 16, 8, 4


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total ^ 0xFFFF


def frame(src, dst, protocol, segment, checksum_offset):
    addresses = inet_aton(src) + inet_aton(dst)
    pseudo_header = addresses + pack("!BBH", 0, protocol, len(segment))
    check = checksum(pseudo_header + segment) or 0xFFFF
    segment = segment[:checksum_offset] + pack("!H", check) + segment[checksum_offset + 2:]
    header = pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0x4000, 64, protocol, 0)
    header += addresses
    src_mac = MAC_PREFIX + bytes([addresses[3] or 42])
    dst_mac = bytes.fromhex("ffffffffffff") if dst == "255.255.255.255" else MAC_PREFIX + addresses[7:]
    return dst_mac + src_mac + b"\x08\x00" + header[:10] + pack("!H", checksum(header)) + header[12:] + segment


def udp(src, dst, sport, dport, data):
    return frame(src, dst, 17, pack("!4H", sport, dport, 8 + len(data), 0) + data, 6)


class TCP:
    def __init__(self, client, server, port, client_seq, server_seq):
        self.addresses = (client, server)
        self.ports = (port, 443)
        self.seq = [client_seq, server_seq]

    def send(self, from_server, flags, data=b""):
        src, dst = int(from_server), int(not from_server)
        ack = self.seq[dst] if flags & ACK else 0
        header = pack("!2H2I2B3H", self.ports[src], self.ports[dst], self.seq[src],
                      ack, 0x50, flags, 65535, 0, 0)
        self.seq[src] += len(data) + bool(flags & SYN)
        return frame(self.addresses[src], self.addresses[dst], 6, header + data, 16)


def dns(name, ip=None):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    question = labels + b"\0" + pack("!2H", 1, 1)
    if ip is None:
        return pack("!6H", 0x1020, 0x0100, 1, 0, 0, 0) + question
    answer = pack("!3HIH", 0xC00C, 1, 1, 300, 4) + inet_aton(ip)
    return pack("!6H", 0x1020, 0x8180, 1, 1, 0, 0) + question + answer


def dhcp(offer):
    hardware = MAC_PREFIX + bytes([42])
    assigned = inet_aton("203.0.113.42") if offer else bytes(4)
    fixed = pack("!4BI2H4s4s8x16s192x", 2 if offer else 1, 1, 6, 0,
                 0x31514159, 0, 0x8000, bytes(4), assigned, hardware)
    options = bytes.fromhex("3501023604cb007101330400000e10ff" if offer else "350101ff")
    return fixed + bytes.fromhex("63825363") + options


def extension(kind, data):
    return pack("!2H", kind, len(data)) + data


def tls_record(kind, data):
    return pack("!B2H", kind, 0x0303, len(data)) + data


def hello(sni, alpn, cipher, random_byte, from_server=False):
    common = pack("!H", 0x0303) + bytes([random_byte]) * 32 + b"\0"
    # Fixed public key bytes are only used to give the key-share vector its wire shape.
    share = pack("!2H", 29, 32) + bytes([random_byte + 1]) * 32
    if from_server:
        body = common + pack("!HB", cipher, 0)
        extensions = extension(43, pack("!H", 0x0304)) + extension(51, share)
    else:
        sni, alpn = sni.encode(), alpn.encode()
        body = common + pack("!2H2B", 2, cipher, 1, 0)
        extensions = b"".join([
            extension(0, pack("!HBH", len(sni) + 3, 0, len(sni)) + sni),
            extension(16, pack("!HB", len(alpn) + 1, len(alpn)) + alpn),
            extension(43, pack("!BH", 2, 0x0304)),
            extension(10, pack("!2H", 2, 29)),
            extension(13, pack("!2H", 2, 0x0804)),
            extension(51, pack("!H", len(share)) + share),
        ])
    body += pack("!H", len(extensions)) + extensions
    return tls_record(22, bytes([2 if from_server else 1]) + len(body).to_bytes(3, "big") + body)


def pad(data):
    return data + bytes(-len(data) % 4)


def option(kind, data):
    return pack("<2H", kind, len(data)) + pad(data)


def block(kind, body):
    length = 12 + len(body)
    return pack("<2I", kind, length) + body + pack("<I", length)


def write_pcapng(name, interfaces, packets, extra_blocks=b""):
    data = block(0x0A0D0D0A, pack("<I2Hq", 0x1A2B3C4D, 1, 0, -1))
    for iface in interfaces:
        data += block(1, pack("<2HI", 1, 0, 262144) + option(2, iface.encode()) + option(0, b""))
    data += extra_blocks
    for number, (interface, frame_data, snap_length, options) in enumerate(packets, 1):
        timestamp_us = 1_700_000_000_000_000 + number * 1_000
        captured = frame_data[:snap_length]
        header = pack("<5I", interface, timestamp_us >> 32, timestamp_us & 0xFFFFFFFF,
                      len(captured), len(frame_data))
        data += block(6, header + pad(captured) + options + option(0, b""))
    (OUT / (name + ".pcapng")).write_bytes(data)


def client():
    client, resolver, origin = "192.0.2.14", "192.0.2.53", "198.51.100.80"
    first = TCP(client, origin, 50000, 1000, 2000)
    reused = TCP(client, origin, 50000, 7000, 8000)
    incomplete = TCP(client, "198.51.100.81", 50001, 3000, 4000)
    hostname = "trace.example"
    frames = [
        udp(client, resolver, 53000, 53, dns(hostname)),
        first.send(False, SYN),
        udp(resolver, client, 53, 53000, dns(hostname, origin)),
        first.send(True, SYN | ACK),
        first.send(False, ACK),
        first.send(False, PSH | ACK, hello(hostname, "h2", 0x1301, 1)),
        first.send(True, PSH | ACK, hello("", "", 0x1301, 3, from_server=True)),
        first.send(True, RST | ACK),
        reused.send(False, SYN),
        incomplete.send(False, SYN),
        reused.send(True, SYN | ACK),
        reused.send(False, ACK),
        reused.send(False, PSH | ACK, b"trace diagnostic bytes"),
        reused.send(True, RST | ACK),
    ]
    packets = [(0, data, 58 if number == 13 else None, b"")
               for number, data in enumerate(frames, 1)]
    write_pcapng("client", ["client-before-nat"], packets)


def proxy():
    front = TCP("192.0.2.21", "192.0.2.10", 51000, 1000, 2000)
    back = TCP("198.51.100.10", "198.51.100.90", 52000, 3000, 4000)
    packets = []
    for from_server, flags in [(False, SYN), (True, SYN | ACK), (False, ACK)]:
        packets.extend((i, leg.send(from_server, flags), None, b"")
                       for i, leg in enumerate((front, back)))

    event = block(0x80000001, pack("<I", 4242) + option(2, b"fixture-proxy\0") + option(0, b""))
    process = option(0x8000, pack("<I", 0))
    packets.extend([
        (0, front.send(False, PSH | ACK, hello("app.example", "h2", 0x1301, 5)), None, b""),
        (1, back.send(False, PSH | ACK, hello("origin.example", "http/1.1", 0x1302, 7)), None, process),
        (0, front.send(True, PSH | ACK, hello("", "", 0x1301, 9, from_server=True)), None, b""),
        (1, back.send(True, PSH | ACK, hello("", "", 0x1302, 11, from_server=True)), None, b""),
        # Placeholders for opaque TLS 1.3 records. There is no authentic ciphertext or key log.
        (0, front.send(True, PSH | ACK, tls_record(23, bytes(range(32)))), None, b""),
        (1, back.send(True, PSH | ACK, tls_record(23, bytes(range(32, 64)))), None, b""),
    ])
    write_pcapng("proxy", ["proxy-client", "proxy-origin"], packets, extra_blocks=event)


def iot():
    sensor, gateway, collector = "203.0.113.42", "203.0.113.1", "203.0.113.7"
    broadcast = "255.255.255.255"
    hostname = "collector.example"
    frames = [
        udp("0.0.0.0", broadcast, 68, 67, dhcp(offer=False)),
        udp(gateway, broadcast, 67, 68, dhcp(offer=True)),
        udp(sensor, gateway, 53001, 53, dns(hostname)),
        udp(sensor, collector, 48000, 49555, bytes.fromhex("d391ee0102")),
        udp(gateway, sensor, 53, 53001, dns(hostname, collector)),
        udp(collector, sensor, 49555, 48000, bytes.fromhex("d391ee0304")),
    ]
    write_pcapng("iot", ["iot-local"], [(0, data, None, b"") for data in frames])


def dns_transactions():
    client, resolver = "192.0.2.14", "192.0.2.53"
    trace = bytearray(pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    tcp = TCP(client, resolver, 53000, 1000, 2000)
    tcp.ports = (53000, 53)

    def packet(ms, name, txid, rcode=None, stream=False):
        reply = rcode is not None
        msg = dns(name, "198.51.100.80" if reply and rcode == 0 else None)
        flags = (0x8180 | rcode) if reply else 0x0100
        msg = pack("!2H", txid, flags) + msg[4:]
        if stream:
            data = tcp.send(reply, PSH | ACK, pack("!H", len(msg)) + msg)
        else:
            data = (udp(resolver, client, 53, 53000, msg) if reply else
                    udp(client, resolver, 53000, 53, msg))
        trace.extend(pack("<4I", 1700000000 + ms // 1000, ms % 1000 * 1000, len(data), len(data)))
        trace.extend(data)

    packet(0, "ok.example", 1)
    packet(8, "ok.example", 1, 0)
    packet(10, "missing.example", 1)
    packet(15, "missing.example", 1, 3)
    packet(20, "slow.example", 2, stream=True)
    packet(25, "fast.example", 3, stream=True)
    packet(31, "FAST.example", 3, 0, stream=True)
    packet(1220, "slow.example", 2, 0, stream=True)
    packet(1230, "retry.example", 4)
    packet(1240, "retry.example", 4)
    packet(1250, "retry.example", 4, 0)
    packet(1260, "orphan.example", 5, 2)
    packet(1270, "pending.example", 6)
    (OUT / "dns-transactions.pcap").write_bytes(trace)


if __name__ == "__main__":
    client()
    proxy()
    iot()
    dns_transactions()
