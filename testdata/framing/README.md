# Wireless and IPsec framing reference

The hex dumps contain eight synthetic packets with documentation addresses
and no real wireless traffic or IPsec secrets. The repository license covers
the dumps and the merged PcapNG fixture. The ESP body is a fixed byte sequence.

Generate the fixture from this directory with Wireshark tools 4.6.10
(commit `eac916f07299`).

```sh
fixture_tmp=$(mktemp -d)
TZ=UTC text2pcap -q -t ISO -l 105 ieee80211.hex "$fixture_tmp/ieee80211.pcapng"
TZ=UTC text2pcap -q -t ISO -l 127 radiotap.hex "$fixture_tmp/radiotap.pcapng"
TZ=UTC text2pcap -q -t ISO -l 1 ipsec.hex "$fixture_tmp/ipsec.pcapng"
mergecap -a -w "$fixture_tmp/merged.pcapng" "$fixture_tmp/ieee80211.pcapng" \
  "$fixture_tmp/radiotap.pcapng" "$fixture_tmp/ipsec.pcapng"
editcap --discard-capture-comment "$fixture_tmp/merged.pcapng" wireless-ipsec.pcapng
```

The host and tool metadata may vary. The packet bytes, order, and timestamps
come from the dumps. Verify the packet classification with TShark.

```sh
tshark -n -r wireless-ipsec.pcapng -T fields \
  -e frame.number -e frame.cap_len -e frame.protocols \
  -e radiotap.length -e radiotap.flags.datapad -e wlan.fc.type_subtype -e wlan.htc \
  -e llc.type -e dns.qry.name -e esp.spi -e esp.sequence \
  -e udp.srcport -e udp.dstport -e isakmp.version -e isakmp.length
```

| Frame | Reference decode |
| --- | --- |
| 1 | 802.11 Data, LLC EtherType `0x0800`, UDP 53000 → 53, DNS question `wifi.example` |
| 2 | 802.11 four-address QoS Data with HT Control, same DNS question |
| 3 | 25-byte Radiotap with data padding, QoS Data, same DNS question |
| 4 | 300-byte Radiotap with a vendor field, Data, same DNS question |
| 5 and 6 | IPv4 and IPv6 ESP respectively, both with SPI `0x10203040` and sequence 7 |
| 7 | UDP 500 → 53000, IKE version `0x20`, IKE length 36 |
| 8 | UDP 53000 → 4500, Non-ESP Marker, IKE version `0x20`, IKE length 36 |

The Go tests use this capture and checked-in expectations. They require no
external decoder.

## PPP and PFLOG

These captures use synthetic IPv4 SYNs and documentation addresses. Generate
them with Wireshark tools 4.6.10 (commit `eac916f07299`).

```sh
fixture_tmp=$(mktemp -d)
TZ=UTC text2pcap -q -t ISO -l 9 ppp.hex "$fixture_tmp/ppp.pcapng"
TZ=UTC text2pcap -q -t ISO -l 117 pflog.hex "$fixture_tmp/pflog.pcapng"
mergecap -a -w "$fixture_tmp/merged.pcapng" "$fixture_tmp/ppp.pcapng" "$fixture_tmp/pflog.pcapng"
editcap --discard-capture-comment "$fixture_tmp/merged.pcapng" ppp-pflog.pcapng
tshark -n -r ppp-pflog.pcapng -T fields -e frame.number -e frame.protocols \
  -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
```

| Frame | Framing | TCP tuple |
| --- | --- | --- |
| 1 | PPP with address, control and two-byte protocol | 198.51.100.10:50000 → 203.0.113.20:443 |
| 2 | PPP with one-byte protocol | 198.51.100.10:50001 → 203.0.113.20:443 |
| 3 | PFLOG with a 45-byte header rounded to 48 bytes | 198.51.100.10:40000 → 203.0.113.20:8080 |

## Standalone PPPoE and NFLOG

These captures use synthetic IPv4 SYNs and documentation addresses. The NFLOG
TLV headers use little-endian lengths and types. Generate the fixture on a
little-endian host with Wireshark tools 4.6.10 (commit `eac916f07299`).

```sh
fixture_tmp=$(mktemp -d)
TZ=UTC text2pcap -q -t ISO -l 51 pppoe.hex "$fixture_tmp/pppoe.pcapng"
TZ=UTC text2pcap -q -t ISO -l 239 nflog.hex "$fixture_tmp/nflog.pcapng"
mergecap -a -w "$fixture_tmp/merged.pcapng" "$fixture_tmp/pppoe.pcapng" "$fixture_tmp/nflog.pcapng"
editcap --discard-capture-comment "$fixture_tmp/merged.pcapng" pppoe-nflog.pcapng
tshark -n -r pppoe-nflog.pcapng -T fields -e frame.number -e frame.protocols \
  -e tcp.srcport -e tcp.dstport
```

| Frame | TShark protocols | TCP ports |
| --- | --- | --- |
| 1 | `pppoes:ppp:ip:tcp` | 50100 → 443 |
| 2 | `nflog:ip:tcp` | 50101 → 443 |

## IP-in-IP

`ipip.hex` contains synthetic Ethernet TCP SYNs with documentation addresses.
Generate the fixture with Wireshark tools 4.6.10 (commit `eac916f07299`).

```sh
fixture_tmp=$(mktemp -d)
TZ=UTC text2pcap -q -t ISO -l 1 ipip.hex "$fixture_tmp/ipip.pcapng"
editcap --discard-capture-comment "$fixture_tmp/ipip.pcapng" ipip.pcapng
tshark -n -r ipip.pcapng -T fields -e frame.number -e frame.protocols \
  -e tcp.srcport -e tcp.dstport
```

| Frame | TShark protocols | Inner TCP ports |
| --- | --- | --- |
| 1 | `eth:ethertype:ip:ip:tcp` | 40000 → 8080 |
| 2 | `eth:ethertype:ip:ipv6:tcp` | 41000 → 8443 |
| 3 | `eth:ethertype:ipv6:ipv6:tcp` | 41000 → 8443 |

## ICMP quoted packets

`icmp-errors.hex` contains synthetic ICMPv4 and ICMPv6 errors with documentation
addresses. The ICMPv4 error quotes its IPv4 header and eight TCP bytes.
Generate the fixture with Wireshark tools 4.6.10 (commit `eac916f07299`).

```sh
fixture_tmp=$(mktemp -d)
TZ=UTC text2pcap -q -t ISO -l 1 icmp-errors.hex "$fixture_tmp/icmp-errors.pcapng"
editcap --discard-capture-comment "$fixture_tmp/icmp-errors.pcapng" icmp-errors.pcapng
tshark -n -r icmp-errors.pcapng -T fields -e frame.number -e frame.protocols \
  -e tcp.srcport -e tcp.dstport
```

| Frame | TShark protocols | Quoted TCP ports |
| --- | --- | --- |
| 1 | `eth:ethertype:ip:icmp:ip:tcp` | 40000 → 8080 |
| 2 | `eth:ethertype:ipv6:icmpv6:ipv6:tcp` | 41000 → 8443 |

## Fragmented TCP

The generator creates a benign TLS ClientHello in IPv4 and IPv6 TCP segments.
Each address pair has one full two-fragment datagram, one initial fragment
whose tail is absent, and one unfragmented control.

```sh
python3 generate_fragmented_tcp.py
tshark -2 -n -r fragmented-tcp.pcap -o ip.defragment:true -o ipv6.defragment:true \
  -T fields -e frame.number -e ip.reassembled_in -e ipv6.reassembled.in \
  -e tcp.srcport -e tls.handshake.extensions_server_name
```

TShark 4.6.10 (commit `eac916f07299`) reports `fragment.example` on original
frames 2, 4, 6 and 8. Frames 2 and 6 complete fragment reassembly. Frames 3
and 7 lack their tail and have no matching hello. The go-pcap example reports
original TCP fragment packet indices and returns only the controls on frames
4 and 8. Go packet indices are zero-based.
