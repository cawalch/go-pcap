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
