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
