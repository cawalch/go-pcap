# Overlapping tenant scopes

`tenant-scope.pcapng` has 77 synthetic packets on one Ethernet interface.
Five scopes reuse tuples, initial TCP sequences, and IPv4 fragment IDs.
Each has an HTTP exchange, a fragmented DNS query, and a split TLS
ClientHello with a retransmission. VNI 202 omits the DNS reply and TLS
ServerHello. The untagged scope is the control.

Regenerate the fixture and inspect the original frame numbers with TShark
4.6.10 (commit `eac916f07299`). Run these commands from the repository root.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/framing/generate_tenant_scope.py
mirror=testdata/framing/tenant-scope.pcapng
tshark -n -r "$mirror" -T fields -e frame.number -e frame.interface_id \
  -e ieee8021ad.id -e vlan.id -e vxlan.vni -e tcp.srcport -e tcp.dstport \
  -e ip.frag_offset
```

All five HTTP exchanges return 200 and share Community ID
`1:sOt0+JmdXpF66uyTH/7eX/9XeD4=` with seed zero. The unfiltered mirror
reports an HTTP stream overlap conflict and two DNS records.

| Scope | HTTP request and response | DNS query and reply completion | TLS ClientHello segments | TLS ServerHello |
| --- | --- | --- | --- | --- |
| Untagged | 16, 21 | 31, 40 | 59, 64 | 74 |
| VLAN 100/11 | 17, 22 | 32, 41 | 60, 65 | 75 |
| VLAN 100/12 | 18, 23 | 33, 42 | 61, 66 | 76 |
| VNI 201 | 19, 24 | 34, 43 | 62, 67 | 77 |
| VNI 202 | 20, 25 | 35 | 63, 68 | Unobserved |

The table uses one-based frame numbers in the original capture. The scoped
Go results use zero-based packet indices. ClientHello retransmissions on
frames 69–73 add no packet references to the recovered hellos.

TShark assigns new frame numbers after you write each subset. In the first
four subsets it decodes HTTP on frames 4 and 5, DNS on frames 7 and 9, and
TLS hellos on frames 14 and 16. In the VNI 202 subset the DNS query is on
frame 7 and the ClientHello is on frame 12.

```sh
subsets=$(mktemp -d)
while IFS='|' read -r scope filter; do
  tshark -n -r "$mirror" -Y "$filter" -w "$subsets/$scope.pcapng"
  tshark -2 -n -r "$subsets/$scope.pcapng" -Y 'http || dns || tls.handshake' -T fields \
    -e frame.number -e http.request.uri -e http.response.code -e dns.qry.name -e dns.a \
    -e tls.handshake.type -e tls.handshake.extensions_server_name
done <<'FILTERS'
plain|!(ieee8021ad || vxlan)
vlan11|ieee8021ad.id == 100 && vlan.id == 11
vlan12|ieee8021ad.id == 100 && vlan.id == 12
vni201|vxlan.vni == 201
vni202|vxlan.vni == 202
FILTERS
go test -count=1 -run 'TestTenant|ExampleCapture_SelectTenant' .
```
