# Overlapping tenant scopes

`tenant-scope.pcapng` has 35 synthetic packets on one Ethernet interface.
Five scopes share a TCP tuple, starting sequences, and IPv4 fragment ID.
Each has one HTTP exchange and one two-fragment DNS query. The untagged
scope is the control.

Regenerate the fixture and inspect the original frame numbers with TShark
4.6.10 (commit `eac916f07299`). Run these commands from the repository root.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/framing/generate_tenant_scope.py
mirror=testdata/framing/tenant-scope.pcapng
tshark -n -r "$mirror" -T fields -e frame.number -e frame.interface_id \
  -e ieee8021ad.id -e vlan.id -e vxlan.vni -e tcp.srcport -e tcp.dstport \
  -e ip.frag_offset
```

Every scope returns HTTP 200 and uses Community ID
`1:sOt0+JmdXpF66uyTH/7eX/9XeD4=` with seed zero. On the unfiltered input,
interface options still leave overlapping TCP bytes and one DNS record.

| Scope | Original TShark frames | Request URI | DNS question |
| --- | --- | --- | --- |
| Untagged | 1, 6, 11, 16, 21, 26, 31 | `/plain` | `plain.mirror.example` |
| VLAN 100/11 | 2, 7, 12, 17, 22, 27, 32 | `/vlan11` | `vlan11.mirror.example` |
| VLAN 100/12 | 3, 8, 13, 18, 23, 28, 33 | `/vlan12` | `vlan12.mirror.example` |
| VNI 201 | 4, 9, 14, 19, 24, 29, 34 | `/vni201` | `vni201.mirror.example` |
| VNI 202 | 5, 10, 15, 20, 25, 30, 35 | `/vni202` | `vni202.mirror.example` |

Select the raw scope first, then decode each subset with fresh reassembly.
Frames 4, 5 and 7 in each subset carry the request, reply and completed
DNS query respectively. The Go example translates those local records
back to zero-based original packet indices.

```sh
subsets=$(mktemp -d)
while IFS='|' read -r scope filter; do
  tshark -n -r "$mirror" -Y "$filter" -w "$subsets/$scope.pcapng"
  tshark -2 -n -r "$subsets/$scope.pcapng" -Y 'http || dns' -T fields \
    -e frame.number -e http.request.uri -e http.response.code -e http.file_data -e dns.qry.name
done <<'FILTERS'
plain|!(ieee8021ad || vxlan)
vlan11|ieee8021ad.id == 100 && vlan.id == 11
vlan12|ieee8021ad.id == 100 && vlan.id == 12
vni201|vxlan.vni == 201
vni202|vxlan.vni == 202
FILTERS
go test -count=1 -run '^ExampleCapture_HTTP1Transactions_tenantScope$' .
```
