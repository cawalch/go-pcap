# SMB command evidence

`smb-evidence.pcapng` contains a synthetic direct Ethernet TCP opening and
a TREE_CONNECT request naming `\\server\share`. There are no session secrets.
The request is command 3, message ID 42 and one-based frame 3. Its magic
starts after a four-byte NetBIOS prefix. The example uses zero-based packet
0 as the opening reference.

Run these commands from the repository root with Python 3.13.18 and
TShark 4.6.10 (commit `eac916f07299`).

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/framing/generate_smb_evidence.py
tshark -n -r testdata/framing/smb-evidence.pcapng -Y smb2 -T fields \
  -e frame.number -e smb2.cmd -e smb2.msg_id -e smb2.tree
go test -count=1 -run '^ExampleCapture_SMB2EvidenceFromReaderAt$' .
```
