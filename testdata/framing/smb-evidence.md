# SMB command evidence

`smb-evidence.pcapng` contains a synthetic TREE_CONNECT to `\\server\share`
with command 3 and message ID 42 in frame 3. The magic follows a four-byte
NetBIOS prefix. The Go example identifies the opening by packet index 0.

Run these commands from the repository root with Python 3.13.18 and
TShark 4.6.10 (commit `eac916f07299`).

```sh
PYTHONDONTWRITEBYTECODE=1 python3 testdata/framing/generate_smb_evidence.py
tshark -n -r testdata/framing/smb-evidence.pcapng -Y smb2 -T fields \
  -e frame.number -e smb2.cmd -e smb2.msg_id -e smb2.tree
go test -count=1 -run '^ExampleCapture_SMB2EvidenceFromReaderAt$' .
```
