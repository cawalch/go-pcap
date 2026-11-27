"""Build a synthetic tree connect on a local documentation-address flow."""

from pathlib import Path
from struct import pack, pack_into
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "deployments"))
import generate as capture


name = r"\\server\share".encode("utf-16-le")
message = bytearray(72)
message[:4] = b"\xfeSMB"
pack_into("<H", message, 4, 64)
pack_into("<HH", message, 12, 3, 1)
pack_into("<Q", message, 24, 42)
pack_into("<4H", message, 64, 9, 0, 72, len(name))
message.extend(name)
wire = pack("!I", len(message)) + message

flow = capture.TCP("192.0.2.1", "198.51.100.2", 51000, 1000, 2000)
flow.ports = (51000, 445)
frames = [
    flow.send(False, capture.SYN),
    flow.send(True, capture.SYN | capture.ACK),
    flow.send(False, capture.PSH | capture.ACK, wire),
]
capture.OUT = HERE
capture.write_pcapng("smb-evidence", ["client"], [(0, frame, None, b"") for frame in frames])
