"""Record four local OpenSSL exchanges with synthetic packet headers."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from struct import pack
import re
import select
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "deployments"))
import generate as capture


REQUEST = b"GET /response HTTP/1.0\r\nHost: example.test\r\n\r\n"
RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Length: 14\r\n\r\ncipher fixture"
CASES = (
    ("-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"),
    ("-tls1_2", "-cipher", "ECDHE-RSA-CHACHA20-POLY1305"),
    ("-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256"),
    ("-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"),
)


def server_port(server):
    deadline = time.monotonic() + 5
    output = bytearray()
    while time.monotonic() < deadline:
        if not select.select([server.stdout], [], [], deadline - time.monotonic())[0]:
            break
        chunk = server.stdout.read1()
        if not chunk:
            break
        output.extend(chunk)
        if match := re.search(rb"ACCEPT 127\.0\.0\.1:(\d+)\n", output):
            return int(match[1])
    raise RuntimeError(f"OpenSSL server did not start: {bytes(output)!r}")


def exchange(directory, options, connection):
    server = subprocess.Popen(
        ["openssl", "s_server", "-accept", "127.0.0.1:0", "-HTTP", "-naccept", "1",
         "-cert", "cert.pem", "-key", "key.pem", "-no_ticket", "-num_tickets", "0", *options],
        cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    frames = [connection.send(False, capture.SYN), connection.send(True, capture.SYN | capture.ACK)]
    try:
        with socket.create_server(("127.0.0.1", 0)) as listener, ThreadPoolExecutor(1) as workers:
            listener.settimeout(5)
            upstream = server_port(server)
            port = listener.getsockname()[1]
            endpoint = workers.submit(
                subprocess.run,
                ["openssl", "s_client", "-quiet", "-connect", f"127.0.0.1:{port}",
                 "-servername", "example.test", "-keylogfile", "fixture.keys", *options],
                input=REQUEST, capture_output=True, cwd=directory, check=True, timeout=10,
            )
            client, _ = listener.accept()
            with client, socket.create_connection(("127.0.0.1", upstream), timeout=5) as peer:
                while True:
                    readable, _, _ = select.select([peer, client], [], [], 5)
                    if not readable:
                        raise TimeoutError("TLS relay idle")
                    done = False
                    for source in readable:
                        wire = source.recv(1200)
                        if not wire:
                            done = True
                            break
                        from_server = source is peer
                        frames.append(connection.send(from_server, capture.PSH | capture.ACK, wire))
                        (client if from_server else peer).sendall(wire)
                    if done:
                        break
            if b"cipher fixture" not in endpoint.result().stdout:
                raise RuntimeError("OpenSSL client did not receive the expected response")
        server.wait(timeout=5)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
        server.stdout.close()
    return frames


def main():
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        (directory / "response").write_bytes(RESPONSE)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
             "-subj", "/CN=example.test", "-out", "cert.pem", "-keyout", "key.pem", "-days", "1"],
            cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
        frames = []
        for index, options in enumerate(CASES):
            conn = capture.TCP("192.0.2.1", "198.51.100.2", 40000 + index, 1, 100)
            frames.extend(exchange(directory, options, conn))
        keys = (directory / "fixture.keys").read_bytes()
    dsb = capture.block(0x0A, pack("<2I", 0x544C534B, len(keys)) + capture.pad(keys))
    capture.OUT = HERE
    capture.write_pcapng("cipher-coverage", ["synthetic-openssl"],
                         [(0, frame, None, b"") for frame in frames], extra_blocks=dsb)


if __name__ == "__main__":
    main()
