# QUIC 1-RTT key-update reference

The capture contains a handshake and small transfers between two in-memory
aioquic 1.3.0 endpoints. The client uses the endpoint API to request two key
updates and waits for peer acknowledgements. The server independently receives
the three stream messages. The generator reorders a previously sent packet in
the recorded file and inserts one damaged copy of the first update. The key
log contains synthetic connection secrets only.

Use Python with aioquic 1.3.0 installed to regenerate the capture. Run these
commands from the repository root, pointing at a temporary certificate and key.

```sh
fixture_dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=fixture.example \
  -keyout "$fixture_dir/key.pem" -out "$fixture_dir/cert.pem"
python3 testdata/generate_quic_key_updates.py testdata \
  "$fixture_dir/cert.pem" "$fixture_dir/key.pem"
tshark -n -o "tls.keylog_file:$PWD/testdata/quic-key-updates.keys" \
  -r testdata/quic-key-updates.pcap -T fields -e frame.number \
  -e quic.packet_number -e quic.key_phase -e quic.stream_data
```

TShark 4.6.10 reports client stream data on frames 8, 10 and 11 carrying
`generation-one`, `generation-zero` and `generation-two`, in capture order.
Their packet numbers are 6, 5 and 7. Frame 7 is the damaged observation of
packet number 6 and contains no authenticated data. Go packet indices are
zero-based. Tests also omit the entire first observed client update and
verify that the later client generation remains unavailable. A separate test
exercises the exact update limit for QUIC v1 and v2.
