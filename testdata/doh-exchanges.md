# DNS-over-HTTPS exchanges

[The generator](generate_doh.py) runs hyper-h2 4.3.0 over TLS 1.3 and aioquic
1.3.0 over QUIC. It verifies headers and body bytes received by each peer
before recording the encrypted transfers in PcapNG. The packet headers, DNS
messages, certificate, and key log are synthetic.

Both connections send their requests before the server replies in reverse
stream order. Every DNS ID is zero. The first two responses contain distinct
answers. The fourth sends a DNS prefix with the HTTP stream left open. The
fifth exchange is ordinary HTTP.

| Request | HTTP status | HTTP/2 stream and frame pair | HTTP/3 stream and frame pair |
| --- | --- | --- | --- |
| GET one.example | 200 | 1, 11 and 20 | 0, 30 and 39 |
| POST two.example | 200 | 3, 12 and 19 | 4, 31 and 38 |
| GET error.example | 503 | 5, 13 and 18 | 8, 32 and 37 |
| POST partial.example | 200 | 7, 14 and 17 | 12, 33 and 36 |
| GET /ordinary | 200 | 9, 15 and 16 | 16, 34 and 35 |

TShark 4.6.10 verified the frame pairs above. TShark frame numbers start at
one. The Go packet indices start at zero.

~~~sh
tshark -n -o tls.keylog_file:testdata/doh-exchanges.keys \
  -r testdata/doh-exchanges.pcapng \
  -Y 'http2.headers.method || http2.headers.status || http3.headers.method || http3.headers.status || http2.data.data || http3.data' \
  -T fields -e frame.number -e http2.streamid -e quic.stream.stream_id \
  -e http2.headers.method -e http3.headers.method \
  -e http2.headers.status -e http3.headers.status \
  -e http2.headers.path -e http3.headers.path -e http2.data.data -e http3.data
~~~

To regenerate, install the fixture dependencies and create a test certificate
in a temporary directory. The encrypted bytes and NSS keys vary between runs.

~~~sh
scratch=$(mktemp -d)
python3 -m venv "$scratch/venv"
"$scratch/venv/bin/pip" install 'aioquic==1.3.0' 'h2==4.3.0'
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -days 1 -subj /CN=resolver.example \
  -keyout "$scratch/key.pem" -out "$scratch/cert.pem"
PYTHONDONTWRITEBYTECODE=1 "$scratch/venv/bin/python" testdata/generate_doh.py \
  testdata "$scratch/cert.pem" "$scratch/key.pem"
rm -r "$scratch"
~~~
