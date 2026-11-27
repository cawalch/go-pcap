# FoxIO fingerprint reference fixtures

The Go tests compare with FoxIO's pinned Wireshark and Zeek baselines.
Python dpkt 1.9.8 extracted the offline inputs. [Upstream revision](https://github.com/FoxIO-LLC/ja4/tree/7388fa0dd43f43ba63eabf36b0867b4920f2ca52)

| Fingerprint | Capture under upstream `pcap/` | Input and expected-output source |
| --- | --- | --- |
| JA4 | `sigalg-grease.pcapng` | Frames 4 and 5 concatenate to the ClientHello in `grease-client.tls`. It contains GREASE signature algorithms. Compare with `zeek/testing/Baseline/tests.ja4-tls-grease/output`. |
| JA4S, JA4X | `tls-alpn-h2.pcap` | The first TLS record in frame 6 is `h2-server.tls`. The first DER certificate in the following Certificate message is `h2-leaf.der`. Compare with Wireshark frames 6 and 7, respectively. The ServerHello extensions retain wire order. |
| JA4T, JA4TS | `tls-alpn-h2.pcap` | Window size and TCP option bytes from frames 1 and 2, including the client's two EOL bytes. Compare with Wireshark frames 1 and 2. |
| JA4H | `http1-with-cookies.pcapng`, `http-empty-useragent.pcap` | The test reproduces frame 5 of the first capture and the request in frames 5, 7 and 9 of the second. It uses CRLF line endings for the library's HTTP parser. Compare with Wireshark frames 5 and 9. These cases cover wire-order headers, cookie sorting, and absent cookies and language. |
| JA4L, JA4LS | `latest.pcapng` | Frames 109, 111 and 112 yield SYN-to-SYN-ACK and SYN-ACK-to-ACK deltas of 7,831 and 65 microseconds. Compare with the two-field handshake result in `zeek/testing/Baseline/tests.ja4l-tls/output`. The library reports the TCP handshake measurement. |
| JA4SSH | `ssh.pcapng` | `ssh-window.txt` contains TCP payload lengths for frames 1–200 in file order, positive for client and negative for server. Every packet in this window carries data. Compare with Wireshark frame 200. `JA4SSH` summarizes the caller's window and `Capture.SSH` summarizes its captured flow. |

Wireshark expected fields are under `wireshark/test/testdata/<capture>.json`.
The public certificate and handshake records contain no decryption key log.
See the upstream [capture directory](https://github.com/FoxIO-LLC/ja4/tree/7388fa0dd43f43ba63eabf36b0867b4920f2ca52/pcap),
[Wireshark baselines](https://github.com/FoxIO-LLC/ja4/tree/7388fa0dd43f43ba63eabf36b0867b4920f2ca52/wireshark/test/testdata),
[Zeek baselines](https://github.com/FoxIO-LLC/ja4/tree/7388fa0dd43f43ba63eabf36b0867b4920f2ca52/zeek/testing/Baseline),
[JA4 license](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4), and
[JA4+ license](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE).

The RFC QUIC tests use the published Initial datagrams. The expected JA4
and JA4S strings hash the published cipher and extension lists.
[RFC 9001 Appendix A](https://www.rfc-editor.org/rfc/rfc9001#appendix-A) and
[RFC 9369 Appendix A](https://www.rfc-editor.org/rfc/rfc9369#appendix-A)
