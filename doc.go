// Package pcap reads Portable Packet Capture (PCAP) and PCAP Next Generation
// (PcapNG) files, decodes Layer 2 through Layer 4 (L2–L4) network frames and
// tunnel encapsulations, and extracts flow, cryptographic handshake, and
// application protocol metadata. It uses only the Go standard library.
//
// Use [New] to parse a byte slice, [NewWithLength] to parse a leading stream
// prefix with a known total stream length, [DecompressCapture] to bound-decode
// gzip-compressed captures, or [Open] to read container metadata from a file
// (discarding the file bytes after parsing). Use [NewFromReaderAt] (with
// [Capture.PacketSeqFromReaderAt], [Capture.PacketsFromReaderAt],
// [Capture.PacketPayloadFromReaderAt], [Capture.FlowsFromReaderAt],
// [Capture.DNSFromReaderAt], [Capture.TLSFromReaderAt], and
// [Capture.QUICFromReaderAt]) to read bounded container metadata, packet
// headers, flows, and handshake records from an [io.ReaderAt] without loading
// large captures into memory.
// [New], [NewWithLength], [Open], and [NewFromReaderAt] return a [Capture]
// that retains no reference to the input. Inspect [Capture.FileSize], [Capture.DeclaredExtent],
// [Capture.InputTruncated], and [Capture.Anomalies] to check whether the
// capture is truncated or contains structural anomalies.
//
// Use [NewPCAPWriter] to write classic PCAP captures, [NewPCAPNGWriter] (and
// [PCAPNGWriter.AddInterface], [PCAPNGWriter.WriteDecryptionSecrets],
// [PCAPNGWriter.WriteNameResolution], [PCAPNGWriter.WriteInterfaceStats], and
// [PCAPNGWriter.WritePacket]) to write PcapNG containers, or
// [Capture.ExtractFlowPCAPNG] to carve a single bidirectional flow. Use
// [OpenLive] (with [LiveCapture.Stats], [LiveStats], [BPFFilterTCPPort],
// [BPFFilterUDPPort], [BPFFilterIPProtocol], [BPFFilterIPv4Host], and
// [EvalBPF]) to capture live packets from a network interface using OS-native
// standard-library syscalls.
//
// To enumerate packet records in file order, pass the original bytes to
// [Capture.PacketSeq] (single-pass iterator without slice allocation) or
// [Capture.Packets], and slice individual packet frames with
// [Capture.PacketPayload]. Each [PacketRecord] reports normalized nanosecond
// timestamps, zero-copy payload offsets, and any PcapNG Enhanced Packet Block
// process attribution (process ID, thread ID, user ID, process name, command
// arguments, container ID, flags, and drop counts).
//
// Use [DecodeFrame] to decode Ethernet, 802.1Q/802.1ad VLAN, MPLS, PPPoE, GRE,
// VXLAN, Geneve, Linux SLL/SLL2, BSD Loopback/Null, or Raw IP frames into
// IPv4/IPv6 network headers and TCP/UDP/ICMP transport headers using a
// fixed-size stack layer cursor that performs zero heap allocations.
//
// Use [Capture.Flows] (and [FlowSummary.CommunityID] for TCP/UDP correlation)
// to aggregate deterministic bidirectional 5-tuple flow summaries with
// directional packet and byte counters, unioned TCP flags, client/server
// JA4T/JA4TS and JA4L TCP fingerprints, process attribution, and anomaly flags
// under bounded flow and packet limits.
//
// Use [JA4T], [Frame.JA4T], [JA4L], and [JA4SSH] to compute FoxIO TCP SYN,
// passive distance/latency, and SSH session fingerprints. Use [DefragmentIP]
// to reassemble fragmented IPv4 and IPv6 packet payloads with overlap-conflict
// anomaly detection, and [ReassembleTCP] or [Capture.Streams] to reassemble
// bounded, ordered TCP streams with sequence-gap and overlap-conflict anomaly
// detection.
//
// Use [ParseDNS], [Capture.DNS], [Capture.HasDNSQuery], [DNSLabelEntropy], and
// [Capture.DNSDomainStats] to decode DNS queries (including fragmented UDP DNS
// packets), resource records, RFC 1035 compressed domain names, and per-domain
// DNS tunneling entropy metrics.
//
// Use [ParseTLSRecords], [ParseTLSClientHello], [ParseTLSServerHello],
// [JA4XFromDER], [JA4XFromCert], [Capture.TLS], [Capture.TLSWithKeyLog],
// [Capture.HasTLSJA4], and [Capture.HasTLSSNI] to decode TLS 1.2/1.3
// handshakes, X.509 certificate chains (including DSB-decrypted TLS 1.3 server
// certificates), and FoxIO JA4, JA4S, and JA4X fingerprints.
//
// Use [ParseQUICInitialPacket], [DecryptQUICInitial], [Capture.QUIC],
// [Capture.HasQUICJA4], and [Capture.HasQUICSNI] to derive RFC 9001 (QUIC v1)
// and RFC 9369 (QUIC v2) Initial keys, remove header protection, decrypt and
// reassemble CRYPTO frames across UDP datagrams, and extract the embedded TLS
// 1.3 ClientHello and JA4 fingerprint.
//
// Use [ParseTLSKeyLog], [Capture.TLSKeyLog], [DecryptTLS13Records],
// [DecryptTLS12Records], and [Capture.DecryptedTLSStreams] to decrypt TLS 1.2
// and TLS 1.3 traffic offline using embedded PcapNG Decryption Secrets Blocks
// (DSB) or external SSLKEYLOGFILE material.
//
// Use [ParseHTTPRequest], [ParseHTTPResponse], [Capture.HTTP],
// [ParseHTTP2Frames], and [Capture.HTTP2] to parse HTTP/1.x and HTTP/2 traffic
// (including automatically decrypted TLS 1.2 and TLS 1.3 flows), compute FoxIO
// JA4H and HTTP/2 SETTINGS fingerprints, and carve request/response body and
// DATA frame payloads.
//
// Use [ParseSSHHandshake] and [Capture.SSH] to parse SSH version banners and
// SSH_MSG_KEXINIT key-exchange algorithms and compute HASSH, HASSHServer, and
// JA4SSH fingerprints.
//
// Use [ParseSMB2Message], [ParseNTLMSSP], [Capture.SMB], [ParseKRB5],
// [Capture.Kerberos], [ParseRDPNegotiation], and [Capture.RDP] to decode
// SMB2 share and CREATE names, SMB3 transform headers, SMB dialect and signing
// metadata, NTLMSSP challenge/authenticate
// tokens, Kerberos v5 AS-REQ/TGS-REQ/KRB-ERROR messages (including RC4-HMAC
// encryption type detection), and RDP TPKT/X.224 connection negotiation PDUs.
//
// Use [ComputeBeaconStats] and [Capture.Beacons] to compute C2 beacon timing
// periodicity, payload size uniformity, and directional Producer-Consumer Ratio
// (PCR) metrics across flows.
package pcap
