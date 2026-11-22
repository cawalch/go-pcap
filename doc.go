// Package pcap reads PCAP and PcapNG packet captures, decodes L2–L4 network
// frames, and aggregates flow and protocol metadata.
// It uses only the Go standard library.
//
// Use [New] to parse a byte slice, [Open] to read a file, [NewWithLength]
// to parse a leading stream prefix with a known total stream length, or
// [NewFromReaderAt] (with [Capture.PacketsFromReaderAt] and
// [Capture.PacketPayloadFromReaderAt]) to read bounded container metadata and
// packet headers from an [io.ReaderAt] without loading large captures into
// memory. Use [NewPCAPNGWriter] to write PcapNG containers, Decryption Secrets
// Blocks (DSB), and Enhanced Packet Blocks (EPB), or [OpenLive] to capture live
// packets from a network interface using OS-native standard-library syscalls. These
// functions return a container snapshot ([Capture]) that retains no reference
// to the input. They validate container headers, interface descriptors, and
// Decryption Secrets Blocks (DSB) while recording the declared byte extent;
// inspect [Capture.FileSize], [Capture.DeclaredExtent], [Capture.InputTruncated],
// and [Capture.Anomalies] to check whether the capture is truncated or contains
// structural anomalies.
//
// To enumerate packet records in file order, pass the original bytes to
// [Capture.PacketSeq] (single-pass iterator without slice allocation) or
// [Capture.Packets], and slice individual packet frames with
// [Capture.PacketPayload]. Each [PacketRecord] reports normalized nanosecond
// timestamps, zero-copy payload offsets, and any PcapNG Enhanced Packet Block
// process attribution (process ID, thread ID, flags, and drop counts).
//
// Use [DecodeFrame] to decode Ethernet, 802.1Q/802.1ad VLAN, Linux SLL/SLL2,
// BSD Loopback/Null, or Raw IP frames into IPv4/IPv6 network headers and
// TCP/UDP/ICMP transport headers using a fixed-size stack layer cursor that
// performs zero heap allocations.
//
// Use [Capture.Flows] to aggregate deterministic bidirectional 5-tuple flow
// summaries with directional packet and byte counters, unioned TCP flags,
// client/server JA4T/JA4TS TCP fingerprints, process attribution, and anomaly
// flags under bounded flow and packet limits.
//
// Use [JA4T] or [Frame.JA4T] to compute FoxIO JA4T/JA4TS TCP SYN fingerprints.
// Use [ReassembleTCP] or [Capture.Streams] to reassemble bounded, ordered TCP
// streams with sequence-gap and overlap-conflict anomaly detection.
//
// Use [ParseDNS], [Capture.DNS], and [Capture.HasDNSQuery] to decode DNS
// queries, resource records, and RFC 1035 compressed domain names over UDP and
// TCP under jump and record limits.
//
// Use [ParseTLSRecords], [ParseTLSClientHello], [ParseTLSServerHello],
// [JA4XFromDER], [JA4XFromCert], [Capture.TLS], [Capture.HasTLSJA4], and
// [Capture.HasTLSSNI] to decode TLS 1.2/1.3 handshakes, X.509 certificate
// chains, and FoxIO JA4, JA4S, and JA4X fingerprints.
//
// Use [ParseQUICInitialPacket], [DecryptQUICInitial], [Capture.QUIC],
// [Capture.HasQUICJA4], and [Capture.HasQUICSNI] to derive RFC 9001 (QUIC v1)
// and RFC 9369 (QUIC v2) Initial keys, remove header protection, decrypt and
// reassemble CRYPTO frames across UDP datagrams, and extract the embedded TLS
// 1.3 ClientHello and JA4 fingerprint.
//
// Use [ParseTLSKeyLog], [Capture.TLSKeyLog], [DecryptTLS13Records], and
// [Capture.DecryptedTLSStreams] to decrypt TLS 1.3 traffic offline using
// embedded PcapNG Decryption Secrets Blocks (DSB) or external SSLKEYLOGFILE
// material.
//
// Use [ParseHTTPRequest], [ParseHTTPResponse], and [Capture.HTTP] to parse
// HTTP/1.x traffic (including automatically decrypted TLS 1.3 flows), compute
// FoxIO JA4H fingerprints, and carve request/response body payloads.
//
// Use [ParseSSHHandshake] and [Capture.SSH] to parse SSH version banners and
// SSH_MSG_KEXINIT key-exchange algorithms and compute HASSH and HASSHServer
// MD5 fingerprints.
//
// Use [ParseSMB2Message], [ParseNTLMSSP], and [Capture.SMB] to decode SMB2/3
// Negotiate and Session Setup packets and extract NTLMSSP challenge, domain,
// host, and user metadata.
//
// Use [ComputeBeaconStats] and [Capture.Beacons] to compute C2 beacon timing
// periodicity, payload size uniformity, and directional Producer-Consumer Ratio
// (PCR) metrics across flows.
package pcap
