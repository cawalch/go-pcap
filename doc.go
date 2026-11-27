// Package pcap reads and writes PCAP and PcapNG, captures live traffic, and
// decodes network protocols.
//
// Open bytes with [New] or a seekable source with [NewFromReaderAt]. The
// [Capture] owns its metadata. Supply the same capture contents to later
// scans. Check [Capture.InputTruncated] for an incomplete trailing record.
//
// Iterate packets with [Capture.PacketSeq] or [Capture.PacketSeqFromReaderAt].
// Pass frame bytes to [DecodeFrame], or use [Capture.Flows] to group packets.
// Protocol scans such as [Capture.DNS], [Capture.TLSHandshakeEvidence], and
// [Capture.KeyedHTTP3Transactions] expose observed fields under bounded
// reads, reassembly, and output. Packet indices refer to the original
// capture and start at zero.
//
// Use [NewPCAPWriter] or [NewPCAPNGWriter] to write a capture,
// [Capture.ExtractFlowPacketsPCAPNG] to export original packets,
// and [OpenLive] to read from a local network interface.
package pcap
