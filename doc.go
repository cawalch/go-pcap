// Package pcap reads and writes PCAP and PcapNG captures, captures live packets,
// and decodes network flows and application protocols using the Go standard library.
//
// Start with [New] for bytes or [NewFromReaderAt] for a seekable source.
// A [Capture] owns its metadata. Pass the same capture contents to subsequent
// scans. For a buffered prefix with a known total length, use [NewWithLength].
// Check [Capture.InputTruncated] before assuming the last packet is complete.
//
// Use [Capture.PacketSeq] to walk packet records in file order. [Capture.PacketPayload]
// borrows the frame bytes from the input. [DecodeFrame] identifies their headers.
// [Capture.Flows] groups bidirectional conversations by five-tuple. Protocol
// methods such as [Capture.DNS], [Capture.TLS], and [Capture.HTTP1RequestEvidence]
// reassemble the data they need and expose their own work and output limits.
//
// [NewPCAPWriter] and [NewPCAPNGWriter] write captures to an [io.Writer].
// [Capture.ExtractFlowPacketsPCAPNG] exports the packets of one flow, including
// their original payloads. [OpenLive] reads from a local network interface.
package pcap
