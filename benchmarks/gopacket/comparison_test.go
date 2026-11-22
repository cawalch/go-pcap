package gopacketbench

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/cawalch/go-pcap"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/tcpassembly"
)

func buildEthernetIPv4TCPFrame(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcpHeaderLen := 20
	ipTotalLen := 20 + tcpHeaderLen + len(payload)
	buf := make([]byte, 14+ipTotalLen)

	// Ethernet header
	binary.BigEndian.PutUint16(buf[12:14], uint16(pcap.EtherTypeIPv4))

	// IPv4 header
	ip := buf[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen))
	ip[8] = 64
	ip[9] = pcap.IPProtoTCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	// TCP header
	tcp := buf[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(buf[54:], payload)
	return buf
}

func buildMultiFlowPCAPFixture(packetCount int) ([]byte, []byte) {
	frames := make([][]byte, 0, packetCount)
	payload := []byte("GET /api/v1/status HTTP/1.1\r\nHost: bench.example.com\r\n\r\n")
	for i := range packetCount {
		flowID := uint8(i % 8)
		srcIP := [4]byte{10, 0, flowID, 1}
		dstIP := [4]byte{10, 0, flowID, 2}
		srcPort := uint16(40000 + int(flowID))
		dstPort := uint16(443)
		seq := uint32(1000 + (i/8)*len(payload))
		ack := uint32(2000)
		flags := pcap.TCPFlagPSH | pcap.TCPFlagACK
		if i < 8 {
			flags = pcap.TCPFlagSYN
		}
		frames = append(frames, buildEthernetIPv4TCPFrame(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload))
	}

	// Build classic PCAP
	var classicBuf bytes.Buffer
	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)
	binary.LittleEndian.PutUint32(ghdr[20:24], uint32(pcap.LinkTypeEthernet))
	classicBuf.Write(ghdr[:])

	// Build PcapNG
	var ngBuf bytes.Buffer
	pw, _ := pcap.NewPCAPNGWriter(&ngBuf, pcap.PCAPNGWriterOptions{
		LinkType: pcap.LinkTypeEthernet,
		SnapLen:  65535,
	})

	for i, f := range frames {
		var phdr [16]byte
		binary.LittleEndian.PutUint32(phdr[0:4], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(phdr[4:8], uint32((i*1000)%1000000))
		binary.LittleEndian.PutUint32(phdr[8:12], uint32(len(f)))
		binary.LittleEndian.PutUint32(phdr[12:16], uint32(len(f)))
		classicBuf.Write(phdr[:])
		classicBuf.Write(f)

		_ = pw.WritePacket(pcap.PacketRecord{
			TimestampNs: int64(1700000000000000000) + int64(i)*1000000,
		}, f)
	}

	return classicBuf.Bytes(), ngBuf.Bytes()
}

// TestDifferentialParityAgainstGopacket verifies that go-pcap and gopacket/pcapgo
// decode identical packet counts, timestamps, L3/L4 header fields, and payload bytes.
func TestDifferentialParityAgainstGopacket(t *testing.T) {
	classicData, ngData := buildMultiFlowPCAPFixture(64)

	for _, tc := range []struct {
		name string
		data []byte
		ng   bool
	}{
		{name: "ClassicPCAP", data: classicData, ng: false},
		{name: "PcapNG", data: ngData, ng: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap, err := pcap.New(tc.data)
			if err != nil {
				t.Fatalf("pcap.New() error = %v", err)
			}
			pkts, err := cap.Packets(tc.data)
			if err != nil {
				t.Fatalf("cap.Packets() error = %v", err)
			}

			var gpCount int
			r := bytes.NewReader(tc.data)
			var readNext func() ([]byte, gopacket.CaptureInfo, error)
			if tc.ng {
				ngr, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
				if err != nil {
					t.Fatalf("pcapgo.NewNgReader() error = %v", err)
				}
				readNext = ngr.ReadPacketData
			} else {
				cr, err := pcapgo.NewReader(r)
				if err != nil {
					t.Fatalf("pcapgo.NewReader() error = %v", err)
				}
				readNext = cr.ReadPacketData
			}

			for {
				gpData, ci, err := readNext()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("ReadPacketData() error = %v", err)
				}
				pkt := pkts[gpCount]
				gpCount++

				payload, err := cap.PacketPayload(tc.data, pkt)
				if err != nil {
					t.Fatalf("PacketPayload() error = %v", err)
				}
				if !bytes.Equal(payload, gpData) {
					t.Fatalf("packet %d payload mismatch", pkt.Index)
				}
				if pkt.TimestampNs != ci.Timestamp.UnixNano() {
					t.Fatalf("packet %d timestamp = %d, want %d", pkt.Index, pkt.TimestampNs, ci.Timestamp.UnixNano())
				}

				frame, err := pcap.DecodeFrame(payload, pkt.LinkType)
				if err != nil {
					t.Fatalf("DecodeFrame() error = %v", err)
				}
				gpPkt := gopacket.NewPacket(gpData, layers.LayerTypeEthernet, gopacket.NoCopy)
				ip4, _ := gpPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				tcp, _ := gpPkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if ip4 == nil || tcp == nil {
					t.Fatalf("gopacket failed to decode IPv4/TCP at packet %d", pkt.Index)
				}
				if frame.SrcAddr != netip.AddrFrom4([4]byte(ip4.SrcIP)) || frame.DstAddr != netip.AddrFrom4([4]byte(ip4.DstIP)) {
					t.Fatalf("IP address mismatch: got %s->%s", frame.SrcAddr, frame.DstAddr)
				}
				if frame.SrcPort != uint16(tcp.SrcPort) || frame.DstPort != uint16(tcp.DstPort) || frame.TCPSeq != tcp.Seq {
					t.Fatalf("TCP header mismatch at packet %d", pkt.Index)
				}
			}

			if gpCount != len(pkts) {
				t.Fatalf("packet count = %d, want %d", len(pkts), gpCount)
			}
		})
	}
}

func BenchmarkDecodeFrame_GoPCAP(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 51234, 443, 100, 200, pcap.TCPFlagPSH|pcap.TCPFlagACK, []byte("benchmark payload"))
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := pcap.DecodeFrame(frame, pcap.LinkTypeEthernet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeFrame_GopacketNewPacket(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 51234, 443, 100, 200, pcap.TCPFlagPSH|pcap.TCPFlagACK, []byte("benchmark payload"))
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
		if pkt.NetworkLayer() == nil || pkt.TransportLayer() == nil {
			b.Fatal("missing layer")
		}
	}
}

func BenchmarkDecodeFrame_GopacketDecodingLayerParser(b *testing.B) {
	frame := buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, 51234, 443, 100, 200, pcap.TCPFlagPSH|pcap.TCPFlagACK, []byte("benchmark payload"))
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &payload)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 4)

	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := parser.DecodeLayers(frame, &decoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPCAPNGWalk_GoPCAP(b *testing.B) {
	_, ngData := buildMultiFlowPCAPFixture(64)
	b.SetBytes(int64(len(ngData)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		cap, err := pcap.New(ngData)
		if err != nil {
			b.Fatal(err)
		}
		for pkt, err := range cap.PacketSeq(ngData) {
			if err != nil {
				b.Fatal(err)
			}
			_, _ = cap.PacketPayload(ngData, pkt)
		}
	}
}

func BenchmarkPCAPNGWalk_GopacketPcapgo(b *testing.B) {
	_, ngData := buildMultiFlowPCAPFixture(64)
	b.SetBytes(int64(len(ngData)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r, err := pcapgo.NewNgReader(bytes.NewReader(ngData), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			b.Fatal(err)
		}
		for {
			_, _, err := r.ReadPacketData()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

type noopStreamFactory struct{}

type noopStream struct{}

func (f *noopStreamFactory) New(_, _ gopacket.Flow) tcpassembly.Stream {
	return &noopStream{}
}

func (s *noopStream) Reassembled(_ []tcpassembly.Reassembly) {}
func (s *noopStream) ReassemblyComplete()                    {}

func BenchmarkTCPReassembly_GoPCAP(b *testing.B) {
	classicData, _ := buildMultiFlowPCAPFixture(64)
	cap, err := pcap.New(classicData)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(classicData)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		streams, err := cap.Streams(classicData)
		if err != nil || len(streams) != 8 {
			b.Fatalf("Streams() = (%d, %v)", len(streams), err)
		}
	}
}

func BenchmarkTCPReassembly_GopacketTCPAssembly(b *testing.B) {
	classicData, _ := buildMultiFlowPCAPFixture(64)
	b.SetBytes(int64(len(classicData)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		cr, err := pcapgo.NewReader(bytes.NewReader(classicData))
		if err != nil {
			b.Fatal(err)
		}
		pool := tcpassembly.NewStreamPool(&noopStreamFactory{})
		assembler := tcpassembly.NewAssembler(pool)
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP
		var payload gopacket.Payload
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &payload)
		decoded := make([]gopacket.LayerType, 0, 4)

		for {
			data, ci, err := cr.ReadPacketData()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			if err := parser.DecodeLayers(data, &decoded); err == nil {
				assembler.AssembleWithTimestamp(ip4.NetworkFlow(), &tcp, ci.Timestamp)
			}
		}
		assembler.FlushAll()
	}
}
