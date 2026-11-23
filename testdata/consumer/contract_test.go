package consumer_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func TestPacketOrderAndPayloadOwnership(t *testing.T) {
	var buf bytes.Buffer
	w, err := pcap.NewPCAPWriter(&buf, pcap.LinkTypeEthernet, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i, ts := range []int64{20, 10} {
		if err := w.WritePacket(ts, []byte{byte(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	raw := buf.Bytes()
	r := bytes.NewReader(raw)
	c, err := pcap.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	f, err := pcap.NewFromReaderAt(r, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	packets, err := c.Packets(raw)
	if err != nil || len(packets) != 2 {
		t.Fatalf("packets %v, error %v", packets, err)
	}
	fromFile, err := f.PacketsFromReaderAt(r)
	if err != nil || !reflect.DeepEqual(packets, fromFile) {
		t.Fatalf("ReaderAt packets %v, error %v", fromFile, err)
	}
	for i, ts := range []int64{20, 10} {
		if packets[i].Index != i || packets[i].TimestampNs != ts {
			t.Fatal(packets[i])
		}
	}
	view, err := c.PacketPayload(raw, packets[0])
	if err != nil {
		t.Fatal(err)
	}
	owned, err := f.PacketPayloadFromReaderAt(r, fromFile[0])
	if err != nil {
		t.Fatal(err)
	}
	raw[packets[0].PayloadOffset] = 42
	if !bytes.Equal(view, []byte{42}) || !bytes.Equal(owned, []byte{1}) {
		t.Fatal(view, owned)
	}

	partial, err := pcap.New(raw[:len(raw)-1])
	if err != nil || !partial.InputTruncated() || partial.PacketCount != 1 {
		t.Fatal(partial, err)
	}

	// Fail the second packet header after opening the complete file.
	fault := failingReader{r, packets[0].PayloadOffset + 1}
	var seen, failures int
	for pkt, err := range f.PacketSeqFromReaderAt(fault) {
		if err != nil {
			if !errors.Is(err, io.ErrClosedPipe) || seen != 1 {
				t.Fatal(seen, err)
			}
			failures++
		} else {
			if pkt.Index != 0 || failures != 0 {
				t.Fatal(pkt, failures)
			}
			seen++
		}
	}
	if seen != 1 || failures != 1 {
		t.Fatal(seen, failures)
	}
	if result, err := f.PacketsFromReaderAt(fault); !errors.Is(err, io.ErrClosedPipe) || len(result) != 0 {
		t.Fatal(result, err)
	}
}

type failingReader struct {
	r      io.ReaderAt
	failAt int64
}

func (r failingReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.failAt {
		return 0, io.ErrClosedPipe
	}
	return r.r.ReadAt(p, off)
}

func TestMetadataSnapshot(t *testing.T) {
	var buf bytes.Buffer
	w, err := pcap.NewPCAPNGWriter(&buf, pcap.PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteDecryptionSecrets(pcap.SecretsTypeTLSKeyLog, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	c, err := pcap.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	f, err := pcap.NewFromReaderAt(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	for _, capture := range []*pcap.Capture{c, f} {
		if len(capture.Secrets) != 1 || string(capture.Secrets[0].Data) != "fixture" {
			t.Fatal(capture.Secrets)
		}
	}
}

func TestClientRecordOrder(t *testing.T) {
	raw, err := os.ReadFile("../deployments/client.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	c, err := pcap.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	flows, err := c.Flows(raw)
	if err != nil {
		t.Fatal(err)
	}
	fileFlows, err := c.FlowsFromReaderAt(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(flows, fileFlows) {
		t.Fatal(fileFlows, err)
	}
	if len(flows) != 3 {
		t.Fatal(flows)
	}
	for i, port := range []uint16{53000, 50000, 50001} {
		if flows[i].SrcPort != port {
			t.Fatalf("flow %d starts at port %d", i, flows[i].SrcPort)
		}
	}
	dns, err := c.DNS(raw)
	if err != nil || len(dns) != 2 || dns[0].PacketIndex != 0 || dns[1].PacketIndex != 2 {
		t.Fatal(dns, err)
	}
	readerDNS, err := c.DNSFromReaderAt(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(readerDNS, dns) {
		t.Fatal(readerDNS, err)
	}

}

func TestWebSocketCompletionAndLimits(t *testing.T) {
	// A ping completes between the start and end of the first text message.
	raw := []byte{0x01, 1, 'a', 0x89, 1, 'p', 0x80, 1, 'b', 0xff}
	m, err := pcap.ParseWebSocketFrames(raw)
	clear(raw)
	if !errors.Is(err, pcap.ErrInvalidWebSocket) || len(m) != 2 || m[0].Opcode != 9 || string(m[0].Payload) != "p" || m[1].Opcode != 1 || string(m[1].Payload) != "ab" {
		t.Fatal(m, err)
	}

	frames := bytes.Repeat([]byte{0x82, 0}, pcap.MaxWebSocketFramesPerStream)
	if m, err := pcap.ParseWebSocketFrames(frames); err != nil || len(m) != pcap.MaxWebSocketFramesPerStream {
		t.Fatal(len(m), err)
	}
	if _, err := pcap.ParseWebSocketFrames(append(frames, 0x82, 0)); !errors.Is(err, pcap.ErrWebSocketLimit) {
		t.Fatal(err)
	}
}

func TestDNSLimitsAndMalformedInput(t *testing.T) {
	if _, err := pcap.ParseDNS([]byte{1}); !errors.Is(err, pcap.ErrInvalidDNS) {
		t.Fatal(err)
	}
	if _, err := pcap.ParseDNS([]byte{0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0}); !errors.Is(err, pcap.ErrDNSLimit) {
		t.Fatal(err)
	}
}

func TestReassemblyLimits(t *testing.T) {
	a, b := []byte("ab"), []byte("ef")
	stream, err := pcap.ReassembleTCP([]pcap.TCPSegmentInput{{Seq: 5, Payload: b}, {Seq: 1, Payload: a}})
	clear(a)
	clear(b)
	if err != nil || string(stream.Data) != "abef" || !stream.Anomalies.SequenceGap {
		t.Fatal(stream, err)
	}

	stream, err = pcap.ReassembleTCP([]pcap.TCPSegmentInput{{Seq: 1, Payload: make([]byte, pcap.MaxFlowStreamBytes+1)}})
	if err != nil || len(stream.Data) != pcap.MaxFlowStreamBytes || !stream.Anomalies.Truncated {
		t.Fatal(len(stream.Data), stream.Anomalies, err)
	}
	_, err = pcap.ReassembleTCP(make([]pcap.TCPSegmentInput, pcap.MaxSegmentsPerFlow+1))
	if !errors.Is(err, pcap.ErrReassemblyLimit) {
		t.Fatal(err)
	}
}

func TestBorrowedViews(t *testing.T) {
	client := []byte("CONNECT host.example:443 HTTP/1.1\r\n\r\nx")
	server := []byte("HTTP/1.1 200 OK\r\n\r\ny")
	inner, reply, _, _, _, ok := pcap.UnwrapProxyStream(client, server)
	if !ok {
		t.Fatal("expected successful CONNECT")
	}
	plain, err := pcap.DecompressCapture(client)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := pcap.NewSafeReader(client).Slice(int64(len(client)-1), 1)
	if err != nil {
		t.Fatal(err)
	}
	client[len(client)-1], server[len(server)-1] = 'a', 'b'
	if string(inner) != "a" || string(reply) != "b" || plain[len(plain)-1] != 'a' || string(tail) != "a" {
		t.Fatal("borrowed views did not track input")
	}
}
