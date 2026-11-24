package pcap

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type tcpCapturePacket struct {
	iface uint32
	ms    int64
	frame []byte
}

func tcpInterfaceCapture(packets []tcpCapturePacket) ([]byte, error) {
	var buf bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&buf, opts)
	if err != nil {
		return nil, err
	}
	if _, err := w.AddInterface(opts); err != nil {
		return nil, err
	}
	for _, p := range packets {
		pkt := PacketRecord{InterfaceID: p.iface, TimestampNs: p.ms * 1_000_000}
		if err := w.WritePacket(pkt, p.frame); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func tcpInterfaceFrame(seq, ack uint32, flags uint8, reverse bool, payload string) []byte {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 80}
	if reverse {
		return buildEthernetIPv4TCPFrame(b, a, 80, 53000, seq, ack, flags, []byte(payload))
	}
	return buildEthernetIPv4TCPFrame(a, b, 53000, 80, seq, ack, flags, []byte(payload))
}

func independentHTTPPackets() []tcpCapturePacket {
	return []tcpCapturePacket{
		{0, 1, tcpInterfaceFrame(100, 0, TCPFlagSYN, false, "")},
		{1, 2, tcpInterfaceFrame(900, 0, TCPFlagSYN, false, "")},
		{0, 3, tcpInterfaceFrame(101, 1, TCPFlagACK, false, "GET /alpha HTTP/1.1\r\nHost: a.example\r\n\r\n")},
		{1, 4, tcpInterfaceFrame(901, 1, TCPFlagACK, false, "GET /beta HTTP/1.1\r\nHost: b.example\r\n\r\n")},
	}
}

func TestTCPInterfaceObservations(t *testing.T) {
	const part1 = "GET /shared HTTP/1.1\r\n"
	const part2 = "Host: app.example\r\n\r\n"
	sharedSYN := tcpInterfaceFrame(100, 0, TCPFlagSYN, false, "")
	for _, tc := range []struct {
		name    string
		packets []tcpCapturePacket
		paths   [2][]string
		indices [2][]int
	}{
		{
			"independent", independentHTTPPackets(),
			[2][]string{{"/beta"}, {"/alpha", "/beta"}}, [2][]int{{3}, {2, 3}},
		},
		{
			"shared",
			[]tcpCapturePacket{
				{0, 1, sharedSYN}, {1, 2, sharedSYN},
				{0, 3, tcpInterfaceFrame(101, 1, TCPFlagACK, false, part1)},
				{1, 4, tcpInterfaceFrame(101+uint32(len(part1)), 1, TCPFlagACK, false, part2)},
			},
			[2][]string{{"/shared"}, nil}, [2][]int{{2}, nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tcpInterfaceCapture(tc.packets)
			if err != nil {
				t.Fatal(err)
			}
			reader := bytes.NewReader(data)
			c, err := New(data)
			if err != nil {
				t.Fatal(err)
			}
			cr, err := NewFromReaderAt(reader, reader.Size())
			if err != nil {
				t.Fatal(err)
			}
			for mode := range 2 {
				separate := mode == 1
				c.SeparateTCPInterfaces, cr.SeparateTCPInterfaces = separate, separate
				flows, err := c.Flows(data)
				if err != nil || len(flows) != 1 || flows[0].PacketCount != len(tc.packets) {
					t.Fatalf("separate=%t flows=%+v err=%v", separate, flows, err)
				}
				records, err := c.HTTP(data)
				web, webErr := c.Web(data)
				if webErr != nil || !reflect.DeepEqual(records, web.HTTP) {
					t.Fatalf("separate=%t Web.HTTP=%+v err=%v", separate, web.HTTP, webErr)
				}
				if err != nil || len(records) != len(tc.paths[mode]) {
					t.Fatalf("separate=%t HTTP=%+v err=%v", separate, records, err)
				}
				for i, r := range records {
					if r.IsResponse || r.FlowIndex != 0 || r.Request.Path != tc.paths[mode][i] {
						t.Fatalf("separate=%t HTTP[%d]=%+v", separate, i, r)
					}
				}
				observations, err := c.HTTPRequests(data)
				if err != nil || len(observations) != len(tc.paths[mode]) {
					t.Fatalf("separate=%t HTTP requests=%+v err=%v", separate, observations, err)
				}
				for i, r := range observations {
					if r.FlowIndex != 0 || r.Path != tc.paths[mode][i] || r.PacketIndex != tc.indices[mode][i] {
						t.Fatalf("separate=%t HTTP requests[%d]=%+v", separate, i, r)
					}
				}
				got, err := cr.HTTPRequestsFromReaderAt(reader)
				if err != nil || !reflect.DeepEqual(got, observations) {
					t.Fatalf("separate=%t ReaderAt requests=%+v err=%v", separate, got, err)
				}
				evidence, err := c.HTTP1RequestEvidence(data)
				if err != nil || len(evidence) != len(observations) {
					t.Fatalf("separate=%t HTTP/1 evidence=%+v err=%v", separate, evidence, err)
				}
				for i, r := range evidence {
					if r.Target != observations[i].Path || r.FlowIndex != observations[i].FlowIndex || r.PacketIndex != observations[i].PacketIndex || r.PacketPayloadOffset != 0 {
						t.Fatalf("separate=%t HTTP/1 evidence[%d]=%+v", separate, i, r)
					}
				}
				readerEvidence, err := cr.HTTP1RequestEvidenceFromReaderAt(reader)
				if err != nil || !reflect.DeepEqual(readerEvidence, evidence) {
					t.Fatalf("separate=%t ReaderAt HTTP/1 evidence=%+v err=%v", separate, readerEvidence, err)
				}
			}
		})
	}
}

func TestTCPInterfaceObservationsShareTupleSegmentLimit(t *testing.T) {
	frame := tcpInterfaceFrame(100, 0, TCPFlagSYN, false, "")
	packets := make([]tcpCapturePacket, MaxSegmentsPerFlow+1)
	for i := range packets {
		packets[i] = tcpCapturePacket{uint32(i % 2), int64(i), frame}
	}
	data, err := tcpInterfaceCapture(packets)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	c.SeparateTCPInterfaces = true
	if _, err := c.HTTP(data); !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("HTTP error = %v", err)
	}
	if _, err := c.HTTPRequests(data); !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("HTTPRequests error = %v", err)
	}
	if rows, err := c.HTTP1RequestEvidence(data); rows != nil || !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("HTTP1RequestEvidence = %d rows, %v", len(rows), err)
	}
	if rows, err := c.HTTP1RequestEvidenceFromReaderAt(bytes.NewReader(data)); rows != nil || !errors.Is(err, ErrReassemblyLimit) {
		t.Fatalf("HTTP1RequestEvidenceFromReaderAt = %d rows, %v", len(rows), err)
	}
}

func TestSSHTCPInterfaceObservations(t *testing.T) {
	data, err := tcpInterfaceCapture([]tcpCapturePacket{
		{0, 1, tcpInterfaceFrame(100, 0, TCPFlagSYN, false, "")},
		{1, 2, tcpInterfaceFrame(900, 0, TCPFlagSYN, false, "")},
		{0, 3, tcpInterfaceFrame(101, 1, TCPFlagACK, false, "SSH-2.0-one\r\n")},
		{1, 4, tcpInterfaceFrame(901, 1, TCPFlagACK, false, "SSH-2.0-last\r\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	c.SeparateTCPInterfaces = true
	rows, err := c.SSH(data)
	if err != nil || len(rows) != 2 || rows[0].JA4SSH != "c13s0_c1s0_c0s0" ||
		rows[1].JA4SSH != "c14s0_c1s0_c0s0" || rows[0].FlowIndex != rows[1].FlowIndex {
		t.Fatalf("SSH = %+v, %v", rows, err)
	}
}

func ExampleCapture_HTTP_independentInterfaces() {
	// The capture contains two independent networks with the same TCP tuple.
	data, err := tcpInterfaceCapture(independentHTTPPackets())
	if err != nil {
		panic(err)
	}
	c, err := New(data)
	if err != nil {
		panic(err)
	}
	c.SeparateTCPInterfaces = true
	records, err := c.HTTP(data)
	if err != nil {
		panic(err)
	}
	for _, r := range records {
		fmt.Println(r.Request.Path)
	}
	// Output:
	// /alpha
	// /beta
}
