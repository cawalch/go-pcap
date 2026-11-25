package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func http1TransactionExportFrames() [][]byte {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	request := func(seq, ack uint32, flags uint8, payload string) []byte {
		return buildEthernetIPv4TCPFrame(client, server, 40700, 80, seq, ack, flags, []byte(payload))
	}
	reply := func(seq, ack uint32, flags uint8, payload string) []byte {
		return buildEthernetIPv4TCPFrame(server, client, 80, 40700, seq, ack, flags, []byte(payload))
	}
	const prior = "GET /prior HTTP/1.1\r\nHost: example.test\r\n\r\n"
	const priorReply = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nprior"
	const target = "GET /target HTTP/1.1\r\nHost: example.test\r\n\r\n"
	const targetReply = "HTTP/1.1 201 Created\r\nContent-Length: 6\r\n\r\n"
	const clientStart = 101
	const serverStart = 501
	const targetSeq = clientStart + len(prior)
	const targetEnd = targetSeq + len(target)
	const targetReplySeq = serverStart + len(priorReply)
	return [][]byte{
		buildEthernetIPv4UDPFrame(client, server, 51234, 51235, []byte("different flow")),
		request(clientStart-1, 0, TCPFlagSYN, ""),
		reply(serverStart-1, clientStart, TCPFlagSYN|TCPFlagACK, ""),
		request(clientStart, serverStart, TCPFlagACK, ""),
		request(clientStart, serverStart, TCPFlagACK, prior),
		reply(serverStart, uint32(targetSeq), TCPFlagACK, priorReply),
		request(uint32(targetSeq), uint32(targetReplySeq), TCPFlagACK, target),
		request(uint32(targetSeq), uint32(targetReplySeq), TCPFlagACK, target), // Retransmission.
		reply(uint32(targetReplySeq), uint32(targetEnd), TCPFlagACK, targetReply),
		reply(uint32(targetReplySeq+len(targetReply)), uint32(targetEnd), TCPFlagACK, "target"),
		request(uint32(targetEnd), uint32(targetReplySeq+len(targetReply)+6), TCPFlagACK, "GET /after HTTP/1.1\r\nHost: example.test\r\n\r\n"),
	}
}

func TestExtractHTTP1TransactionPCAPNG(t *testing.T) {
	frames := http1TransactionExportFrames()
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"classic", buildClassicPCAP(binary.BigEndian, true, LinkTypeEthernet, 65535, frames)},
		{"pcapng", buildPCAPNGFixture(binary.LittleEndian, []byte("decryption-marker"), frames)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, src := readWrittenPackets(t, tc.raw)
			r := bytes.NewReader(tc.raw)
			fromReader, err := NewFromReaderAt(r, r.Size())
			if err != nil {
				t.Fatal(err)
			}
			id := HTTP1TransactionID{PacketIndex: 6}
			var exported, exportedReader bytes.Buffer
			if err := c.ExtractHTTP1TransactionPCAPNG(tc.raw, &exported, id); err != nil {
				t.Fatal(err)
			}
			if err := fromReader.ExtractHTTP1TransactionPCAPNGFromReaderAt(r, &exportedReader, id); err != nil || !bytes.Equal(exported.Bytes(), exportedReader.Bytes()) {
				t.Fatalf("ReaderAt parity: %v", err)
			}
			indices := []int{1, 2, 4, 5, 6, 8, 9}
			output, packets := readWrittenPackets(t, exported.Bytes())
			if output.Format != FormatPCAPNG || len(output.Interfaces) != 1 || len(output.Secrets) != 0 || len(packets) != len(indices) {
				t.Fatalf("exported capture: format=%v interfaces=%d secrets=%d packets=%d", output.Format, len(output.Interfaces), len(output.Secrets), len(packets))
			}
			for i, at := range indices {
				got, want := packets[i], src[at]
				if got.TimestampNs != want.TimestampNs || got.CaptureLen != want.CaptureLen || got.OriginalLen != want.OriginalLen || got.LinkType != want.LinkType {
					t.Fatalf("packet %d: got %+v, want %+v", i, got, want)
				}
				payload, err := output.PacketPayload(exported.Bytes(), got)
				if err != nil || !bytes.Equal(payload, frames[at]) {
					t.Fatalf("packet %d payload differs: %v", i, err)
				}
			}
			txs, err := output.HTTP1Transactions(exported.Bytes())
			if err != nil || len(txs) != 2 {
				t.Fatalf("reopened transactions: %+v, %v", txs, err)
			}
			if tx := txs[1]; tx.ID() != (HTTP1TransactionID{PacketIndex: 4}) || tx.Request.Target != "/target" || tx.Response == nil || tx.Response.StatusCode != 201 || string(tx.Response.Body) != "target" {
				t.Fatalf("reopened transaction: %+v", tx)
			}
		})
	}
}

func TestExtractHTTP1TransactionPCAPNGErrors(t *testing.T) {
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, http1TransactionExportFrames())
	c, _ := readWrittenPackets(t, raw)
	r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
	for _, id := range []HTTP1TransactionID{{PacketIndex: -1}, {PacketIndex: c.PacketCount}, {PacketPayloadOffset: -1}, {PacketPayloadOffset: MaxSnapLen}} {
		writer := &incompleteCaptureWrite{}
		if err := c.ExtractHTTP1TransactionPCAPNGFromReaderAt(r, writer, id); !errors.Is(err, ErrOutOfBounds) || r.calls != 0 || writer.writes != 0 {
			t.Fatalf("invalid id %+v: err=%v reads=%d writes=%d", id, err, r.calls, writer.writes)
		}
	}
	for _, export := range []func(io.Writer, HTTP1TransactionID) error{
		func(w io.Writer, id HTTP1TransactionID) error { return c.ExtractHTTP1TransactionPCAPNG(raw, w, id) },
		func(w io.Writer, id HTTP1TransactionID) error {
			return c.ExtractHTTP1TransactionPCAPNGFromReaderAt(r, w, id)
		},
	} {
		writer := &incompleteCaptureWrite{failAt: 2}
		if err := export(writer, HTTP1TransactionID{PacketIndex: 6, PacketPayloadOffset: 1}); !errors.Is(err, ErrOutOfBounds) || writer.writes != 0 {
			t.Fatalf("missing id: err=%v writes=%d", err, writer.writes)
		}
		if err := export(writer, HTTP1TransactionID{PacketIndex: 6}); !errors.Is(err, io.ErrShortWrite) || writer.writes != 2 {
			t.Fatalf("short write: err=%v writes=%d", err, writer.writes)
		}
	}
}

func TestExtractHTTP1TransactionPCAPNGReaderAtBudget(t *testing.T) {
	frames := http1TransactionExportFrames()
	c, r := transactionExportBudgetCapture(t, [][]byte{frames[1], frames[2], frames[4], frames[5]}, MaxSnapLen-128)
	writer := &incompleteCaptureWrite{}
	err := c.ExtractHTTP1TransactionPCAPNGFromReaderAt(r, writer, HTTP1TransactionID{PacketIndex: 2})
	if !errors.Is(err, ErrPacketLimit) || writer.writes == 0 || r.bytesRead > MaxReaderAtScanBytes || r.bytesRead < MaxReaderAtScanBytes-32<<10 {
		t.Fatalf("shared read budget: err=%v read=%d writes=%d", err, r.bytesRead, writer.writes)
	}
}
