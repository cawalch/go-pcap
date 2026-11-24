package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

const txGET = "GET / HTTP/1.1\r\n\r\n"
const txOK = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"

func txFrame(reverse bool, seq, ack uint32, flags uint8, data string) []byte {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	sp, dp := uint16(45000), uint16(80)
	if reverse {
		a, b, sp, dp = b, a, dp, sp
	}
	return buildEthernetIPv4TCPFrame(a, b, sp, dp, seq, ack, flags, []byte(data))
}

func txOpening() [][]byte {
	return [][]byte{txFrame(false, 100, 0, TCPFlagSYN, ""), txFrame(true, 200, 101, TCPFlagSYN|TCPFlagACK, "")}
}

func txScan(t *testing.T, frames [][]byte) ([]HTTP1Transaction, []byte, *Capture) {
	t.Helper()
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	return checkReaderParity(t, raw, c.HTTP1Transactions, c.HTTP1TransactionsFromReaderAt), raw, c
}

func TestHTTP1TransactionResponseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, first, firstResponse string
		firstState                 HTTPBodyState
		second                     HTTP1Pairing
	}{
		{"HEAD", "HEAD / HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nContent-Encoding: gzip\r\n\r\n", HTTPBodyComplete, HTTP1ResponseConfirmed},
		{"not modified", txGET, "HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n", HTTPBodyComplete, HTTP1ResponseConfirmed},
		{"malformed length", txGET, "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n", HTTPBodyUnknown, HTTP1ResponseAmbiguous},
		{"malformed chunk", txGET, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HTTPBodyUnknown, HTTP1ResponseAmbiguous},
		{"bad coding known extent", txGET, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\n\r\nmalformed!!!", HTTPBodyUnknown, HTTP1ResponseConfirmed},
		{"unsupported coding known extent", txGET, "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 3\r\n\r\nabc", HTTPBodyUnsupported, HTTP1ResponseConfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, tc.first), txFrame(true, 201, 101+uint32(len(tc.first)), TCPFlagACK, tc.firstResponse),
				txFrame(false, 101+uint32(len(tc.first)), 201+uint32(len(tc.firstResponse)), TCPFlagACK, txGET),
				txFrame(true, 201+uint32(len(tc.firstResponse)), 101+uint32(len(tc.first)+len(txGET)), TCPFlagACK, txOK))
			rows, raw, c := txScan(t, frames)
			if len(rows) != 2 || rows[0].Pairing != HTTP1ResponseConfirmed || rows[0].Response.BodyState != tc.firstState || rows[1].Pairing != tc.second || rows[1].SharedPackets || rows[1].ExportIncludesPriorMessages != (tc.second == HTTP1ResponseConfirmed) {
				t.Fatalf("rows = %+v", rows)
			}
			if tc.second == HTTP1ResponseConfirmed {
				var out bytes.Buffer
				if err := c.ExtractHTTP1TransactionPCAPNG(raw, &out, rows[1].ID()); err != nil {
					t.Fatal(err)
				}
				reopened, err := New(out.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				other, err := reopened.HTTP1Transactions(out.Bytes())
				if err != nil || len(other) != 2 || other[1].Response == nil || string(other[1].Response.Body) != "x" {
					t.Fatalf("reopened = %+v, %v", other, err)
				}
			}
		})
	}
}

func TestHTTP1TransactionPairingEvidence(t *testing.T) {
	client := txFrame(false, 101, 201, TCPFlagACK, txGET)
	server := txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagACK, txOK)
	for _, tc := range []struct {
		name    string
		frames  [][]byte
		pairing HTTP1Pairing
	}{
		{"no response", append(txOpening(), client), HTTP1ResponseUnseen},
		{"missing SYN", [][]byte{client, server}, HTTP1ResponseAmbiguous},
		{"missing SYN ACK", [][]byte{txOpening()[0], client, server}, HTTP1ResponseAmbiguous},
		{"response unavailable ACK flag", append(txOpening(), client, txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagPSH, txOK)), HTTP1ResponseAmbiguous},
		{"request unavailable ACK flag", append(txOpening(), txFrame(false, 101, 201, TCPFlagPSH, txGET), server), HTTP1ResponseAmbiguous},
		{"response predates request", append(txOpening(), client, txFrame(true, 201, 101, TCPFlagACK, txOK)), HTTP1ResponseAmbiguous},
		{"only interim", append(txOpening(), client, txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagACK, "HTTP/1.1 103 Early Hints\r\n\r\n")), HTTP1ResponseUnseen},
		{"only suffix after gap", append(txOpening(), client, txFrame(true, 230, 101+uint32(len(txGET)), TCPFlagACK, txOK)), HTTP1ResponseAmbiguous},
		{"clean retransmission", append(txOpening(), client, client, server), HTTP1ResponseConfirmed},
		{"conflicting retransmission", append(txOpening(), client, server, txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagACK, strings.Replace(txOK, "200", "201", 1))), HTTP1ResponseAmbiguous},
		{"malformed status", append(txOpening(), client, txFrame(true, 201, 101+uint32(len(txGET)), TCPFlagACK, "HTTP/1.1 200X\r\n\r\n")), HTTP1ResponseAmbiguous},
		{"fast open", [][]byte{txFrame(false, 100, 0, TCPFlagSYN, txGET), txFrame(true, 200, 101+uint32(len(txGET)), TCPFlagSYN|TCPFlagACK, txOK)}, HTTP1ResponseConfirmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, _, _ := txScan(t, tc.frames)
			if len(rows) != 1 || rows[0].Pairing != tc.pairing {
				t.Fatalf("rows = %+v", rows)
			}
			if tc.pairing != HTTP1ResponseConfirmed && !slices.Equal(rows[0].PacketIndices, []int{rows[0].Request.PacketIndex}) {
				t.Fatalf("unpaired indices = %v", rows[0].PacketIndices)
			}
			if tc.name == "clean retransmission" && !slices.Equal(rows[0].PacketIndices, []int{2, 4}) {
				t.Fatalf("indices = %v", rows[0].PacketIndices)
			}
		})
	}
}

func TestHTTP1TransactionCloseDelimited(t *testing.T) {
	header := "HTTP/1.0 200 OK\r\n\r\n"
	entity := strings.Repeat("x", 600) // Larger than the ReaderAt header prefix.
	response := header + entity
	for _, tc := range []struct {
		name        string
		flags       uint8
		trim        int
		separateFIN bool
		state       HTTPBodyState
	}{
		{"captured EOF", TCPFlagACK, 0, false, HTTPBodyPartial},
		{"complete FIN", TCPFlagACK | TCPFlagFIN, 0, false, HTTPBodyComplete},
		{"truncated FIN", TCPFlagACK | TCPFlagFIN, 50, false, HTTPBodyPartial},
		{"control FIN", TCPFlagACK, 0, true, HTTPBodyComplete},
		{"reset", TCPFlagRST | TCPFlagACK, 0, false, HTTPBodyPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := txFrame(true, 201, 101+uint32(len(txGET)), tc.flags, response)
			frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, txGET), reply[:len(reply)-tc.trim])
			if tc.separateFIN {
				frames = append(frames, txFrame(true, 201+uint32(len(response)), 101+uint32(len(txGET)), TCPFlagFIN|TCPFlagACK, ""))
			}
			rows, _, _ := txScan(t, frames)
			if len(rows) != 1 || rows[0].Response == nil || rows[0].Response.BodyState != tc.state || string(rows[0].Response.Body) != entity[:len(entity)-tc.trim] {
				t.Fatalf("rows = %+v", rows)
			}
			if tc.separateFIN && !slices.Equal(rows[0].PacketIndices, []int{2, 3, 4}) {
				t.Fatalf("closing FIN not selected: %v", rows[0].PacketIndices)
			}
		})
	}
}

func TestHTTP1TransactionInterimMessageBudget(t *testing.T) {
	// Each short packet carries several hundred interim responses.
	frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, txGET))
	const interim = "HTTP/1.1 103 Early Hints\r\n\r\n"
	seq := uint32(201)
	for n := 0; n < MaxHTTPMessagesPerScan; {
		count := min(1000, MaxHTTPMessagesPerScan-n)
		wire := strings.Repeat(interim, count)
		frames = append(frames, txFrame(true, seq, 101+uint32(len(txGET)), TCPFlagACK, wire))
		seq += uint32(len(wire))
		n += count
	}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw)
	cr, err := NewFromReaderAt(reader, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP1Transactions(raw)
	if rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("slice: %v, %v", rows, err)
	}
	rows, err = cr.HTTP1TransactionsFromReaderAt(reader)
	if rows != nil || !errors.Is(err, ErrHTTPLimit) {
		t.Fatalf("ReaderAt: %v, %v", rows, err)
	}
}

func TestHTTP1TransactionRequestOnlyExportPrefix(t *testing.T) {
	const head = "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"
	const tail = "data" + txGET
	for _, ambiguous := range []bool{false, true} {
		frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, head), txFrame(false, 101+uint32(len(head)), 201, TCPFlagACK, tail))
		want := HTTP1ResponseUnseen
		if ambiguous {
			frames = append(frames, txFrame(true, 251, 101+uint32(len(head+tail)), TCPFlagACK, txOK))
			want = HTTP1ResponseAmbiguous
		}
		rows, raw, c := txScan(t, frames)
		if len(rows) != 2 || rows[1].Pairing != want || !rows[1].SharedPackets || !rows[1].ExportIncludesPriorMessages || !slices.Equal(rows[1].PacketIndices, []int{3}) {
			t.Fatalf("rows = %+v", rows)
		}
		var out bytes.Buffer
		if err := c.ExtractHTTP1TransactionPCAPNG(raw, &out, rows[1].ID()); err != nil {
			t.Fatal(err)
		}
		index, packets := readWrittenPackets(t, out.Bytes())
		if len(packets) != 3 {
			t.Fatalf("exported %d packets, want opening SYN and two client packets", len(packets))
		}
		reopened, err := index.HTTP1Transactions(out.Bytes())
		if err != nil || len(reopened) != 2 || reopened[1].Request.PacketIndex != 2 || reopened[1].Request.PacketPayloadOffset != 4 || reopened[1].Response != nil {
			t.Fatalf("reopened rows = %+v, %v", reopened, err)
		}
	}
}

func TestHTTP1TransactionFINOrder(t *testing.T) {
	const request = txGET + txGET
	const response = txOK + txOK
	for _, pastEnd := range []bool{false, true} {
		end := len(response)
		if pastEnd {
			end = len(txOK)
		}
		fin := txFrame(true, 201+uint32(end), 101+uint32(len(request)), TCPFlagFIN|TCPFlagACK, "")
		data := txFrame(true, 201, 101+uint32(len(request)), TCPFlagACK, response)
		for _, finFirst := range []bool{false, true} {
			frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, request))
			if finFirst {
				frames = append(frames, fin, data)
			} else {
				frames = append(frames, data, fin)
			}
			rows, _, _ := txScan(t, frames)
			if len(rows) != 2 || (rows[1].Pairing == HTTP1ResponseConfirmed) == pastEnd {
				t.Fatalf("past end %v, FIN first %v, rows = %+v", pastEnd, finFirst, rows)
			}
		}
	}
	frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, txGET), txFrame(true, 301, 101+uint32(len(txGET)), TCPFlagFIN|TCPFlagACK, ""))
	rows, _, _ := txScan(t, frames)
	if len(rows) != 1 || rows[0].Pairing != HTTP1ResponseAmbiguous {
		t.Fatalf("uncaptured reply before FIN: %+v", rows)
	}
}

func TestHTTP1TransactionResetBeforeFIN(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\n\r\nshort"
	sack := uint32(101 + len(txGET))
	end := uint32(201 + len(response))
	for _, reset := range [][]byte{txFrame(false, sack, end, TCPFlagRST|TCPFlagACK, ""), txFrame(true, end, sack, TCPFlagRST|TCPFlagACK, ""), nil} {
		frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, txGET), txFrame(true, 201, sack, TCPFlagACK, response))
		flags := TCPFlagFIN | TCPFlagACK
		if reset != nil {
			frames = append(frames, reset)
		} else {
			flags |= TCPFlagRST
		}
		frames = append(frames, txFrame(true, end, sack, flags, ""))
		rows, _, _ := txScan(t, frames)
		if len(rows) != 1 || rows[0].Response == nil || rows[0].Response.BodyState != HTTPBodyPartial || string(rows[0].Response.Body) != "short" {
			t.Fatalf("rows = %+v", rows)
		}
	}
}

func TestHTTP1TransactionACKSequenceRange(t *testing.T) {
	const syn = uint32(0xfffffff4)
	for _, ack := range []uint32{syn, syn + 1, 0} {
		frames := [][]byte{txFrame(false, syn, 0, TCPFlagSYN, ""), txFrame(true, syn, syn+1, TCPFlagSYN|TCPFlagACK, ""),
			txFrame(false, syn+1, ack, TCPFlagACK, txGET), txFrame(true, syn+1, (syn+1)+uint32(len([]byte(txGET))), TCPFlagACK, txOK)}
		// The request starts before sequence wrap and ends after it.
		rows, _, _ := txScan(t, frames)
		if len(rows) != 1 || (rows[0].Pairing == HTTP1ResponseConfirmed) != (ack == syn+1) {
			t.Fatalf("ACK %x, rows = %+v", ack, rows)
		}
	}
}

func TestHTTP1TransactionSharedClosingFIN(t *testing.T) {
	const last = "HTTP/1.1 200 OK\r\n\r\nfinal"
	ack := uint32(101 + 2*len(txGET))
	frames := append(txOpening(), txFrame(false, 101, 201, TCPFlagACK, txGET), txFrame(false, 101+uint32(len(txGET)), 201, TCPFlagACK, txGET),
		txFrame(true, 201, ack, TCPFlagACK, txOK), txFrame(true, 201+uint32(len(txOK)), ack, TCPFlagACK, last),
		txFrame(true, 201, ack, TCPFlagACK|TCPFlagFIN, txOK+last))
	rows, _, _ := txScan(t, frames)
	if len(rows) != 2 || !rows[1].SharedPackets || !slices.Equal(rows[1].PacketIndices, []int{3, 5, 6}) || rows[1].Response == nil || rows[1].Response.BodyState != HTTPBodyComplete || string(rows[1].Response.Body) != "final" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestHTTP1TransactionMalformedChunkExport(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	const request = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	for _, reverse := range []bool{false, true} {
		head, seq, ack := request, uint32(101), uint32(201)
		frames := txOpening()
		if reverse {
			frames = append(frames, txFrame(false, seq, ack, TCPFlagACK, txGET))
			head, seq, ack = response, ack, seq+uint32(len(txGET))
		}
		frames = append(frames, txFrame(reverse, seq, ack, TCPFlagACK, head),
			txFrame(reverse, seq+uint32(len(head)), ack, TCPFlagACK, "invalid\r\n"),
			txFrame(reverse, seq+uint32(len(head+"invalid\r\n")), ack, TCPFlagACK, "later bytes"))
		rows, raw, c := txScan(t, frames)
		if len(rows) != 1 || !slices.Contains(rows[0].PacketIndices, len(frames)-2) || slices.Contains(rows[0].PacketIndices, len(frames)-1) {
			t.Fatalf("malformed chunk evidence = %+v", rows)
		}
		var out bytes.Buffer
		if err := c.ExtractHTTP1TransactionPCAPNG(raw, &out, rows[0].ID()); err != nil {
			t.Fatal(err)
		}
		carved, _ := readWrittenPackets(t, out.Bytes())
		got, err := carved.HTTP1Transactions(out.Bytes())
		if err != nil || len(got) != 1 {
			t.Fatalf("reopened = %+v, %v", got, err)
		}
		if reverse {
			if got[0].Response == nil || got[0].Response.BodyState != HTTPBodyUnknown {
				t.Fatalf("reopened response = %+v", got[0].Response)
			}
		} else if got[0].Request.BodyState != HTTPBodyUnknown {
			t.Fatalf("reopened request = %+v", got[0].Request)
		}
	}
}
