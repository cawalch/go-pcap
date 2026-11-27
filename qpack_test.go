package pcap

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"testing"
)

func qpackBytes(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestQPACKRFC9204Examples(t *testing.T) {
	// RFC 9204 Appendix B, encoder and field sections B.1 through B.5.
	enc := QUICStream{ID: 2, Data: []byte{2}}
	enc.Data = append(enc.Data, qpackBytes(t, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")...)
	enc.Data = append(enc.Data, qpackBytes(t, "4a637573746f6d2d6b65790c637573746f6d2d76616c756502")...)
	atDuplicate := len(enc.Data)
	enc.Data = append(enc.Data, qpackBytes(t, "810d637573746f6d2d76616c756532")...)
	input := []QPACKSectionInput{
		{0, 8, qpackBytes(t, "0000510b2f696e6465782e68746d6c"), 0},
		{4, 3, qpackBytes(t, "03811011"), 6}, // The first insert is still partial at arrival.
		{8, 4, qpackBytes(t, "050080c181"), atDuplicate},
		{12, 9, qpackBytes(t, "060080"), len(enc.Data)},
		{16, 10, qpackBytes(t, "060084"), len(enc.Data)},     // Entry zero has been evicted.
		{20, 11, qpackBytes(t, "0680000178"), len(enc.Data)}, // Post-base name reference, index 4.
	}
	rows, err := DecodeQPACKSections(enc, 220, input)
	if err != nil {
		t.Fatal(err)
	}
	// Both B.2 dependencies are available before B.3 and the duplicate.
	if rows[0].EncoderOffset != 0 || rows[1].EncoderOffset != 35 || rows[2].EncoderOffset != atDuplicate || rows[3].EncoderOffset != len(enc.Data) {
		t.Fatalf("encoder context offsets: %+v", rows)
	}
	for i, want := range [][]HTTPHeader{
		{{":path", "/index.html"}},
		{{":authority", "www.example.com"}, {":path", "/sample/path"}},
		{{":authority", "www.example.com"}, {":path", "/"}, {"custom-key", "custom-value"}},
		{{"custom-key", "custom-value2"}},
		nil,
		{{"custom-key", "x"}},
	} {
		row := rows[i]
		if row.Offset != input[i].Offset || row.StreamID != input[i].StreamID || row.Length != len(input[i].Data) ||
			!slices.Equal(row.Headers, want) || (row.State == QPACKDecoded) != (want != nil) || want == nil && row.State != QPACKMalformed {
			t.Fatalf("section %d = %+v", i, row)
		}
	}
}

func TestQPACKWrapGapAndLimits(t *testing.T) {
	// MaxEntries=2, so encoded count 2 is absolute 1 on arrival before
	// the first insertion and absolute 5 after four insertions.
	enc := QUICStream{ID: 6, Data: qpackBytes(t, "023f2141610131416201324163013341640134416501354166"), Gap: true}
	input := []QPACKSectionInput{
		{4, 0, []byte{2, 0, 0x80}, 0},
		{8, 0, []byte{2, 0, 0x80}, 19},
		{12, 0, []byte{3, 0, 0x80}, len(enc.Data)},
		{16, 0, []byte{0, 0, 0xd1}, len(enc.Data)},
	}
	rows, err := DecodeQPACKSections(enc, 64, input)
	if err != nil || rows[0].RequiredInsertCount != 1 || rows[1].RequiredInsertCount != 5 ||
		rows[0].Headers[0] != (HTTPHeader{"a", "1"}) || rows[1].Headers[0] != (HTTPHeader{"e", "5"}) ||
		rows[2].State != QPACKBlocked || rows[2].RequiredInsertCount != 6 || len(rows[2].Headers) != 0 ||
		rows[3].Headers[0] != (HTTPHeader{":method", "GET"}) {
		t.Fatalf("gap: %+v, %v", rows, err)
	}
	enc.Gap, enc.Complete = false, true
	if rows, err := DecodeQPACKSections(enc, 64, input); rows != nil || !errors.Is(err, ErrInvalidHTTP3) {
		t.Fatalf("encoder FIN: %+v, %v", rows, err)
	}
	// The count ceiling and compressed-byte ceiling are independent.
	for _, tc := range []struct{ size, waiting int }{{3, MaxQPACKBlockedSections}, {MaxHTTP2HeaderBlockBytes, MaxQPACKBlockedBytes / MaxHTTP2HeaderBlockBytes}} {
		block := make([]byte, tc.size)
		block[0], block[2] = 2, 0x80
		input := make([]QPACKSectionInput, tc.waiting+1)
		for i := range input {
			input[i] = QPACKSectionInput{StreamID: uint64(4 * i), Data: block}
		}
		rows, err := DecodeQPACKSections(QUICStream{}, 64, input)
		if err != nil || rows[tc.waiting-1].State != QPACKBlocked || rows[tc.waiting].State != QPACKLimited {
			t.Fatalf("queue %d: %+v, %v", tc.size, rows, err)
		}
	}
}

func TestQPACKFieldValidityAndWork(t *testing.T) {
	for _, tc := range []struct {
		wire  string
		state QPACKSectionState
		want  HTTPHeader
	}{
		{"0000", QPACKDecoded, HTTPHeader{}},
		{"00002df2b24a84ff0176", QPACKDecoded, HTTPHeader{"x-test", "v"}}, // Huffman literal name.
		{"00005f500178", QPACKDecoded, HTTPHeader{"user-agent", "x"}},     // Static name at index 95.
		{"00002fff", QPACKMalformed, HTTPHeader{}},
		{"0000ffffff7f", QPACKMalformed, HTTPHeader{}},
		{"000080", QPACKMalformed, HTTPHeader{}},
		{"0080c1", QPACKMalformed, HTTPHeader{}},
		{"020080", QPACKMalformed, HTTPHeader{}},       // Zero maximum capacity.
		{"0000c1ff", QPACKMalformed, HTTPHeader{}},     // No partial fields.
		{"000029ff0178", QPACKMalformed, HTTPHeader{}}, // Invalid Huffman padding.
	} {
		rows, err := DecodeQPACKSections(QUICStream{}, 0, []QPACKSectionInput{{Data: qpackBytes(t, tc.wire)}})
		if err != nil || rows[0].State != tc.state || (tc.want.Name != "" && !slices.Equal(rows[0].Headers, []HTTPHeader{tc.want})) ||
			tc.state != QPACKDecoded && len(rows[0].Headers) != 0 {
			t.Errorf("%s: %+v, %v", tc.wire, rows, err)
		}
	}
	for _, wire := range [][]byte{append([]byte{0, 0}, bytes.Repeat([]byte{0xc0}, MaxHTTPHeaders+1)...), make([]byte, MaxHTTP2HeaderBlockBytes+1)} {
		rows, err := DecodeQPACKSections(QUICStream{}, 0, []QPACKSectionInput{{Data: wire}})
		if err != nil || rows[0].State != QPACKLimited || len(rows[0].Headers) != 0 {
			t.Fatalf("section limit: %+v, %v", rows, err)
		}
	}
	// A single static byte can reference a long value. The output budget
	// covers all sections, including repetitions of the same static entry.
	field := bytes.Repeat([]byte{0xf5}, MaxHTTPHeaders)
	block := append([]byte{0, 0}, field...)
	input := make([]QPACKSectionInput, MaxHTTP2DecodedHeaderBytes/(MaxHTTPHeaders*32)+2)
	for i := range input {
		input[i].Data = block
	}
	rows, err := DecodeQPACKSections(QUICStream{}, 0, input)
	if err != nil || rows[0].State != QPACKDecoded || rows[len(rows)-1].State != QPACKLimited {
		t.Fatalf("aggregate headers: %v", err)
	}
}

func TestQPACKEncoderErrors(t *testing.T) {
	for _, tc := range []struct {
		wire string
		max  uint64
		want error
	}{
		{"0220", 0, ErrInvalidHTTP3}, // Capacity zero forbids even a resize.
		{"023f22", 64, ErrInvalidHTTP3},
		{"0241610176", 64, ErrInvalidHTTP3},               // Starts at zero before the first resize.
		{"023f2100", 64, ErrInvalidHTTP3},                 // Duplicate empty table.
		{"023f21416101314162013201", 64, ErrInvalidHTTP3}, // Evicted duplicate.
		{"023fe2ff03", 1 << 20, ErrHTTP3Limit},
		{"023fffffffffffffffffffffff", 64, ErrInvalidHTTP3},
	} {
		rows, err := DecodeQPACKSections(QUICStream{ID: 2, Data: qpackBytes(t, tc.wire)}, tc.max, nil)
		if rows != nil || !errors.Is(err, tc.want) {
			t.Errorf("%s: %+v, %v", tc.wire, rows, err)
		}
	}
	enc := QUICStream{ID: 2, Data: append([]byte{2}, bytes.Repeat([]byte{0x20}, MaxQUICStreamFrames+1)...)}
	if _, err := DecodeQPACKSections(enc, 64, nil); !errors.Is(err, ErrHTTP3Limit) {
		t.Fatal(err)
	}
}

func TestQPACKStringLimit(t *testing.T) {
	// A value length of 8,193 fits the field section and connection limits.
	value := append([]byte{0x7f, 0x82, 0x3f}, bytes.Repeat([]byte{'a'}, MaxHTTPHeaderLineBytes+1)...)
	field := QPACKSectionInput{Data: append([]byte{0, 0, 0x50}, value...)}
	rows, err := DecodeQPACKSections(QUICStream{}, 0, []QPACKSectionInput{field})
	if err != nil || len(rows) != 1 || rows[0].State != QPACKLimited || len(rows[0].Headers) != 0 {
		t.Fatalf("oversized field value: %+v, %v", rows, err)
	}

	encoder := QUICStream{ID: 2, Data: append([]byte{2, 0xc0}, value...), Complete: true}
	rows, err = DecodeQPACKSections(encoder, MaxQPACKTableBytes, nil)
	if rows != nil || !errors.Is(err, ErrHTTP3Limit) {
		t.Fatalf("oversized encoder value: %+v, %v", rows, err)
	}
}

func TestQPACKAioquicCapture(t *testing.T) {
	// Synthetic aioquic 1.3.0 capture and TShark 4.6.10's decoded fields.
	raw, err := os.ReadFile("testdata/http3-framing.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	connection := keyedQUICBoth(t, raw, nil)[0]
	for _, tc := range []struct {
		packets []QUIC1RTTPacket
		want    []HTTPHeader
	}{
		{connection.Client, []HTTPHeader{{":method", "POST"}, {":scheme", "https"}, {":authority", "fixture.test"}, {":path", "/ingest"}}},
		{connection.Server, []HTTPHeader{{":status", "200"}}},
	} {
		streams, err := keyedQUICStreamData(tc.packets)
		if err != nil {
			t.Fatal(err)
		}
		var enc QUICStream
		var input []QPACKSectionInput
		for _, stream := range streams {
			parsed, err := ParseHTTP3Stream(stream)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Kind == HTTP3StreamQPACKEncoder {
				enc = stream
			}
			for _, frame := range parsed.Frames {
				if frame.Type == HTTP3FrameHeaders {
					input = append(input, QPACKSectionInput{StreamID: stream.ID, Offset: frame.PayloadOffset, Data: stream.Data[frame.PayloadOffset : frame.PayloadOffset+frame.PayloadLength]})
				}
			}
		}
		rows, err := DecodeQPACKSections(enc, 4096, input)
		if err != nil || len(rows) != 1 || rows[0].Offset != 2 || rows[0].State != QPACKDecoded || !slices.Equal(rows[0].Headers, tc.want) {
			t.Fatalf("capture: %+v, %v", rows, err)
		}
	}
}
