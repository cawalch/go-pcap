package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSMB2EvidenceCommandsAndOpenings(t *testing.T) {
	const messageID = 11
	share := smbNameRequest(SMB2CommandTreeConnect, `\\host\share`)
	next := (len(share) + 7) &^ 7
	share = append(share, make([]byte, next-len(share))...)
	binary.LittleEndian.PutUint32(share[20:], uint32(next))
	file := smbNameRequest(SMB2CommandCreate, "file.txt")
	binary.LittleEndian.PutUint64(file[24:], messageID)
	compound := smbSessionFrame(append(share, file...))
	cut := 4 + next + 12
	response := bytes.Clone(file[:64])
	binary.LittleEndian.PutUint32(response[8:], 0xc0000022)
	binary.LittleEndian.PutUint32(response[16:], 1)
	reply := smbSessionFrame(response)
	ntlm := buildSMB2SessionSetupNTLMChallenge()
	transform := smbSessionFrame(smbTransformPacket())
	const transformHeaderEnd = 4 + 52
	const clientStart, serverStart = 1001, 5001
	local, peer := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	client := func(seq uint32, flags uint8, payload []byte) []byte {
		return buildEthernetIPv4TCPFrame(local, peer, 51000, 445, seq, serverStart, flags, payload)
	}
	server := func(seq uint32, flags uint8, payload []byte) []byte {
		return buildEthernetIPv4TCPFrame(peer, local, 445, 51000, seq, clientStart, flags, payload)
	}
	dataEnd := serverStart + uint32(len(reply)+len(ntlm))
	var output bytes.Buffer
	w, err := NewPCAPNGWriter(&output, PCAPNGWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.AddInterface(PCAPNGWriterOptions{LinkType: LinkTypeEthernet})
	if err != nil {
		t.Fatal(err)
	}
	for i, packet := range [][]byte{
		client(clientStart-1, TCPFlagSYN, nil),
		server(serverStart-1, TCPFlagSYN|TCPFlagACK, nil),
		client(clientStart+uint32(cut), TCPFlagACK, compound[cut:]),
		client(clientStart, TCPFlagACK, compound[:cut]),
		client(clientStart, TCPFlagACK, compound[:cut]),
		server(serverStart, TCPFlagACK, reply),
		server(serverStart+uint32(len(reply)), TCPFlagACK, ntlm),
		server(dataEnd, TCPFlagACK, transform[:transformHeaderEnd]),
		server(dataEnd+transformHeaderEnd, TCPFlagACK, transform[transformHeaderEnd:]),
		client(3000, TCPFlagSYN, nil),
		client(3001, TCPFlagACK, smbSessionFrame(file)),
		client(clientStart-1, TCPFlagSYN, nil),
		client(clientStart, TCPFlagACK, file), // Unframed command on the second interface.
	} {
		var record PacketRecord
		if i >= 11 {
			record.InterfaceID = second
		}
		if err := w.WritePacket(record, packet); err != nil {
			t.Fatal(err)
		}
	}
	raw := output.Bytes()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.SeparateTCPInterfaces = true
	records, err := c.SMB(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		opening, packet, offset, length int
		packets                         []int
	}{
		{0, 3, 4, next, []int{3}},
		{0, 3, 4 + next, len(file), []int{2, 3}},
		{0, 5, 4, len(response), []int{5}},
		{0, 6, len(reply) + 4, len(ntlm) - 4, []int{6}},
		{0, 7, len(reply) + len(ntlm) + 4, 52, []int{7}},
		{9, 10, 4, len(file), []int{10}},
		{11, 12, 0, len(file), []int{12}},
	}
	rows := checkReaderParity(t, raw, c.SMB2Evidence, c.SMB2EvidenceFromReaderAt)
	if len(rows) != len(want) || len(records) != len(want) {
		t.Fatalf("got %d evidence rows and %d legacy rows, want %d: %+v", len(rows), len(records), len(want), rows)
	}
	for i, row := range rows {
		loc := want[i]
		if row.SMB2Record != records[i] || row.FlowIndex != 0 ||
			row.OpeningPacket != loc.opening || row.PacketIndex != loc.packet || row.StreamOffset != loc.offset ||
			row.WireLength != loc.length || !reflect.DeepEqual(row.PacketIndices, loc.packets) {
			t.Fatalf("row %d = %+v, want location %+v and SMB record %+v", i, row, loc, records[i])
		}
	}
	if rows[0].Message.ShareName != `\\host\share` || rows[1].Message.FileName != "file.txt" ||
		rows[1].Message.MessageID != messageID || rows[2].Message.MessageID != messageID ||
		!rows[2].Message.IsResponse || rows[2].Message.Status != 0xc0000022 || !rows[3].Message.HasNTLM ||
		!rows[4].Message.IsEncrypted || rows[4].Message.SessionID != 0xfedcba9876543210 || rows[4].Message.HasNTLM ||
		rows[5].Message.MessageID != messageID || rows[6].Message.MessageID != messageID {
		t.Fatalf("unexpected command fields: %+v", rows)
	}

	path := filepath.Join(t.TempDir(), "smb.pcapng")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fileRows, err := c.SMB2EvidenceFromReaderAt(f)
	if err != nil || !reflect.DeepEqual(fileRows, rows) {
		t.Fatalf("file evidence parity: %v", err)
	}
}

func TestSMB2EvidenceProxyOffsets(t *testing.T) {
	const request = "CONNECT host.example:445 HTTP/1.1\r\nHost: host.example:445\r\n\r\n"
	const reply = "HTTP/1.1 200 Connection Established\r\n\r\n"
	share := smbNameRequest(SMB2CommandTreeConnect, `\\host\share`)
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	// Observe the proxy response first, so logical request direction is reversed.
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		buildEthernetIPv4TCPFrame(server, client, 8080, 51000, 1, 1, TCPFlagACK, []byte(reply)),
		buildEthernetIPv4TCPFrame(client, server, 51000, 8080, 1, 1, TCPFlagACK, append([]byte(request), smbSessionFrame(share)...)),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := checkReaderParity(t, raw, c.SMB2Evidence, c.SMB2EvidenceFromReaderAt)
	if len(rows) != 1 || rows[0].SrcPort != 51000 || rows[0].OpeningPacket != 0 || rows[0].PacketIndex != 1 ||
		rows[0].StreamOffset != len(request)+4 || rows[0].WireLength != len(share) {
		t.Fatalf("unexpected proxied evidence: %+v", rows)
	}
}

func TestSMB2EvidenceSpanLimit(t *testing.T) {
	r := SMB2Evidence{WireLength: 64}
	remaining := 1
	spans := []tcpWireSpan{{end: 32}, {end: 64}}
	if err := r.locate(spans, &remaining); !errors.Is(err, ErrSMBLimit) || len(r.PacketIndices) != 0 {
		t.Fatalf("span limit = %v, evidence = %v", err, r.PacketIndices)
	}
}

func TestSMB2EvidenceReaderAtReadsUnrelatedTCP(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	share := smbSessionFrame(smbNameRequest(SMB2CommandTreeConnect, `\\host\share`))
	payload := bytes.Repeat([]byte{'x'}, 1400)
	for _, count := range []int{0, 128} {
		var frames [][]byte
		for i := range count {
			frames = append(frames, buildEthernetIPv4TCPFrame(client, server, 1234, 8080, uint32(i*len(payload)+1), 1, TCPFlagACK, payload))
		}
		frames = append(frames, buildEthernetIPv4TCPFrame(client, server, 1235, 445, 1, 1, TCPFlagACK, share))
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		r := &measuredReaderAt{Reader: bytes.NewReader(raw)}
		c, err := NewFromReaderAt(r, r.Size())
		if err != nil {
			t.Fatal(err)
		}
		r.calls, r.bytesRead = 0, 0
		rows := checkReaderParity(t, raw, c.SMB2Evidence, func(io.ReaderAt) ([]SMB2Evidence, error) {
			return c.SMB2EvidenceFromReaderAt(r)
		})
		if len(rows) != 1 || rows[0].PacketIndex != count {
			t.Fatalf("expected share packet %d, got %+v", count, rows)
		}
		t.Logf("%d unrelated TCP packets: %d bytes in %d reads", count, r.bytesRead, r.calls)
	}
}
