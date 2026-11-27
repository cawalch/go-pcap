package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"testing"
)

func handshakeEvidenceParity(t *testing.T, raw, key []byte, separate bool) []TLSHandshakeEvidence {
	t.Helper()
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.SeparateTCPInterfaces = separate
	rows := checkReaderParity(t, raw, func(data []byte) ([]TLSHandshakeEvidence, error) { return c.TLSHandshakeEvidence(data, key) }, func(r io.ReaderAt) ([]TLSHandshakeEvidence, error) { return c.TLSHandshakeEvidenceFromReaderAt(r, key) })
	hs, err := c.TLSWithKeyLog(raw, key)
	if err != nil || len(hs) != len(rows) {
		t.Fatalf("ordinary TLS returned %d rows, %v", len(hs), err)
	}
	for i, r := range rows {
		if !reflect.DeepEqual(hs[i], r.TLSRecord) {
			t.Fatalf("record %d differs", i)
		}
	}
	return rows
}

func TestTLSHandshakeEvidenceOpenings(t *testing.T) {
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 53}
	var out bytes.Buffer
	opts := PCAPNGWriterOptions{LinkType: LinkTypeEthernet}
	w, err := NewPCAPNGWriter(&out, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.AddInterface(opts); err != nil {
		t.Fatal(err)
	}
	write := func(iface uint32, frame []byte) {
		t.Helper()
		if err := w.WritePacket(PacketRecord{InterfaceID: iface}, frame); err != nil {
			t.Fatal(err)
		}
	}
	hello := buildTLS13ClientHelloRecord("first.example", "h2")
	other := buildTLS13ClientHelloRecord("second.example", "h2")
	proxy := []byte("CONNECT first.example:443 HTTP/1.1\r\n\r\n")
	accepted := []byte("HTTP/1.1 200 OK\r\n\r\n")
	// The server-side prefix arrives first, so proxy recognition reverses the
	// observed direction. A different interface uses the same endpoints.
	write(0, buildEthernetIPv4TCPFrame(server, client, 443, 5000, 10, 0, TCPFlagACK, accepted))
	write(1, buildEthernetIPv4TCPFrame(client, server, 5000, 443, 100, 0, TCPFlagSYN, nil))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, 100, 0, TCPFlagACK, proxy))
	base := 100 + uint32(len(proxy))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, base+5, 0, TCPFlagACK, hello[5:]))
	write(1, buildEthernetIPv4TCPFrame(client, server, 5000, 443, 101, 0, TCPFlagACK, other))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, base, 0, TCPFlagACK, hello[:5]))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, base, 0, TCPFlagACK, hello))
	write(0, buildEthernetIPv4TCPFrame(server, client, 443, 5000, 10+uint32(len(accepted)), 0, TCPFlagACK, buildTLSServerHelloRecord()))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, 4000, 0, TCPFlagSYN, nil))
	write(0, buildEthernetIPv4TCPFrame(client, server, 5000, 443, 4001, 0, TCPFlagACK, other))
	rows := handshakeEvidenceParity(t, out.Bytes(), nil, true)
	if len(rows) != 3 {
		t.Fatalf("got %d rows", len(rows))
	}
	for i, want := range []struct {
		opening        int
		name           string
		client, server []int
	}{{0, "first.example", []int{3, 5}, []int{7}}, {1, "second.example", []int{4}, nil}, {8, "second.example", []int{9}, nil}} {
		got := rows[i]
		if got.FlowIndex != rows[0].FlowIndex || got.OpeningPacket != want.opening || got.Handshake.ClientHello.SNI != want.name || !slices.Equal(got.ClientHello.PacketIndices, want.client) || !slices.Equal(got.ServerHello.PacketIndices, want.server) {
			t.Fatalf("row %d: opening %d hello %s packets %v/%v", i, got.OpeningPacket, got.Handshake.ClientHello.SNI, got.ClientHello.PacketIndices, got.ServerHello.PacketIndices)
		}
	}
}

func TestTLSHandshakeEvidenceCertificates(t *testing.T) {
	chain := sanTestChain(t, []string{"service.example"}, nil, false)
	for _, encrypted := range []bool{false, true} {
		raw := mtlsTestCapture(t, encrypted, chain, chain, true, true)
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		var frames [][]byte
		for pkt, err := range c.PacketSeq(raw) {
			if err != nil {
				t.Fatal(err)
			}
			frame, err := c.PacketPayload(raw, pkt)
			if err != nil {
				t.Fatal(err)
			}
			f, err := DecodeFrame(frame, LinkTypeEthernet)
			if err != nil {
				t.Fatal(err)
			}
			wire := frame[f.PayloadOffset : f.PayloadOffset+f.PayloadLength]
			helloEnd := 5 + int(binary.BigEndian.Uint16(wire[3:5]))
			certEnd := helloEnd + 5 + int(binary.BigEndian.Uint16(wire[helloEnd+3:helloEnd+5]))
			for _, chunk := range [][2]int{{0, helloEnd}, {helloEnd, certEnd - 1}, {certEnd - 1, certEnd}, {certEnd, len(wire)}} {
				if chunk[0] == chunk[1] {
					continue
				}
				frames = append(frames, buildEthernetIPv4TCPFrame(f.SrcAddr.As4(), f.DstAddr.As4(), f.SrcPort, f.DstPort, f.TCPSeq+uint32(chunk[0]), 0, TCPFlagACK, wire[chunk[0]:chunk[1]]))
			}
		}
		var key []byte
		if encrypted {
			key = c.Secrets[0].Data
		}
		raw = buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames)
		row := handshakeEvidenceParity(t, raw, key, false)[0]
		client := len(frames) - 3
		if !slices.Equal(row.ServerHello.PacketIndices, []int{0}) || !slices.Equal(row.ClientHello.PacketIndices, []int{client}) ||
			!slices.Equal(row.ServerCertificates.PacketIndices, []int{1, 2}) || !slices.Equal(row.ClientCertificates.PacketIndices, []int{client + 1, client + 2}) ||
			row.ServerCertificates.Protected != encrypted || row.ClientCertificates.Protected != encrypted {
			t.Fatalf("encrypted=%t hello %v/%v cert %v/%v", encrypted, row.ClientHello, row.ServerHello, row.ClientCertificates, row.ServerCertificates)
		}
		if encrypted {
			without := handshakeEvidenceParity(t, raw, nil, false)[0]
			if len(without.ServerCertificates.PacketIndices)+len(without.ClientCertificates.PacketIndices) != 0 {
				t.Fatal("missing keys produced evidence")
			}
		}
	}
}

func TestTLSHandshakeEvidenceRecordLimit(t *testing.T) {
	// Keyed scanning charges control records as well as records that
	// authenticate and produce a field.
	trace := tlsHandshakeTrace{mapper: tlsRecordMapper{budget: &tlsProvenanceBudget{records: 1}}}
	first := buildTLS13ClientHelloRecord("limit.example", "h2")
	_, err := parseTLSRecords(append(first, first...), nil, &trace)
	if !errors.Is(err, ErrTLSLimit) || !trace.limited {
		t.Fatalf("scan error %v, limited %t", err, trace.limited)
	}
}

func TestTLSHandshakeEvidenceSharedAndSplitRecords(t *testing.T) {
	chain := sanTestChain(t, []string{"trace.example"}, nil, false)
	client, server := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	hello := buildTLS13ClientHelloRecord("trace.example", "h2")
	serverHello := buildTLSServerHelloRecord()
	for _, protected := range []bool{false, true} {
		packets := [][]byte{buildEthernetIPv4TCPFrame(client, server, 5000, 443, 1, 0, TCPFlagACK, hello)}
		var seq uint32 = 10
		add := func(wire []byte) {
			packets = append(packets, buildEthernetIPv4TCPFrame(server, client, 443, 5000, seq, 0, TCPFlagACK, wire))
			seq += uint32(len(wire))
		}
		cert := certificateTestRecord(chain, protected)[5:]
		var key []byte
		var wantHello, wantCert []int
		if protected {
			secret := bytes.Repeat([]byte{0x77}, 32)
			key = fmt.Appendf(nil, "SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", bytes.Repeat([]byte{0x42}, 32), secret)
			add(serverHello)
			// An authenticated record before the certificate carries no part of it.
			add(encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 0, TLSRecordHandshake, []byte{8, 0, 0, 0}))
			a := encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 1, TLSRecordHandshake, cert[:4])
			add(a[:5])
			add(a[5:])
			add(encryptTLS13AppDataRecord(t, secret, TLS_AES_128_GCM_SHA256, 2, TLSRecordHandshake, append(bytes.Clone(cert[4:]), 20, 0, 0, 0)))
			wantHello, wantCert = []int{1}, []int{3, 4, 5}
		} else {
			// Two plaintext messages share the record header. Each payload
			// lives in its own packet, so their attribution diverges.
			header := bytes.Clone(serverHello[:5])
			binary.BigEndian.PutUint16(header[3:], uint16(len(serverHello)-5+len(cert)))
			add(header)
			add(serverHello[5:])
			add(cert)
			wantHello, wantCert = []int{1, 2}, []int{1, 3}
		}
		raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, packets)
		row := handshakeEvidenceParity(t, raw, key, false)[0]
		if !slices.Equal(row.ServerHello.PacketIndices, wantHello) || !slices.Equal(row.ServerCertificates.PacketIndices, wantCert) ||
			row.ServerCertificates.Protected != protected {
			t.Fatalf("protected=%t hello=%v certificates=%v", protected, row.ServerHello, row.ServerCertificates)
		}
	}
}
