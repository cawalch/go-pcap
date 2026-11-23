package pcap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const dohTestQuery = "\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02c2\x07example\x03com\x00\x00\x01\x00\x01"

func TestDNSOverHTTPS(t *testing.T) {
	query := []byte(dohTestQuery)
	reply := buildDNSQueryResponsePacket()
	typed := HTTPHeader{"content-type", "application/dns-message"}
	encoded := base64.RawURLEncoding.EncodeToString(query)
	getPath := "/resolver?a=1&dns=" + encoded
	for _, tc := range []struct {
		name     string
		block    HTTP2HeaderBlock
		body     []byte
		match    bool
		response bool
		err      error
	}{
		{"typed post", HTTP2HeaderBlock{Method: "POST", Headers: []HTTPHeader{typed}}, query, true, false, nil},
		{"custom get endpoint", HTTP2HeaderBlock{Method: "GET", Path: getPath}, nil, true, false, nil},
		{"percent-escaped name and value", HTTP2HeaderBlock{Method: "GET", Path: "/?dn%73=%45" + encoded[1:]}, nil, true, false, nil},
		{"duplicate parameter", HTTP2HeaderBlock{Method: "GET", Path: getPath + "&dn%73=x"}, nil, true, false, ErrInvalidDNS},
		{"malformed escape", HTTP2HeaderBlock{Method: "GET", Path: "/?dns=%zz"}, nil, true, false, ErrInvalidDNS},
		{"padded base64", HTTP2HeaderBlock{Method: "GET", Path: getPath + "="}, nil, true, false, ErrInvalidDNS},
		{"base64 newline", HTTP2HeaderBlock{Method: "GET", Path: getPath + "%0A"}, nil, true, false, ErrInvalidDNS},
		{"no parameter", HTTP2HeaderBlock{Method: "GET", Path: "/dns-query?name=example.org&type=A"}, nil, false, false, nil},
		{"oversize path", HTTP2HeaderBlock{Method: "GET", Path: getPath + strings.Repeat("a", MaxHTTPHeaderLineBytes)}, nil, false, false, ErrHTTPLimit},
		{"duplicate path", HTTP2HeaderBlock{Method: "GET", Path: getPath, Headers: []HTTPHeader{{":path", getPath}, {":path", getPath}}}, nil, false, false, nil},
		{"typed response", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed}}, reply, true, true, nil},
		{"case-insensitive media type and identity coding", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{{"Content-Type", "Application/DNS-Message"}, {"Content-Encoding", "identity"}}}, reply, true, true, nil},
		{"no content response", HTTP2HeaderBlock{Status: "204", Headers: []HTTPHeader{typed}}, reply, false, false, nil},
		{"reset content response", HTTP2HeaderBlock{Status: "205", Headers: []HTTPHeader{typed}}, reply, false, false, nil},
		{"error response", HTTP2HeaderBlock{Status: "400", Headers: []HTTPHeader{typed}}, reply, false, false, nil},
		{"trailer", HTTP2HeaderBlock{Headers: []HTTPHeader{typed}}, reply, false, false, nil},
		{"wrong media type", HTTP2HeaderBlock{Method: "POST", Headers: []HTTPHeader{{"content-type", "application/dns-json"}}}, query, false, false, nil},
		{"missing media type", HTTP2HeaderBlock{Method: "POST"}, query, false, false, nil},
		{"duplicate media type", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed, typed}}, reply, false, false, nil},
		{"encoded body", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed, {"content-encoding", "gzip"}}}, reply, false, false, nil},
		{"invalid dns", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed}}, []byte{1}, true, false, ErrInvalidDNS},
		{"reply as request", HTTP2HeaderBlock{Method: "POST", Headers: []HTTPHeader{typed}}, reply, true, false, ErrInvalidDNS},
		{"query as response", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed}}, query, true, false, ErrInvalidDNS},
		{"oversize body", HTTP2HeaderBlock{Status: "200", Headers: []HTTPHeader{typed}}, make([]byte, 65536), true, false, ErrDNSLimit},
		{"oversize header count", HTTP2HeaderBlock{Status: "200", Headers: make([]HTTPHeader, MaxHTTPHeaders+1)}, reply, false, false, ErrHTTPLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, ok, err := tc.block.DNSOverHTTPS(tc.body)
			if ok != tc.match || !errors.Is(err, tc.err) {
				t.Fatalf("match %v, error %v, want %v and %v", ok, err, tc.match, tc.err)
			}
			if !ok || err != nil {
				return
			}
			wantAnswers := 0
			if tc.response {
				wantAnswers = 2
			}
			if msg.IsResponse != tc.response || msg.TransactionID != 0x1337 || len(msg.Questions) != 1 ||
				msg.Questions[0].Name != "c2.example.com" || len(msg.Answers) != wantAnswers {
				t.Fatalf("unexpected DNS message %+v", msg)
			}
		})
	}
}

func TestDNSOverHTTPSDecryptedExchange(t *testing.T) {
	const media = "application/dns-message"
	const authority = "example.org"
	path := "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString([]byte(dohTestQuery))
	// Indexed GET and https, then literals using the indexed :authority and :path names.
	request := append([]byte{0x82, 0x87, 0x01, byte(len(authority))}, authority...)
	request = append(request, 0x04, byte(len(path)))
	request = append(request, path...)
	settings := buildHTTP2Frame(HTTP2FrameSettings, 0, 0, nil)
	clientFrames := bytes.Join([][]byte{HTTP2ClientPreface, settings, buildHTTP2Frame(HTTP2FrameHeaders, 5, 1, request)}, nil)

	// Indexed :status 200, then content-type as a literal with indexed name 31.
	reply := append([]byte{0x88, 0x0f, 16, byte(len(media))}, media...)
	serverFrames := bytes.Join([][]byte{
		settings,
		buildHTTP2Frame(HTTP2FrameHeaders, 4, 1, reply),
		buildHTTP2Frame(HTTP2FrameData, 1, 1, buildDNSQueryResponsePacket()),
	}, nil)
	clientKey := bytes.Repeat([]byte{0xaa}, 32)
	serverKey := bytes.Repeat([]byte{0xbb}, 32)
	client := append(buildTLS13ClientHelloRecord(authority, "h2"), encryptTLS13AppDataRecord(t, clientKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, clientFrames)...)
	server := append(buildTLSServerHelloRecord(), encryptTLS13AppDataRecord(t, serverKey, TLS_AES_128_GCM_SHA256, 0, TLSRecordApplicationData, serverFrames)...)
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	random := bytes.Repeat([]byte{0x42}, 32)
	keys := fmt.Appendf(nil, "CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, clientKey, random, serverKey)
	raw := buildPCAPNGFixture(binary.LittleEndian, keys, [][]byte{
		buildEthernetIPv4TCPFrame(a, b, 40000, 443, 1, 0, TCPFlagACK, client),
		buildEthernetIPv4TCPFrame(b, a, 443, 40000, 1, 0, TCPFlagACK, server),
	})
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.HTTP2(raw)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	for i, row := range rows {
		if row.IsServer != (i == 1) || !row.IsDecrypted || len(row.Summary.Streams) != 1 || row.FlowIndex != rows[0].FlowIndex {
			t.Fatalf("row %+v", row)
		}
		st := row.Summary.Streams[0]
		if st.StreamID != 1 || len(st.HeaderBlocks) != 1 {
			t.Fatalf("stream %+v", st)
		}
		msg, match, err := st.HeaderBlocks[0].DNSOverHTTPS(st.Data)
		if err != nil || !match || msg.IsResponse != row.IsServer || msg.TransactionID != 0x1337 || len(msg.Answers) != 2*i {
			t.Fatalf("message %+v, match %v, error %v", msg, match, err)
		}
	}
}
