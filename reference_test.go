package pcap

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// FoxIO's version, capture names and frame numbers are in testdata/foxio/README.md.
func TestFoxIOReferenceFingerprints(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile("testdata/foxio/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	ch, err := ParseTLSRecords(read("grease-client.tls"))
	if err != nil || ch.ClientHello.JA4 != "t13d1517h2_8daaf6152771_cb7bf5808d99" {
		t.Errorf("JA4 = %q, %v", ch.ClientHello.JA4, err)
	}
	sh, err := ParseTLSRecords(read("h2-server.tls"))
	if err != nil || sh.ServerHello.JA4S != "t1204h2_cca9_1428ce7b4018" {
		t.Errorf("JA4S = %q, %v", sh.ServerHello.JA4S, err)
	}
	x, err := JA4XFromDER(read("h2-leaf.der"))
	if err != nil || x != "7d5dbb3783b4_ba7ce0880c07_7bf9a7bf7029" {
		t.Errorf("JA4X = %q, %v", x, err)
	}
	for _, tc := range []struct{ request, want string }{
		{"GET / HTTP/1.1\r\n" +
			"Host: localhost:8000\r\n" +
			"User-Agent: curl/8.1.2\r\n" +
			"Accept: */*\r\n" +
			"Referer: https://fake.example\r\n" +
			"Cookie: yummy_cookie=choco; tasty_cookie=strawberry\r\n" +
			"Accept-Language: da, en-GB;q=0.8, en;q=0.7\r\n" +
			"\r\n", "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"},
		{"GET / HTTP/1.0\r\n" +
			"User-Agent:\r\n" +
			"\r\n", "ge10nn010000_b8bcd45ac095_000000000000_000000000000"},
	} {
		r, _, err := ParseHTTPRequest([]byte(tc.request))
		if err != nil || r.JA4H != tc.want {
			t.Errorf("JA4H(%s) = %q, %v", tc.request, r.JA4H, err)
		}
	}
	for _, tc := range []struct{ options, want string }{
		{"02040542010303060101080a6e69087c0000000004020000", "65535_2-1-3-1-1-8-4-0-0_1346_6"},
		{"02040542010104020103030a", "65535_2-1-1-4-1-3_1346_10"},
	} {
		opts, err := hex.DecodeString(tc.options)
		if err != nil {
			t.Fatal(err)
		}
		if fp, ok := JA4T(65535, opts); !ok || fp != tc.want {
			t.Errorf("JA4T/TS = %q, %v", fp, ok)
		}
	}
	if fp := JA4L(65000, 128); fp != "32_128" {
		t.Errorf("client JA4L = %q", fp)
	}
	if fp := JA4L(7831000, 57); fp != "3916_57" {
		t.Errorf("server JA4L = %q", fp)
	}
	var segs []JA4SSHSegment
	for _, v := range strings.Fields(string(read("ssh-window.txt"))) {
		length, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		client := length > 0
		if !client {
			length = -length
		}
		segs = append(segs, JA4SSHSegment{IsClient: client, PayloadLength: length, Flags: TCPFlagACK})
	}
	if fp := JA4SSH(segs); fp != "c36s36_c76s124_c0s0" {
		t.Errorf("JA4SSH = %q", fp)
	}
}
