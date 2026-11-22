package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func smbNameRequest(command uint16, name string) []byte {
	fixed, field := 56, 44
	if command == SMB2CommandTreeConnect {
		fixed, field = 8, 4
	}
	buf := make([]byte, 64+fixed)
	copy(buf, smb2Magic)
	binary.LittleEndian.PutUint16(buf[4:], 64)
	binary.LittleEndian.PutUint16(buf[12:], command)
	binary.LittleEndian.PutUint32(buf[36:], 0x12345678)
	binary.LittleEndian.PutUint64(buf[40:], 0x0123456789abcdef)
	binary.LittleEndian.PutUint16(buf[64:], uint16(fixed+1))
	raw := encodeUTF16LE(name)
	binary.LittleEndian.PutUint16(buf[64+field:], uint16(len(buf)))
	binary.LittleEndian.PutUint16(buf[66+field:], uint16(len(raw)))
	if len(raw) == 0 {
		return append(buf, 0)
	}
	return append(buf, raw...)
}

func smbTransformPacket() []byte {
	p := make([]byte, 52+64)
	copy(p, []byte{0xfd, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint32(p[36:], 64)
	binary.LittleEndian.PutUint16(p[42:], 1)
	binary.LittleEndian.PutUint64(p[44:], 0xfedcba9876543210)
	copy(p[52:], ntlmsspSig)
	return p
}

func smbSessionFrame(p []byte) []byte {
	return append([]byte{0, byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p))}, p...)
}

func BenchmarkCaptureSMBPaths(b *testing.B) {
	for _, tc := range []struct {
		name   string
		frames [][]byte
	}{
		{"SessionSetup", [][]byte{buildSMB2SessionSetupNTLMChallenge()}},
		{"Paths", [][]byte{smbSessionFrame(smbNameRequest(SMB2CommandTreeConnect, `\\server\IPC$`)), smbSessionFrame(smbNameRequest(SMB2CommandCreate, `srvsvc`)), smbSessionFrame(smbNameRequest(SMB2CommandCreate, `reports\新📄.txt`))}},
		{"Transforms", [][]byte{smbSessionFrame(smbTransformPacket())}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var packets [][]byte
			for i := range 16 {
				stream := bytes.Join(tc.frames, nil)
				packets = append(packets, buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, uint16(50000+i), 445, 1, 0, TCPFlagACK, stream))
			}
			raw := buildPCAPNGFixture(binary.LittleEndian, nil, packets)
			c, err := New(raw)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.SMB(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSMBPathAndTransformParity(t *testing.T) {
	share := smbNameRequest(SMB2CommandTreeConnect, `\\server\IPC$`)
	pipe := smbNameRequest(SMB2CommandCreate, "srvsvc")
	file := smbNameRequest(SMB2CommandCreate, `reports\新📄.txt`)
	transform := smbTransformPacket()
	// Put a recognizable NTLM challenge header into the opaque payload to catch accidental decoding.
	copy(transform[52:], buildSMB2SessionSetupNTLMChallenge()[4+64+8:])
	want := []SMB2Message{
		{Command: SMB2CommandTreeConnect, ShareName: `\\server\IPC$`},
		{Command: SMB2CommandCreate, FileName: "srvsvc"},
		{Command: SMB2CommandCreate, FileName: `reports\新📄.txt`},
		{IsEncrypted: true, OriginalMessageSize: 64, SessionID: 0xfedcba9876543210},
	}
	for i, raw := range [][]byte{share, pipe, file, transform} {
		if !want[i].IsEncrypted {
			want[i].SessionID = 0x0123456789abcdef
			want[i].TreeID = 0x12345678
		}
		for _, wire := range [][]byte{raw, smbSessionFrame(raw)} {
			got, err := ParseSMB2Message(wire)
			if err != nil || got != want[i] {
				t.Fatalf("message %d: %+v, %v; want %+v", i, got, err, want[i])
			}
		}
	}
	// TREE_CONNECT and CREATE share a single NetBIOS frame. Split the
	// following filename across TCP segments, then append a transform frame.
	next := (len(share) + 7) &^ 7
	compound := make([]byte, next)
	copy(compound, share)
	binary.LittleEndian.PutUint32(compound[20:], uint32(next))
	compound = append(compound, pipe...)
	got, err := ParseSMB2Message(smbSessionFrame(compound))
	if err != nil || got != want[0] {
		t.Fatal(got, err)
	}
	first := smbSessionFrame(compound)
	stream := append(first, smbSessionFrame(file)...)
	stream = append(stream, smbSessionFrame(transform)...)
	split := len(first) + 4 + 120 + 3
	var frames [][]byte
	seq := uint32(1)
	for _, segment := range [][]byte{stream[:split], stream[split:]} {
		frames = append(frames, buildEthernetIPv4TCPFrame([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 50000, 445, seq, 0, TCPFlagACK, segment))
		seq += uint32(len(segment))
	}
	for _, raw := range [][]byte{buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, frames), buildPCAPNGFixture(binary.BigEndian, nil, frames)} {
		c, err := New(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.SMB(raw)
		if err != nil || len(rows) != len(want) {
			t.Fatalf("%d messages, %v", len(rows), err)
		}
		for i := range rows {
			if rows[i].Message != want[i] {
				t.Fatalf("%d: %+v; want %+v", i, rows[i].Message, want[i])
			}
		}
	}
}

func TestSMBRequestBounds(t *testing.T) {
	for _, tc := range []struct {
		cmd   uint16
		field int
	}{{SMB2CommandTreeConnect, 68}, {SMB2CommandCreate, 108}} {
		req := smbNameRequest(tc.cmd, "ab")
		for i := range req {
			if _, err := ParseSMB2Message(req[:i]); !errors.Is(err, ErrInvalidSMB) {
				t.Fatalf("command %d prefix %d: %v", tc.cmd, i, err)
			}
		}
		for _, v := range []struct {
			at    int
			value uint16
		}{{64, 8}, {tc.field, 32}, {tc.field, 0xfffe}, {tc.field + 2, 3}, {tc.field + 2, 0xfffe}} {
			p := bytes.Clone(req)
			binary.LittleEndian.PutUint16(p[v.at:], v.value)
			if _, err := ParseSMB2Message(p); !errors.Is(err, ErrInvalidSMB) {
				t.Fatalf("command %d field %d: %v", tc.cmd, v.at, err)
			}
		}
		for _, n := range []int{MaxOptionStringBytes / 2, MaxOptionStringBytes/2 + 1} {
			got, err := ParseSMB2Message(smbNameRequest(tc.cmd, strings.Repeat("x", n)))
			if n == MaxOptionStringBytes/2 {
				if err != nil || len(got.FileName)+len(got.ShareName) != n {
					t.Fatal(n, err)
				}
			} else if !errors.Is(err, ErrSMBLimit) {
				t.Fatal(n, err)
			}
		}
		binary.LittleEndian.PutUint32(req[16:], 3) // Asynchronous response: no TreeID or request name.
		got, err := ParseSMB2Message(req[:64])
		if err != nil || !got.IsResponse || got.TreeID != 0 || got.FileName != "" || got.ShareName != "" {
			t.Fatal(got, err)
		}
	}
	root := smbNameRequest(SMB2CommandCreate, "")
	got, err := ParseSMB2Message(root)
	if err != nil || got.FileName != "" {
		t.Fatal(got, err)
	}
	x := smbTransformPacket()
	for n := range 52 {
		if _, err := ParseSMB2Message(x[:n]); !errors.Is(err, ErrInvalidSMB) {
			t.Fatal(n, err)
		}
	}
	if got, err := ParseSMB2Message(x[:52]); err != nil || !got.IsEncrypted {
		t.Fatal(got, err)
	}
	if _, err := ParseSMB2Message(smbSessionFrame(x)[:56]); !errors.Is(err, ErrInvalidSMB) {
		t.Fatal(err)
	}
	if _, err := ParseSMB2Message([]byte{0, 1, 0, 1}); !errors.Is(err, ErrSMBLimit) {
		t.Fatal(err)
	}
	x[0] = 0xff
	if _, err := ParseSMB2Message(x); !errors.Is(err, ErrInvalidSMB) {
		t.Fatal(err)
	}
}

func TestSMBCommandOffsets(t *testing.T) {
	p := smbNameRequest(SMB2CommandTreeConnect, `\\host\ext`)
	binary.LittleEndian.PutUint16(p[66:], 4)
	if _, err := ParseSMB2Message(p); !errors.Is(err, ErrInvalidSMB) {
		t.Fatal(err)
	}
	p = append(append(bytes.Clone(p[:72]), make([]byte, 16)...), p[72:]...)
	binary.LittleEndian.PutUint16(p[68:], 88)
	if got, err := ParseSMB2Message(p); err != nil || got.ShareName != `\\host\ext` {
		t.Fatal(got, err)
	}
	next := (len(p) + 7) &^ 7
	buf := make([]byte, next)
	copy(buf, p)
	buf = append(buf, smbNameRequest(SMB2CommandCreate, "pipe")...)
	binary.LittleEndian.PutUint32(buf[20:], uint32(next))
	binary.LittleEndian.PutUint16(buf[68:], uint16(next))
	if _, err := ParseSMB2Message(buf); !errors.Is(err, ErrInvalidSMB) {
		t.Fatal("name crosses compound boundary", err)
	}
	for _, off := range []uint32{4, 65, uint32(len(buf)), 0xffffffff} {
		binary.LittleEndian.PutUint32(buf[20:], off)
		if _, err := ParseSMB2Message(buf); !errors.Is(err, ErrInvalidSMB) {
			t.Fatal(off, err)
		}
	}
}
