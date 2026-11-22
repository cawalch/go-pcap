package pcap

import (
	"encoding/binary"
	"testing"
)

func TestFlowHandshakeTimestampOptions(t *testing.T) {
	valid := []byte{8, 10, 1, 2, 3, 4, 0, 0, 0, 5}
	want := TCPTimestamp{TSval: 0x01020304, TSecr: 5, Present: true}
	for _, tc := range []struct {
		name string
		opts []byte
		want TCPTimestamp
	}{
		{"absent", nil, TCPTimestamp{}},
		{"zero", []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}, TCPTimestamp{Present: true}},
		{"other option", append([]byte{4, 2}, valid...), want},
		{"EOL before timestamp", append([]byte{0, 1}, valid...), TCPTimestamp{}},
		{"EOL after timestamp", append(append([]byte{}, valid...), 0, 255), want},
		{"truncated timestamp", []byte{8, 10, 0, 0}, TCPTimestamp{}},
		{"short timestamp", []byte{8, 4, 0, 0}, TCPTimestamp{}},
		{"malformed following option", append(append([]byte{}, valid...), 30, 0), TCPTimestamp{}},
		{"missing length", []byte{1, 1, 1, 8}, TCPTimestamp{}},
		{"duplicate", append(append([]byte{}, valid...), valid...), TCPTimestamp{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
				handshakeFrame(12345, TCPFlagSYN|TCPFlagACK, tc.opts),
				handshakeFrame(12345, TCPFlagSYN, tc.opts),
			})
			pair := singleFlowBothReaders(t, raw)
			if pair[0] != pair[1] || pair[0].SYNTimestamp != tc.want || pair[0].SYNACKTimestamp != tc.want {
				t.Fatalf("slice %+v, ReaderAt %+v, want timestamps %+v", pair[0], pair[1], tc.want)
			}
		})
	}
}

func TestFlowHandshakeTimestampSelection(t *testing.T) {
	client := []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	server := []byte{1, 1, 8, 10, 0, 0, 0, 9, 0, 0, 0, 6}
	raw := buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, [][]byte{
		handshakeFrame(12345, TCPFlagSYN|TCPFlagACK, server),
		handshakeFrame(12345, TCPFlagACK, server),
		handshakeFrame(12345, TCPFlagSYN, []byte{8, 4, 0, 0}),
		handshakeFrame(12345, TCPFlagSYN, client),
		handshakeFrame(12345, TCPFlagSYN, server),
		handshakeFrame(12345, TCPFlagSYN|TCPFlagACK, client),
	})
	for _, f := range singleFlowBothReaders(t, raw) {
		if f.SYNTimestamp != (TCPTimestamp{Present: true}) || f.SYNACKTimestamp != (TCPTimestamp{TSval: 9, TSecr: 6, Present: true}) {
			t.Fatalf("SYN %+v, SYN-ACK %+v", f.SYNTimestamp, f.SYNACKTimestamp)
		}
	}
}
