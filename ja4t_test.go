package pcap

import "testing"

func TestJA4TFingerprint(t *testing.T) {
	// Options: MSS(2)=1460, SACKPerm(4), TS(8), NOP(1), WS(3)=8
	opts := []byte{
		2, 4, 0x05, 0xb4, // MSS = 1460
		4, 2, // SACK Permitted
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
		1,       // NOP
		3, 3, 8, // Window scale = 8
	}
	fp, ok := JA4T(64240, opts)
	if !ok {
		t.Fatal("JA4T() ok = false, want true")
	}
	const want = "64240_2-4-8-1-3_1460_8"
	if fp != want {
		t.Fatalf("JA4T() = %q, want %q", fp, want)
	}

	// Empty options -> "window_00_00_00"
	emptyFP, ok := JA4T(8192, nil)
	if !ok || emptyFP != "8192_00_00_00" {
		t.Fatalf("JA4T(nil) = (%q, %v), want (\"8192_00_00_00\", true)", emptyFP, ok)
	}
}

func TestJA4LAndJA4SSHFingerprints(t *testing.T) {
	// Issue #11: JA4L (<half_rtt_us>_<ttl>) and JA4SSH (c<mode>s<mode>_c<pkts>s<pkts>_c<acks>s<acks>).
	// 2,400,000 ns (2.4 ms) delta -> half RTT = 1,200 us.
	if got := JA4L(2_400_000, 64); got != "1200_64" {
		t.Fatalf("JA4L(2.4ms, 64) = %q, want \"1200_64\"", got)
	}

	segs := []JA4SSHSegment{
		{IsClient: true, PayloadLength: 36, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: true, PayloadLength: 36, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: true, PayloadLength: 76, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: false, PayloadLength: 36, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: false, PayloadLength: 76, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: false, PayloadLength: 76, Flags: TCPFlagPSH | TCPFlagACK},
		{IsClient: true, PayloadLength: 0, Flags: TCPFlagACK},
		{IsClient: true, PayloadLength: 0, Flags: TCPFlagACK},
		{IsClient: false, PayloadLength: 0, Flags: TCPFlagACK},
	}
	if got := JA4SSH(segs); got != "c36s76_c3s3_c2s1" {
		t.Fatalf("JA4SSH() = %q, want \"c36s76_c3s3_c2s1\"", got)
	}
}
