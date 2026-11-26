package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCompileBPFFilter(t *testing.T) {
	frames := bpfPortFrames()
	for _, tt := range []struct {
		expression string
		wanted     []int
	}{
		{"ip and port 53", []int{0, 1, 2, 4, 6}},
		{"ip and tcp port 53", []int{0, 6}},
		{"\tip and\n udp port 53 \r", []int{1, 4}},
		{"ip and udp port 65535", []int{3}},
		{"ip and tcp port 0", []int{10}},
	} {
		t.Run(tt.expression, func(t *testing.T) {
			program, err := CompileBPFFilter(tt.expression, LinkTypeEthernet)
			if err != nil || len(program) == 0 || len(program) > MaxBPFFilterInstructions {
				t.Fatalf("compile = %d instructions, %v", len(program), err)
			}
			var matched []int
			for i, frame := range frames {
				if snap, ok := EvalBPF(program, frame); ok {
					if snap != DefaultLiveSnapLen {
						t.Fatalf("snapshot length = %d", snap)
					}
					matched = append(matched, i)
				}
			}
			if !slices.Equal(matched, tt.wanted) {
				t.Fatalf("matched frames = %v, want %v", matched, tt.wanted)
			}
		})
	}
	for _, expression := range []string{"", strings.Repeat(" ", 128), " \n\t"} {
		program, err := CompileBPFFilter(expression, LinkTypeRaw)
		if _, ok := EvalBPF(program, nil); program != nil || err != nil || !ok {
			t.Fatalf("empty expression = %v, %v", program, err)
		}
	}
	for _, expression := range []string{
		"tcp port 53", "ip and src port 53", "ip and udp port domain", "ip and port +53",
		"ip and port 65536", "ip and port 053", "ip and port 0x35", "ip and port -1",
		"ip and port 53 or ip", "ip and port", "IP and port 53", "ip and\u00a0port 53",
		strings.Repeat(" ", 129),
	} {
		program, err := CompileBPFFilter(expression, LinkTypeEthernet)
		if program != nil || !errors.Is(err, ErrUnsupportedBPFFilterExpression) {
			t.Errorf("%q = %v, %v", expression, program, err)
		}
	}
	if program, err := CompileBPFFilter("ip and port 53", LinkTypeRaw); program != nil || !errors.Is(err, ErrUnsupportedDataLink) {
		t.Fatalf("raw datalink = %v, %v", program, err)
	}
}

func TestCompileBPFFilterTCPDumpParity(t *testing.T) {
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump unavailable")
	}
	frames := bpfPortFrames()
	raw := buildClassicPCAP(binary.LittleEndian, true, LinkTypeEthernet, 65535, frames)
	path := filepath.Join(t.TempDir(), "filters.pcap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{"ip and port 53", "ip and tcp port 53", "ip and udp port 53"} {
		t.Run(expression, func(t *testing.T) {
			program, err := CompileBPFFilter(expression, LinkTypeEthernet)
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), tcpdump, "-n", "-ddd", "-r", path, expression).Output()
			if err != nil {
				t.Fatal(err)
			}
			r := bytes.NewReader(output)
			var count int
			if _, err := fmt.Fscan(r, &count); err != nil || count < 1 || count > MaxBPFFilterInstructions {
				t.Fatalf("tcpdump instruction count = %d, %v", count, err)
			}
			reference := make([]BPFInstruction, count)
			for i := range reference {
				in := &reference[i]
				if _, err := fmt.Fscan(r, &in.Code, &in.JT, &in.JF, &in.K); err != nil {
					t.Fatal(err)
				}
			}
			for i, frame := range frames {
				_, want := EvalBPF(reference, frame)
				if _, got := EvalBPF(program, frame); got != want {
					t.Fatalf("frame %d accepted = %v, tcpdump = %v", i, got, want)
				}
			}
		})
	}
}

func bpfPortFrames() [][]byte {
	src, dst := [4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 14}
	tcp := buildEthernetIPv4TCPFrame(src, dst, 53, 53000, 1, 1, TCPFlagACK, nil)
	udp := buildEthernetIPv4UDPFrame(dst, src, 53000, 53, []byte("dns"))
	sctp := bytes.Clone(tcp)
	sctp[23] = IPProtoSCTP
	otherPort := bytes.Clone(udp)
	binary.BigEndian.PutUint16(otherPort[36:38], 65535)
	firstFragment := buildEthernetIPv4UDPFrame(dst, src, 53000, 53, []byte("dnsquery"))
	binary.BigEndian.PutUint16(firstFragment[38:40], 24)
	firstFragment[20] = 0x20 // More Fragments set, fragment offset zero.
	laterFragment := bytes.Clone(firstFragment)
	laterFragment[21] = 1
	options := append(bytes.Clone(tcp[:34]), 1, 1, 1, 1)
	options = append(options, tcp[34:]...)
	options[14] = 0x46
	binary.BigEndian.PutUint16(options[16:18], uint16(len(options)-14))
	ipv6 := append(bytes.Clone(tcp[:14]), ipipIPv6(IPProtoTCP, tcp[34:])...)
	binary.BigEndian.PutUint16(ipv6[12:14], EtherTypeIPv6)
	vlan := append(bytes.Clone(tcp[:12]), 0x81, 0, 0, 1)
	vlan = append(vlan, tcp[12:]...)
	zero := bytes.Clone(tcp)
	clear(zero[34:36])
	return [][]byte{tcp, udp, sctp, otherPort, firstFragment, laterFragment, options, ipv6, vlan, udp[:37], zero}
}

func BenchmarkCompileBPFFilter(b *testing.B) {
	const expression = "ip and port 53"
	b.ReportAllocs()
	for b.Loop() {
		program, err := CompileBPFFilter(expression, LinkTypeEthernet)
		if err != nil || len(program) != 15 {
			b.Fatalf("compile = %d instructions, %v", len(program), err)
		}
	}
}
