package pcap

import (
	"encoding/binary"
	"net/netip"
)

// Classic BPF instruction class, size, mode, and operation flags.
const (
	bpfClassLD   uint16 = 0x00
	bpfClassLDX  uint16 = 0x01
	bpfClassST   uint16 = 0x02
	bpfClassSTX  uint16 = 0x03
	bpfClassALU  uint16 = 0x04
	bpfClassJMP  uint16 = 0x05
	bpfClassRET  uint16 = 0x06
	bpfClassMISC uint16 = 0x07

	bpfSizeW uint16 = 0x00
	bpfSizeH uint16 = 0x08
	bpfSizeB uint16 = 0x10

	bpfModeIMM uint16 = 0x00
	bpfModeABS uint16 = 0x20
	bpfModeIND uint16 = 0x40
	bpfModeMEM uint16 = 0x60
	bpfModeLEN uint16 = 0x80
	bpfModeMSH uint16 = 0xa0

	bpfOpJA   uint16 = 0x00
	bpfOpJEQ  uint16 = 0x10
	bpfOpJGT  uint16 = 0x20
	bpfOpJGE  uint16 = 0x30
	bpfOpJSET uint16 = 0x40

	bpfSrcK uint16 = 0x00
	bpfSrcX uint16 = 0x08
	bpfRetA uint16 = 0x10
)

// BPFFilterIPProtocol returns a classic BPF program for Ethernet frames that
// accepts IPv4 or IPv6 packets whose L4 protocol byte equals proto.
func BPFFilterIPProtocol(proto uint8) []BPFInstruction {
	p := uint32(proto)
	return []BPFInstruction{
		{Code: bpfClassLD | bpfSizeH | bpfModeABS, K: 12},                                // 0: ldh [12] (EtherType)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 2, K: uint32(EtherTypeIPv4)}, // 1: jeq #0x0800, ipv4(2), check_ipv6(4)
		{Code: bpfClassLD | bpfSizeB | bpfModeABS, K: 23},                                // 2: ldb [23] (IPv4 protocol)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 3, JF: 4, K: p},                     // 3: jeq #proto, accept(7), reject(8)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 3, K: uint32(EtherTypeIPv6)}, // 4: jeq #0x86dd, ipv6(5), reject(8)
		{Code: bpfClassLD | bpfSizeB | bpfModeABS, K: 20},                                // 5: ldb [20] (IPv6 NextHeader)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 1, K: p},                     // 6: jeq #proto, accept(7), reject(8)
		{Code: bpfClassRET | bpfSrcK, K: DefaultLiveSnapLen},                             // 7: accept
		{Code: bpfClassRET | bpfSrcK, K: 0},                                              // 8: reject
	}
}

// BPFFilterTCPPort returns a classic BPF program for unfragmented IPv4 Ethernet
// frames that accepts TCP packets whose source or destination port equals port.
func BPFFilterTCPPort(port uint16) []BPFInstruction {
	return bpfFilterIPv4L4Port(IPProtoTCP, port)
}

// BPFFilterUDPPort returns a classic BPF program for unfragmented IPv4 Ethernet
// frames that accepts UDP packets whose source or destination port equals port.
func BPFFilterUDPPort(port uint16) []BPFInstruction {
	return bpfFilterIPv4L4Port(IPProtoUDP, port)
}

func bpfFilterIPv4L4Port(proto uint8, port uint16) []BPFInstruction {
	p := uint32(port)
	return []BPFInstruction{
		{Code: bpfClassLD | bpfSizeH | bpfModeABS, K: 12},                                 // 0: ldh [12] (EtherType)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 10, K: uint32(EtherTypeIPv4)}, // 1: jeq #0x0800, +0, reject(12)
		{Code: bpfClassLD | bpfSizeB | bpfModeABS, K: 23},                                 // 2: ldb [23] (IPv4 proto)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 8, K: uint32(proto)},          // 3: jeq #proto, +0, reject(12)
		{Code: bpfClassLD | bpfSizeH | bpfModeABS, K: 20},                                 // 4: ldh [20] (IPv4 frag offset)
		{Code: bpfClassJMP | bpfOpJSET | bpfSrcK, JT: 6, JF: 0, K: 0x1fff},                // 5: jset #0x1fff, reject(12), +0
		{Code: bpfClassLDX | bpfSizeB | bpfModeMSH, K: 14},                                // 6: ldxb 4*([14]&0xf)
		{Code: bpfClassLD | bpfSizeH | bpfModeIND, K: 14},                                 // 7: ldh [x + 14] (src port)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 2, JF: 0, K: p},                      // 8: jeq #port, accept(11), +0
		{Code: bpfClassLD | bpfSizeH | bpfModeIND, K: 16},                                 // 9: ldh [x + 16] (dst port)
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 1, K: p},                      // 10: jeq #port, accept(11), reject(12)
		{Code: bpfClassRET | bpfSrcK, K: DefaultLiveSnapLen},                              // 11: accept
		{Code: bpfClassRET | bpfSrcK, K: 0},                                               // 12: reject
	}
}

// BPFFilterIPv4Host returns a classic BPF program for Ethernet frames that
// accepts IPv4 packets whose source or destination address equals addr.
func BPFFilterIPv4Host(addr netip.Addr) []BPFInstruction {
	if !addr.Is4() {
		return []BPFInstruction{{Code: bpfClassRET | bpfSrcK, K: 0}}
	}
	a4 := addr.As4()
	hostU32 := binary.BigEndian.Uint32(a4[:])
	return []BPFInstruction{
		{Code: bpfClassLD | bpfSizeH | bpfModeABS, K: 12},
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 5, K: uint32(EtherTypeIPv4)},
		{Code: bpfClassLD | bpfSizeW | bpfModeABS, K: 26}, // IPv4 src
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 2, JF: 0, K: hostU32},
		{Code: bpfClassLD | bpfSizeW | bpfModeABS, K: 30}, // IPv4 dst
		{Code: bpfClassJMP | bpfOpJEQ | bpfSrcK, JT: 0, JF: 1, K: hostU32},
		{Code: bpfClassRET | bpfSrcK, K: DefaultLiveSnapLen},
		{Code: bpfClassRET | bpfSrcK, K: 0},
	}
}

// EvalBPF executes a classic Berkeley Packet Filter program against frame in
// memory and returns (snapLen, true) when the filter accepts the packet
// (return value > 0) or (0, false) when rejected or invalid.
func EvalBPF(insns []BPFInstruction, frame []byte) (uint32, bool) {
	if len(insns) == 0 {
		return DefaultLiveSnapLen, true
	}
	if len(insns) > MaxBPFFilterInstructions {
		return 0, false
	}

	var a, x uint32
	var mem [16]uint32
	pc := 0

	for pc >= 0 && pc < len(insns) {
		in := insns[pc]
		pc++
		class := in.Code & 0x07

		switch class {
		case bpfClassLD:
			mode := in.Code & 0xe0
			size := in.Code & 0x18
			switch mode {
			case bpfModeIMM:
				a = in.K
			case bpfModeLEN:
				a = uint32(len(frame))
			case bpfModeMEM:
				if in.K >= 16 {
					return 0, false
				}
				a = mem[in.K]
			case bpfModeABS, bpfModeIND:
				off := uint64(in.K)
				if mode == bpfModeIND {
					off += uint64(x)
				}
				val, ok := bpfLoadFrame(frame, off, size)
				if !ok {
					return 0, false
				}
				a = val
			default:
				return 0, false
			}

		case bpfClassLDX:
			mode := in.Code & 0xe0
			switch mode {
			case bpfModeIMM:
				x = in.K
			case bpfModeLEN:
				x = uint32(len(frame))
			case bpfModeMEM:
				if in.K >= 16 {
					return 0, false
				}
				x = mem[in.K]
			case bpfModeMSH:
				if uint64(in.K) >= uint64(len(frame)) {
					return 0, false
				}
				x = uint32(frame[in.K]&0x0f) * 4
			default:
				return 0, false
			}

		case bpfClassST:
			if in.K >= 16 {
				return 0, false
			}
			mem[in.K] = a

		case bpfClassSTX:
			if in.K >= 16 {
				return 0, false
			}
			mem[in.K] = x

		case bpfClassALU:
			src := in.K
			if (in.Code & 0x08) == bpfSrcX {
				src = x
			}
			switch in.Code & 0xf0 {
			case 0x00:
				a += src
			case 0x10:
				a -= src
			case 0x20:
				a *= src
			case 0x30:
				if src == 0 {
					return 0, false
				}
				a /= src
			case 0x40:
				a |= src
			case 0x50:
				a &= src
			case 0x60:
				a <<= (src & 31)
			case 0x70:
				a >>= (src & 31)
			case 0x80:
				a = -a
			case 0x90:
				if src == 0 {
					return 0, false
				}
				a %= src
			case 0xa0:
				a ^= src
			default:
				return 0, false
			}

		case bpfClassJMP:
			op := in.Code & 0xf0
			if op == bpfOpJA {
				if in.K > uint32(len(insns)-pc) {
					return 0, false
				}
				pc += int(in.K)
				continue
			}
			src := in.K
			if (in.Code & 0x08) == bpfSrcX {
				src = x
			}
			var cond bool
			switch op {
			case bpfOpJEQ:
				cond = a == src
			case bpfOpJGT:
				cond = a > src
			case bpfOpJGE:
				cond = a >= src
			case bpfOpJSET:
				cond = (a & src) != 0
			default:
				return 0, false
			}
			if cond {
				pc += int(in.JT)
			} else {
				pc += int(in.JF)
			}

		case bpfClassRET:
			retVal := in.K
			if (in.Code & 0x18) == bpfRetA {
				retVal = a
			}
			return retVal, retVal > 0

		case bpfClassMISC:
			if (in.Code & 0xf8) == 0x00 {
				x = a // TAX
			} else {
				a = x // TXA
			}
		}
	}

	return 0, false
}

func bpfLoadFrame(frame []byte, off uint64, size uint16) (uint32, bool) {
	switch size {
	case bpfSizeB:
		if off >= uint64(len(frame)) {
			return 0, false
		}
		return uint32(frame[off]), true
	case bpfSizeH:
		if off+2 > uint64(len(frame)) {
			return 0, false
		}
		return uint32(binary.BigEndian.Uint16(frame[off : off+2])), true
	case bpfSizeW:
		if off+4 > uint64(len(frame)) {
			return 0, false
		}
		return binary.BigEndian.Uint32(frame[off : off+4]), true
	default:
		return 0, false
	}
}
