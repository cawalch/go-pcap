package pcap

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

const sshMsgKexInit uint8 = 20

// SSHKexInit contains the algorithm name-lists parsed from an SSH_MSG_KEXINIT
// packet (RFC 4253 §7.1).
type SSHKexInit struct {
	Cookie                    [16]byte
	KexAlgorithms             string
	ServerHostKeyAlgorithms   string
	EncryptionClientToServer  string
	EncryptionServerToClient  string
	MACClientToServer         string
	MACServerToClient         string
	CompressionClientToServer string
	CompressionServerToClient string
	LanguagesClientToServer   string
	LanguagesServerToClient   string
	FirstKexPacketFollows     bool
}

// SSHHandshake contains the version banners, KEXINIT algorithms, and HASSH /
// HASSHServer MD5 fingerprints of an SSH connection.
type SSHHandshake struct {
	ClientBanner string
	ServerBanner string
	HasClientKex bool
	HasServerKex bool
	ClientKex    SSHKexInit
	ServerKex    SSHKexInit
	HASSH        string
	HASSHServer  string
}

// SSHRecord associates a parsed [SSHHandshake] and its FoxIO JA4SSH session
// fingerprint with its 5-tuple TCP flow in a [Capture].
type SSHRecord struct {
	FlowIndex int
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Handshake SSHHandshake
	JA4SSH    string
}

// ParseSSHHandshake parses SSH version banners and the first SSH_MSG_KEXINIT
// packet from clientStream and serverStream, computing HASSH and HASSHServer
// fingerprints.
func ParseSSHHandshake(clientStream, serverStream []byte) (SSHHandshake, error) {
	var out SSHHandshake
	var found bool

	if banner, rest, ok := parseSSHBanner(clientStream); ok {
		out.ClientBanner = banner
		found = true
		if kex, err := parseFirstSSHKexInit(rest); err == nil {
			out.ClientKex = kex
			out.HasClientKex = true
			out.HASSH = computeHASSH(
				kex.KexAlgorithms,
				kex.EncryptionClientToServer,
				kex.MACClientToServer,
				kex.CompressionClientToServer,
			)
		}
	}

	if banner, rest, ok := parseSSHBanner(serverStream); ok {
		out.ServerBanner = banner
		found = true
		if kex, err := parseFirstSSHKexInit(rest); err == nil {
			out.ServerKex = kex
			out.HasServerKex = true
			out.HASSHServer = computeHASSH(
				kex.KexAlgorithms,
				kex.EncryptionServerToClient,
				kex.MACServerToClient,
				kex.CompressionServerToClient,
			)
		}
	}

	if !found {
		return SSHHandshake{}, fmt.Errorf("%w: no SSH version banner found", ErrInvalidSSH)
	}
	return out, nil
}

func parseSSHBanner(stream []byte) (string, []byte, bool) {
	if !bytes.HasPrefix(stream, []byte("SSH-")) {
		return "", nil, false
	}
	nl := bytes.IndexByte(stream, '\n')
	if nl < 0 || nl > MaxSSHBannerBytes {
		return "", nil, false
	}
	banner := strings.TrimRight(string(stream[:nl]), "\r")
	return banner, stream[nl+1:], true
}

func parseFirstSSHKexInit(rest []byte) (SSHKexInit, error) {
	if len(rest) < 6 {
		return SSHKexInit{}, fmt.Errorf("%w: truncated SSH binary packet header", ErrInvalidSSH)
	}
	pktLen := int(binary.BigEndian.Uint32(rest[0:4]))
	padLen := int(rest[4])
	if pktLen < 2+padLen || pktLen > MaxSSHKexPacketBytes || 4+pktLen > len(rest) {
		return SSHKexInit{}, fmt.Errorf("%w: invalid SSH packet length %d", ErrInvalidSSH, pktLen)
	}
	payloadLen := pktLen - padLen - 1
	if payloadLen < 17 {
		return SSHKexInit{}, fmt.Errorf("%w: SSH payload too short for KEXINIT", ErrInvalidSSH)
	}
	payload := rest[5 : 5+payloadLen]
	if payload[0] != sshMsgKexInit {
		return SSHKexInit{}, fmt.Errorf("%w: SSH message code %d is not KEXINIT (20)", ErrInvalidSSH, payload[0])
	}

	var kex SSHKexInit
	copy(kex.Cookie[:], payload[1:17])
	offset := 17

	var lists [10]string
	for i := range 10 {
		if offset+4 > len(payload) {
			return SSHKexInit{}, fmt.Errorf("%w: truncated KEXINIT name-list %d", ErrInvalidSSH, i)
		}
		sLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
		offset += 4
		if sLen < 0 || sLen > MaxSSHNameListBytes || offset+sLen > len(payload) {
			return SSHKexInit{}, fmt.Errorf("%w: KEXINIT name-list length %d exceeds bounds", ErrSSHLimit, sLen)
		}
		lists[i] = string(payload[offset : offset+sLen])
		offset += sLen
	}
	if offset < len(payload) {
		kex.FirstKexPacketFollows = payload[offset] != 0
	}

	kex.KexAlgorithms = lists[0]
	kex.ServerHostKeyAlgorithms = lists[1]
	kex.EncryptionClientToServer = lists[2]
	kex.EncryptionServerToClient = lists[3]
	kex.MACClientToServer = lists[4]
	kex.MACServerToClient = lists[5]
	kex.CompressionClientToServer = lists[6]
	kex.CompressionServerToClient = lists[7]
	kex.LanguagesClientToServer = lists[8]
	kex.LanguagesServerToClient = lists[9]
	return kex, nil
}

func computeHASSH(kex, enc, mac, comp string) string {
	h := md5.New()
	for i, field := range [...]string{kex, enc, mac, comp} {
		if i != 0 {
			h.Write([]byte(";"))
		}
		h.Write([]byte(field))
	}
	var sum [md5.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0]))
}

// SSH extracts SSH handshakes, HASSH / HASSHServer fingerprints, and FoxIO
// JA4SSH session fingerprints across all TCP flows in the capture.
func (c *Capture) SSH(data []byte) ([]SSHRecord, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	if len(streams) == 0 {
		return nil, nil
	}

	// Collect per-flow JA4SSH segments in a single packet pass.
	r := SafeReader{data: data, size: int64(len(data))}
	var table flowIndexTable
	segsByFlow := make(map[int][]JA4SSHSegment)
	_ = c.walkPackets(&r, func(pkt PacketRecord) error {
		payload, err := r.Slice(pkt.PayloadOffset, pkt.PayloadLength)
		if err != nil {
			return err
		}
		frame, err := DecodeFrame(payload, pkt.LinkType)
		if err != nil || frame.IPVersion == 0 || frame.IPProtocol != IPProtoTCP {
			return nil
		}
		key, isFirst := makeCanonicalFlowKey(frame.IPProtocol, frame.SrcAddr, frame.SrcPort, frame.DstAddr, frame.DstPort)
		flowIdx, _, err := table.lookupOrInsert(key)
		if err != nil {
			return err
		}
		_ = isFirst
		segsByFlow[flowIdx] = append(segsByFlow[flowIdx], JA4SSHSegment{
			IsClient:      frame.SrcAddr == streamsFlowClientAddr(streams, flowIdx, frame.SrcAddr),
			PayloadLength: int(frame.PayloadLength),
			Flags:         frame.TCPFlags,
		})
		return nil
	})

	var records []SSHRecord
	for i := range streams {
		st := &streams[i]
		if !bytes.HasPrefix(st.Client.Data, []byte("SSH-")) && !bytes.HasPrefix(st.Server.Data, []byte("SSH-")) {
			continue
		}
		hs, err := ParseSSHHandshake(st.Client.Data, st.Server.Data)
		if err != nil {
			continue
		}
		if len(records) >= MaxSSHHandshakesPerScan {
			return nil, fmt.Errorf("%w: exceeds %d SSH handshakes", ErrSSHLimit, MaxSSHHandshakesPerScan)
		}
		records = append(records, SSHRecord{
			FlowIndex: st.FlowIndex,
			SrcAddr:   st.SrcAddr,
			DstAddr:   st.DstAddr,
			SrcPort:   st.SrcPort,
			DstPort:   st.DstPort,
			Handshake: hs,
			JA4SSH:    JA4SSH(segsByFlow[st.FlowIndex]),
		})
	}
	return records, nil
}

func streamsFlowClientAddr(streams []TCPStream, flowIndex int, fallback netip.Addr) netip.Addr {
	for i := range streams {
		if streams[i].FlowIndex == flowIndex {
			return streams[i].SrcAddr
		}
	}
	return fallback
}
