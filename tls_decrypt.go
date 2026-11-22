package pcap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// TLSKeyLogEntry holds traffic secrets indexed by a 32-byte TLS ClientHello.Random.
type TLSKeyLogEntry struct {
	ClientHandshakeSecret []byte
	ServerHandshakeSecret []byte
	ClientTrafficSecret0  []byte
	ServerTrafficSecret0  []byte
	MasterSecret          []byte
}

// TLSKeyLog indexes parsed NSS SSLKEYLOGFILE secrets by the 32-byte client random.
type TLSKeyLog struct {
	Entries map[[32]byte]TLSKeyLogEntry
}

// ParseTLSKeyLog parses NSS key log lines (such as those stored in a PcapNG
// Decryption Secrets Block with type [SecretsTypeTLSKeyLog] or an external
// SSLKEYLOGFILE).
func ParseTLSKeyLog(data []byte) (*TLSKeyLog, error) {
	kl := &TLSKeyLog{
		Entries: make(map[[32]byte]TLSKeyLogEntry),
	}
	lines := bytes.SplitSeq(data, []byte{'\n'})
	count := 0
	for rawLine := range lines {
		line := strings.TrimSpace(string(rawLine))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var fields [4]string
		n := 0
		for part := range strings.FieldsSeq(line) {
			if n < len(fields) {
				fields[n] = part
			}
			n++
		}
		if n != 3 {
			continue
		}
		label, randHex, secretHex := fields[0], fields[1], fields[2]
		if len(randHex) != 64 {
			continue
		}
		var clientRandom [32]byte
		if _, err := hex.Decode(clientRandom[:], []byte(randHex)); err != nil {
			continue
		}
		secret, err := hex.DecodeString(secretHex)
		if err != nil || len(secret) == 0 || len(secret) > 64 {
			continue
		}

		entry, exists := kl.Entries[clientRandom]
		if !exists {
			if count >= MaxTLSKeyLogEntries {
				return nil, fmt.Errorf("%w: keylog entries exceed %d", ErrSecretLimit, MaxTLSKeyLogEntries)
			}
			count++
		}
		switch label {
		case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
			entry.ClientHandshakeSecret = secret
		case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
			entry.ServerHandshakeSecret = secret
		case "CLIENT_TRAFFIC_SECRET_0":
			entry.ClientTrafficSecret0 = secret
		case "SERVER_TRAFFIC_SECRET_0":
			entry.ServerTrafficSecret0 = secret
		case "CLIENT_RANDOM":
			entry.MasterSecret = secret
		default:
			continue
		}
		kl.Entries[clientRandom] = entry
	}
	return kl, nil
}

// TLSKeyLog combines all embedded PcapNG [SecretsTypeTLSKeyLog] blocks in c with
// optional extraKeyLog bytes into a single [TLSKeyLog].
func (c *Capture) TLSKeyLog(extraKeyLog []byte) (*TLSKeyLog, error) {
	if err := c.validateContainer(); err != nil {
		return nil, err
	}
	var combined bytes.Buffer
	for i := range c.Secrets {
		if c.Secrets[i].SecretsType == SecretsTypeTLSKeyLog {
			combined.Write(c.Secrets[i].Data)
			combined.WriteByte('\n')
		}
	}
	if len(extraKeyLog) > 0 {
		combined.Write(extraKeyLog)
	}
	if combined.Len() == 0 {
		return &TLSKeyLog{Entries: nil}, nil
	}
	return ParseTLSKeyLog(combined.Bytes())
}

func deriveTLS13TrafficAEAD(secret []byte, cipherSuite uint16) (cipher.AEAD, [12]byte, error) {
	var hashFn func() hash.Hash
	var keyLen int
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		hashFn = sha256.New
		keyLen = 16
	case TLS_AES_256_GCM_SHA384:
		hashFn = sha512.New384
		keyLen = 32
	default:
		return nil, [12]byte{}, fmt.Errorf("%w: unsupported TLS 1.3 cipher suite %#04x for decryption", ErrInvalidTLS, cipherSuite)
	}

	key, err := tls13ExpandLabelHash(hashFn, secret, "key", nil, keyLen)
	if err != nil {
		return nil, [12]byte{}, err
	}
	ivSlice, err := tls13ExpandLabelHash(hashFn, secret, "iv", nil, 12)
	if err != nil {
		return nil, [12]byte{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, [12]byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, [12]byte{}, err
	}
	var iv [12]byte
	copy(iv[:], ivSlice)
	return aead, iv, nil
}

func tls13ExpandLabelHash(hashFn func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	var info [64]byte
	b := info[:0]
	b = append(b, byte(length>>8), byte(length))
	b = append(b, byte(len(fullLabel)))
	b = append(b, fullLabel...)
	b = append(b, byte(len(context)))
	b = append(b, context...)
	return hkdf.Expand(hashFn, secret, string(b), length)
}

// DecryptTLS13Records decrypts a directional TLS 1.3 byte stream using the
// caller's handshake traffic secret (optional) and application traffic secret 0
// (optional). It returns the decrypted handshake payload bytes and application
// data payload bytes.
func DecryptTLS13Records(
	stream []byte,
	cipherSuite uint16,
	handshakeSecret []byte,
	appSecret []byte,
) (handshakePlain []byte, appPlain []byte, err error) {
	var hsAEAD, appAEAD cipher.AEAD
	var hsIV, appIV [12]byte

	if len(handshakeSecret) > 0 {
		hsAEAD, hsIV, err = deriveTLS13TrafficAEAD(handshakeSecret, cipherSuite)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(appSecret) > 0 {
		appAEAD, appIV, err = deriveTLS13TrafficAEAD(appSecret, cipherSuite)
		if err != nil {
			return nil, nil, err
		}
	}

	var hsSeq, appSeq uint64
	inAppPhase := hsAEAD == nil
	var hsBuf, appBuf bytes.Buffer
	offset := 0

	for offset+5 <= len(stream) {
		contentType := stream[offset]
		recVer := binary.BigEndian.Uint16(stream[offset+1 : offset+3])
		recLen := int(binary.BigEndian.Uint16(stream[offset+3 : offset+5]))
		if recVer < TLSVersionSSL30 || recVer > TLSVersion13 || recLen > MaxTLSRecordBytes || offset+5+recLen > len(stream) {
			break
		}
		header := stream[offset : offset+5]
		ciphertext := stream[offset+5 : offset+5+recLen]
		offset += 5 + recLen

		if contentType != TLSRecordApplicationData {
			continue
		}

		// Try current phase AEAD first; if handshake phase finishes (e.g. after Server Finished),
		// transition seamlessly to appAEAD with sequence number 0.
		var plain []byte
		var decErr error
		if !inAppPhase && hsAEAD != nil {
			nonce := xorTLS13Nonce(hsIV, hsSeq)
			plain, decErr = hsAEAD.Open(nil, nonce[:], ciphertext, header)
			if decErr == nil {
				hsSeq++
			} else if appAEAD != nil {
				inAppPhase = true
			}
		}
		if inAppPhase && appAEAD != nil {
			nonce := xorTLS13Nonce(appIV, appSeq)
			plain, decErr = appAEAD.Open(nil, nonce[:], ciphertext, header)
			if decErr == nil {
				appSeq++
			}
		}
		if decErr != nil || len(plain) == 0 {
			continue
		}

		// Strip TLS 1.3 inner zero padding from the end to find the 1-byte inner ContentType.
		idx := len(plain) - 1
		for idx >= 0 && plain[idx] == 0 {
			idx--
		}
		if idx < 0 {
			continue
		}
		innerType := plain[idx]
		innerContent := plain[:idx]

		switch innerType {
		case TLSRecordHandshake:
			if hsBuf.Len()+len(innerContent) <= MaxTLSHandshakeBytes {
				hsBuf.Write(innerContent)
			}
		case TLSRecordApplicationData:
			if appBuf.Len()+len(innerContent) <= MaxFlowStreamBytes {
				appBuf.Write(innerContent)
			}
		}
	}

	return hsBuf.Bytes(), appBuf.Bytes(), nil
}

func xorTLS13Nonce(iv [12]byte, seq uint64) [12]byte {
	out := iv
	for i := range 8 {
		out[11-i] ^= byte(seq >> (8 * i))
	}
	return out
}

// DecryptedTLSStreams reassembles TCP streams and decrypts any TLS 1.3 flows
// matching secrets in the capture's PcapNG Decryption Secrets Blocks (DSB) or
// extraKeyLog. Only flows with matching decryption secrets and non-empty
// decrypted application payloads are returned.
func (c *Capture) DecryptedTLSStreams(data []byte, extraKeyLog []byte) ([]TCPStream, error) {
	keyLog, err := c.TLSKeyLog(extraKeyLog)
	if err != nil || len(keyLog.Entries) == 0 {
		return nil, err
	}
	streams, err := c.Streams(data)
	if err != nil || len(streams) == 0 {
		return nil, err
	}

	var decrypted []TCPStream
	for i := range streams {
		st := &streams[i]
		if findTLSHandshakeStart(st.Client.Data) < 0 || findTLSHandshakeStart(st.Server.Data) < 0 {
			continue
		}
		hsClient, err1 := ParseTLSRecords(st.Client.Data)
		hsServer, err2 := ParseTLSRecords(st.Server.Data)
		if err1 != nil || err2 != nil || !hsClient.HasClientHello || !hsServer.HasServerHello {
			continue
		}
		entry, ok := keyLog.Entries[hsClient.ClientHello.Random]
		if !ok {
			continue
		}
		suite := hsServer.ServerHello.CipherSuite
		_, clientApp, errC := DecryptTLS13Records(st.Client.Data, suite, entry.ClientHandshakeSecret, entry.ClientTrafficSecret0)
		_, serverApp, errS := DecryptTLS13Records(st.Server.Data, suite, entry.ServerHandshakeSecret, entry.ServerTrafficSecret0)
		if (errC != nil && errS != nil) || (len(clientApp) == 0 && len(serverApp) == 0) {
			continue
		}
		decrypted = append(decrypted, TCPStream{
			FlowIndex: st.FlowIndex,
			SrcAddr:   st.SrcAddr,
			DstAddr:   st.DstAddr,
			SrcPort:   st.SrcPort,
			DstPort:   st.DstPort,
			Client:    StreamBuffer{Data: clientApp},
			Server:    StreamBuffer{Data: serverApp},
		})
	}
	return decrypted, nil
}
