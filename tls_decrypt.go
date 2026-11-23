package pcap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
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

		var entry TLSKeyLogEntry
		var exists bool
		entry, exists = kl.Entries[clientRandom]
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
		if !exists {
			if count >= MaxTLSKeyLogEntries {
				return nil, fmt.Errorf("%w: keylog entries exceed %d", ErrSecretLimit, MaxTLSKeyLogEntries)
			}
			count++
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

func tls13SuiteParams(suite uint16) (func() hash.Hash, int) {
	switch suite {
	case TLS_AES_128_GCM_SHA256:
		return sha256.New, 16
	case TLS_AES_256_GCM_SHA384:
		return sha512.New384, 32
	default:
		return nil, 0
	}
}

func deriveTLS13TrafficAEAD(secret []byte, cipherSuite uint16) (cipher.AEAD, [12]byte, error) {
	hashFn, keyLen := tls13SuiteParams(cipherSuite)
	if hashFn == nil {
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

// tls13PostHandshake tracks message boundaries without retaining message bodies.
type tls13PostHandshake struct {
	header       [4]byte
	n, remaining int
}

func (h *tls13PostHandshake) endsWithKeyUpdate(record []byte) bool {
	for len(record) > 0 {
		if h.n < len(h.header) {
			n := copy(h.header[h.n:], record)
			h.n += n
			record = record[n:]
			if h.n < len(h.header) {
				return false
			}
			h.remaining = int(h.header[1])<<16 | int(h.header[2])<<8 | int(h.header[3])
		}
		if h.remaining > len(record) {
			h.remaining -= len(record)
			return false
		}
		// The one-byte request must end the old traffic generation's record.
		update := h.header == [4]byte{TLSHandshakeKeyUpdate, 0, 0, 1} && len(record) == 1 && record[0] <= 1
		record = record[h.remaining:]
		h.n = 0
		if update {
			return true
		}
	}
	return false
}

// DecryptTLS13Records decrypts a directional TLS 1.3 byte stream using the
// caller's handshake traffic secret (optional) and application traffic secret 0
// (optional). It returns the decrypted handshake payload bytes and application
// data payload bytes. Authenticated KeyUpdate messages advance only this direction.
// At the next update after [MaxTLSKeyUpdatesPerStream], it returns the recovered prefix.
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

	var postHandshake tls13PostHandshake
	var updates int
	var hsSeq, appSeq uint64
	inAppPhase := hsAEAD == nil
	var hsBuf, appBuf bytes.Buffer
	var hsFull, appFull bool
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

		// Try current phase AEAD first; only transition permanently to appAEAD
		// once appAEAD.Open actually succeeds (avoiding premature phase flip on 0-RTT).
		var plain []byte
		var decErr error
		if !inAppPhase && hsAEAD != nil {
			nonce := xorTLS13Nonce(hsIV, hsSeq)
			plain, decErr = hsAEAD.Open(nil, nonce[:], ciphertext, header)
			if decErr == nil {
				hsSeq++
			} else if appAEAD != nil {
				appNonce := xorTLS13Nonce(appIV, appSeq)
				if appPlain, appErr := appAEAD.Open(nil, appNonce[:], ciphertext, header); appErr == nil {
					inAppPhase = true
					plain, decErr = appPlain, nil
					appSeq++
				}
			}
		} else if appAEAD != nil {
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

		if innerType != TLSRecordHandshake {
			postHandshake = tls13PostHandshake{}
		}
		switch innerType {
		case TLSRecordHandshake:
			if !hsFull {
				rem := MaxTLSHandshakeBytes - hsBuf.Len()
				if len(innerContent) <= rem {
					hsBuf.Write(innerContent)
				} else {
					hsBuf.Write(innerContent[:rem])
					hsFull = true
				}
			}
			if inAppPhase && postHandshake.endsWithKeyUpdate(innerContent) {
				if updates == MaxTLSKeyUpdatesPerStream {
					return hsBuf.Bytes(), appBuf.Bytes(), nil
				}
				hashFn, _ := tls13SuiteParams(cipherSuite)
				appSecret, err = tls13ExpandLabelHash(hashFn, appSecret, "traffic upd", nil, hashFn().Size())
				if err != nil {
					return nil, nil, err
				}
				appAEAD, appIV, err = deriveTLS13TrafficAEAD(appSecret, cipherSuite)
				if err != nil {
					return nil, nil, err
				}
				appSeq = 0
				updates++
			}
		case TLSRecordApplicationData:
			if !appFull {
				rem := MaxFlowStreamBytes - appBuf.Len()
				if len(innerContent) <= rem {
					appBuf.Write(innerContent)
				} else {
					appBuf.Write(innerContent[:rem])
					appFull = true
				}
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

func tls12CipherSuiteParams(cipherSuite uint16) (keyLen int, hashFn func() hash.Hash, ok bool) {
	switch cipherSuite {
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return 16, sha256.New, true
	case TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return 32, sha512.New384, true
	default:
		return 0, nil, false
	}
}

func tls12PRF(hashFn func() hash.Hash, secret []byte, label string, seed []byte, outLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	out := make([]byte, 0, outLen)
	mac := hmac.New(hashFn, secret)
	mac.Write(labelAndSeed)
	a := mac.Sum(nil)

	for len(out) < outLen {
		mac.Reset()
		mac.Write(a)
		mac.Write(labelAndSeed)
		block := mac.Sum(nil)
		need := min(len(block), outLen-len(out))
		out = append(out, block[:need]...)

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(a[:0])
	}
	return out
}

// DecryptTLS12Records decrypts a directional TLS 1.2 byte stream using the
// 48-byte masterSecret (from a CLIENT_RANDOM keylog line) and the 32-byte
// client and server random values.
func DecryptTLS12Records(
	stream []byte,
	cipherSuite uint16,
	masterSecret []byte,
	clientRandom [32]byte,
	serverRandom [32]byte,
	isClient bool,
) ([]byte, error) {
	keyLen, hashFn, ok := tls12CipherSuiteParams(cipherSuite)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported TLS 1.2 cipher suite %#04x for decryption", ErrInvalidTLS, cipherSuite)
	}
	if len(masterSecret) == 0 {
		return nil, fmt.Errorf("%w: empty TLS 1.2 master secret", ErrInvalidTLS)
	}

	var seed [64]byte
	copy(seed[0:32], serverRandom[:])
	copy(seed[32:64], clientRandom[:])
	// key_block = client_write_key (keyLen) + server_write_key (keyLen) + client_write_IV (4) + server_write_IV (4)
	keyBlock := tls12PRF(hashFn, masterSecret, "key expansion", seed[:], 2*keyLen+8)

	var writeKey []byte
	var salt [4]byte
	if isClient {
		writeKey = keyBlock[:keyLen]
		copy(salt[:], keyBlock[2*keyLen:2*keyLen+4])
	} else {
		writeKey = keyBlock[keyLen : 2*keyLen]
		copy(salt[:], keyBlock[2*keyLen+4:2*keyLen+8])
	}

	block, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var seqNum uint64
	var appBuf bytes.Buffer
	offset := 0
	for offset+5 <= len(stream) {
		contentType := stream[offset]
		recVer := binary.BigEndian.Uint16(stream[offset+1 : offset+3])
		recLen := int(binary.BigEndian.Uint16(stream[offset+3 : offset+5]))
		if recVer < TLSVersionSSL30 || recVer > TLSVersion13 || recLen > MaxTLSRecordBytes || offset+5+recLen > len(stream) {
			break
		}
		recordBody := stream[offset+5 : offset+5+recLen]
		offset += 5 + recLen

		if contentType == TLSRecordChangeCipherSpec {
			seqNum = 0
			continue
		}
		if contentType != TLSRecordApplicationData && contentType != TLSRecordHandshake && contentType != TLSRecordAlert {
			continue
		}
		// TLS 1.2 AES-GCM record payload: 8-byte explicit nonce + ciphertext + 16-byte tag.
		if len(recordBody) < 8+aead.Overhead() {
			continue
		}
		var nonce [12]byte
		copy(nonce[0:4], salt[:])
		copy(nonce[4:12], recordBody[:8])
		ciphertext := recordBody[8:]
		plainLen := len(ciphertext) - aead.Overhead()

		var aad [13]byte
		binary.BigEndian.PutUint64(aad[0:8], seqNum)
		aad[8] = contentType
		binary.BigEndian.PutUint16(aad[9:11], recVer)
		binary.BigEndian.PutUint16(aad[11:13], uint16(plainLen))

		plain, decErr := aead.Open(nil, nonce[:], ciphertext, aad[:])
		if decErr != nil {
			continue
		}
		seqNum++
		if contentType == TLSRecordApplicationData {
			rem := MaxFlowStreamBytes - appBuf.Len()
			if len(plain) <= rem {
				appBuf.Write(plain)
			} else {
				appBuf.Write(plain[:rem])
				break
			}
		}
	}

	return appBuf.Bytes(), nil
}

// DecryptedTLSStreams reassembles TCP streams and decrypts any TLS 1.2 or TLS
// 1.3 flows matching secrets in the capture's PcapNG Decryption Secrets Blocks
// (DSB) or extraKeyLog. Only flows with matching decryption secrets and
// non-empty decrypted application payloads are returned.
func (c *Capture) DecryptedTLSStreams(data []byte, extraKeyLog []byte) ([]TCPStream, error) {
	keyLog, err := c.TLSKeyLog(extraKeyLog)
	if err != nil || len(keyLog.Entries) == 0 {
		return nil, err
	}
	streams, err := c.proxyStreams(data)
	if err != nil || len(streams) == 0 {
		return nil, err
	}

	return decryptTLSStreams(streams, keyLog), nil
}

func decryptTLSStreams(streams []TCPStream, keyLog *TLSKeyLog) []TCPStream {
	var decrypted []TCPStream
	for i := range streams {
		st := &streams[i]
		clientBuf, serverBuf := st.Client, st.Server
		cData, sData := clientBuf.Data, serverBuf.Data
		srcAddr, dstAddr, srcPort, dstPort := st.SrcAddr, st.DstAddr, st.SrcPort, st.DstPort
		if !hasTLSHandshakeStart(cData) || !hasTLSHandshakeStart(sData) {
			continue
		}
		hsClient, err1 := ParseTLSRecords(cData)
		hsServer, err2 := ParseTLSRecords(sData)
		if err1 != nil || err2 != nil {
			continue
		}
		if !hsClient.HasClientHello && hsServer.HasClientHello && hsClient.HasServerHello {
			hsClient, hsServer = hsServer, hsClient
			cData, sData = sData, cData
			clientBuf, serverBuf = serverBuf, clientBuf
			srcAddr, dstAddr = dstAddr, srcAddr
			srcPort, dstPort = dstPort, srcPort
		}
		if !hsClient.HasClientHello || !hsServer.HasServerHello {
			continue
		}
		entry, ok := keyLog.Entries[hsClient.ClientHello.Random]
		if !ok {
			continue
		}
		suite := hsServer.ServerHello.CipherSuite
		var clientApp, serverApp []byte
		var errC, errS error

		if hsServer.ServerHello.NegotiatedVersion == TLSVersion13 || len(entry.ClientTrafficSecret0) > 0 || len(entry.ServerTrafficSecret0) > 0 {
			_, clientApp, errC = DecryptTLS13Records(cData, suite, entry.ClientHandshakeSecret, entry.ClientTrafficSecret0)
			_, serverApp, errS = DecryptTLS13Records(sData, suite, entry.ServerHandshakeSecret, entry.ServerTrafficSecret0)
		} else if len(entry.MasterSecret) > 0 {
			clientApp, errC = DecryptTLS12Records(cData, suite, entry.MasterSecret, hsClient.ClientHello.Random, hsServer.ServerHello.Random, true)
			serverApp, errS = DecryptTLS12Records(sData, suite, entry.MasterSecret, hsClient.ClientHello.Random, hsServer.ServerHello.Random, false)
		}
		if (errC != nil && errS != nil) || (len(clientApp) == 0 && len(serverApp) == 0) {
			continue
		}
		clientBuf.Data, serverBuf.Data = clientApp, serverApp
		decrypted = append(decrypted, TCPStream{
			FlowIndex: st.FlowIndex,
			SrcAddr:   srcAddr,
			DstAddr:   dstAddr,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Client:    clientBuf,
			Server:    serverBuf,
		})
	}
	return decrypted
}
