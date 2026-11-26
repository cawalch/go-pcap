package pcap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
)

const tlsExtEncryptThenMAC = 0x0016

type tls12CBCMode uint8

const (
	tls12CBCDetectMode tls12CBCMode = iota
	tls12CBCMACThenEncrypt
	tls12CBCEncryptThenMAC
)

type tls12CBCSuite struct {
	keyLen int
	prf    func() hash.Hash
	mac    func() hash.Hash
}

func tls12CBCSuiteParams(suite uint16) tls12CBCSuite {
	switch suite {
	case TLS_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return tls12CBCSuite{16, sha256.New, sha1.New}
	case TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return tls12CBCSuite{32, sha256.New, sha1.New}
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return tls12CBCSuite{16, sha256.New, sha256.New}
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return tls12CBCSuite{32, sha256.New, sha256.New}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return tls12CBCSuite{32, sha512.New384, sha512.New384}
	}
	return tls12CBCSuite{}
}

type tls12CBCProtection struct {
	block cipher.Block
	mac   hash.Hash
	mode  tls12CBCMode
}

func (suite tls12CBCSuite) trafficProtection(master []byte, clientRandom, serverRandom [32]byte, isClient bool, mode tls12CBCMode) (tls12CBCProtection, error) {
	if len(master) == 0 {
		return tls12CBCProtection{}, fmt.Errorf("%w: empty TLS 1.2 master secret", ErrInvalidTLS)
	}
	var seed [64]byte
	copy(seed[:32], serverRandom[:])
	copy(seed[32:], clientRandom[:])
	macLen := suite.mac().Size()
	// TLS 1.2 CBC carries an explicit IV in each record. The key block
	// contains the two MAC keys followed by the two encryption keys.
	keys := tls12PRF(suite.prf, master, "key expansion", seed[:], 2*(macLen+suite.keyLen))
	macOffset, keyOffset := 0, 2*macLen
	if !isClient {
		macOffset += macLen
		keyOffset += suite.keyLen
	}
	block, err := aes.NewCipher(keys[keyOffset : keyOffset+suite.keyLen])
	if err != nil {
		return tls12CBCProtection{}, err
	}
	return tls12CBCProtection{block: block, mac: hmac.New(suite.mac, keys[macOffset:macOffset+macLen]), mode: mode}, nil
}

func (p *tls12CBCProtection) open(seq uint64, typ byte, version uint16, body []byte) ([]byte, bool) {
	if version != TLSVersion12 {
		return nil, false
	}
	if p.mode != tls12CBCMACThenEncrypt {
		if plain, ok := p.openEncryptThenMAC(seq, typ, version, body); ok {
			p.mode = tls12CBCEncryptThenMAC
			return plain, true
		}
		if p.mode == tls12CBCEncryptThenMAC {
			return nil, false
		}
	}
	plain, ok := p.openMACThenEncrypt(seq, typ, version, body)
	if ok {
		p.mode = tls12CBCMACThenEncrypt
	}
	return plain, ok
}

func (p *tls12CBCProtection) openEncryptThenMAC(seq uint64, typ byte, version uint16, body []byte) ([]byte, bool) {
	encLen := len(body) - p.mac.Size()
	if !tls12CBCRecordLength(encLen) || !hmac.Equal(p.recordMAC(seq, typ, version, body[:encLen]), body[encLen:]) {
		return nil, false
	}
	plain := p.decrypt(body[:encLen])
	n, good := tls12CBCUnpad(plain)
	if good != 1 {
		return nil, false
	}
	return plain[:n], true
}

func (p *tls12CBCProtection) openMACThenEncrypt(seq uint64, typ byte, version uint16, body []byte) ([]byte, bool) {
	macLen := p.mac.Size()
	if !tls12CBCRecordLength(len(body)) || len(body)-aes.BlockSize <= macLen {
		return nil, false
	}
	plain := p.decrypt(body)
	n, paddingOK := tls12CBCUnpad(plain)
	hasMAC := subtle.ConstantTimeLessOrEq(macLen, n)
	contentLen := subtle.ConstantTimeSelect(hasMAC, n-macLen, 0)
	expected := p.recordMAC(seq, typ, version, plain[:contentLen])
	macOK := subtle.ConstantTimeCompare(expected, plain[contentLen:contentLen+macLen])
	if paddingOK&hasMAC&macOK != 1 {
		return nil, false
	}
	return plain[:contentLen], true
}

func tls12CBCRecordLength(n int) bool {
	return n >= 2*aes.BlockSize && n%aes.BlockSize == 0
}

func (p *tls12CBCProtection) decrypt(body []byte) []byte {
	plain := make([]byte, len(body)-aes.BlockSize)
	cipher.NewCBCDecrypter(p.block, body[:aes.BlockSize]).CryptBlocks(plain, body[aes.BlockSize:])
	return plain
}

func (p *tls12CBCProtection) recordMAC(seq uint64, typ byte, version uint16, data []byte) []byte {
	var header [13]byte
	binary.BigEndian.PutUint64(header[:8], seq)
	header[8] = typ
	binary.BigEndian.PutUint16(header[9:11], version)
	binary.BigEndian.PutUint16(header[11:13], uint16(len(data)))
	p.mac.Reset()
	p.mac.Write(header[:])
	p.mac.Write(data)
	return p.mac.Sum(nil)
}

// tls12CBCUnpad checks every potential padding byte in the received record.
// Returning the full length on failure leaves a bounded span for the MAC check.
func tls12CBCUnpad(data []byte) (int, int) {
	padding := data[len(data)-1]
	length := int(padding) + 1
	good := subtle.ConstantTimeLessOrEq(length, len(data))
	for i := range min(len(data), 256) {
		check := subtle.ConstantTimeLessOrEq(i+1, length)
		equal := subtle.ConstantTimeByteEq(data[len(data)-1-i], padding)
		good &= 1 ^ (check & (1 ^ equal))
	}
	return len(data) - subtle.ConstantTimeSelect(good, length, 0), good
}
