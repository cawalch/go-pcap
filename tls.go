package pcap

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// TLSAnomalies reports structural or security anomalies in a TLS handshake.
type TLSAnomalies struct {
	TruncatedRecord       bool
	SNIIPLiteral          bool
	EmptySNI              bool
	DuplicateExtension    bool
	ALPNTransportMismatch bool
	SelfSignedCertificate bool
	InvalidCertificateDER bool
}

// Any reports whether any TLS anomaly was detected.
func (a TLSAnomalies) Any() bool {
	return a.TruncatedRecord ||
		a.SNIIPLiteral ||
		a.EmptySNI ||
		a.DuplicateExtension ||
		a.ALPNTransportMismatch ||
		a.SelfSignedCertificate ||
		a.InvalidCertificateDER
}

// TLSClientHello contains the parsed fields and JA4 fingerprint of a TLS
// ClientHello handshake message.
type TLSClientHello struct {
	RecordVersion      uint16
	HandshakeVersion   uint16
	NegotiatedVersion  uint16
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []uint16
	SNI                string // Server name from the observed ClientHello.
	ALPNs              []string
	SupportedVersions  []uint16
	SignatureSchemes   []uint16
	SupportedGroups    []uint16 // Advertised non-GREASE groups in wire order.
	KeyShareGroups     []uint16 // Offered non-GREASE groups in wire order, capped at MaxTLSExtensions.
	HasSessionTicket   bool     // The session_ticket extension was offered.
	HasPSK             bool     // The pre_shared_key extension was offered.
	HasECH             bool     // A nonempty encrypted_client_hello extension was observed, including GREASE ECH.
	JA4                string
	Anomalies          TLSAnomalies
}

// TLSServerHello contains the parsed fields and JA4S fingerprint of a TLS
// ServerHello handshake message.
type TLSServerHello struct {
	RecordVersion       uint16
	HandshakeVersion    uint16
	NegotiatedVersion   uint16
	Random              [32]byte
	SessionID           []byte
	CipherSuite         uint16
	CompressionMethod   uint8
	Extensions          []uint16
	ALPN                string
	SelectedGroup       uint16 // Server key-share group, or the requested group in a HelloRetryRequest.
	HasSessionTicket    bool   // The server included the session_ticket extension.
	HasPSK              bool   // The server supplied a two-byte pre_shared_key identity selection.
	IsHelloRetryRequest bool   // The random matches the RFC 8446 retry marker.
	SupportedVersion    uint16
	JA4S                string
	Anomalies           TLSAnomalies
}

// TLSCertificate contains metadata and the JA4X structural fingerprint of a
// parsed X.509 certificate from a TLS Certificate handshake message. DNSNames
// and IPAddresses each retain up to [MaxTLSCertSANsPerKind] entries in wire
// order and are nil when absent. RawDER contains the complete certificate.
type TLSCertificate struct {
	Version     int
	Serial      string
	Subject     string
	Issuer      string
	NotBefore   int64
	NotAfter    int64
	DNSNames    []string
	IPAddresses []netip.Addr
	// SANsTruncated reports that DNS or IP names exceeded the per-kind limit.
	SANsTruncated bool
	SelfSigned    bool
	JA4X          string
	RawDER        []byte
}

// TLSCertificateValidity describes a certificate's validity window at an observation time.
type TLSCertificateValidity uint8

const (
	// TLSValidityUnknown indicates missing time or certificate data, or a reversed window.
	TLSValidityUnknown TLSCertificateValidity = iota
	// TLSValidityNotYetValid indicates a time before NotBefore.
	TLSValidityNotYetValid
	// TLSValidityCurrent indicates a time within the inclusive validity window.
	TLSValidityCurrent
	// TLSValidityExpired indicates a time after NotAfter.
	TLSValidityExpired
)

// ValidityAt compares the supplied capture time with the certificate's X.509 validity window.
// Pass a zero time when the capture timestamp is unavailable.
func (c TLSCertificate) ValidityAt(at time.Time) TLSCertificateValidity {
	if at.IsZero() || c.Version == 0 || c.NotAfter < c.NotBefore {
		return TLSValidityUnknown
	}
	if at.Before(time.Unix(c.NotBefore, 0)) {
		return TLSValidityNotYetValid
	}
	if at.After(time.Unix(c.NotAfter, 0)) {
		return TLSValidityExpired
	}
	return TLSValidityCurrent
}

// TLSHandshake aggregates the ClientHello, ServerHello, and X.509 certificates
// decoded from a TLS record stream.
type TLSHandshake struct {
	HasClientHello bool
	HasServerHello bool
	// HasCertificateRequest reports an observed server request for a client certificate.
	HasCertificateRequest bool
	// IsResumed reports an observed TLS 1.2 session ID echo without a certificate,
	// or a TLS 1.3 ServerHello selecting a PSK (possibly externally provisioned).
	IsResumed   bool
	ClientHello TLSClientHello
	ServerHello TLSServerHello
	// Certificates holds the server chain, or a standalone chain of unknown direction.
	Certificates []TLSCertificate
	// ClientCertificates holds the chain presented by the client, in wire order.
	ClientCertificates []TLSCertificate
	Anomalies          TLSAnomalies
}

// ServerNameMatch compares the observed ClientHello DNS name with the server
// leaf's DNS SANs using [x509.Certificate.VerifyHostname]. The second result
// is false when the name, server leaf, or DNS SAN evidence is insufficient.
// With ECH, the observed name can be the public name from ClientHelloOuter.
// The result applies only to the observed name. ECH acceptance and the inner
// server name are unavailable from this comparison.
func (hs *TLSHandshake) ServerNameMatch() (match, known bool) {
	if !hs.HasClientHello || len(hs.Certificates) == 0 || hs.Anomalies.InvalidCertificateDER {
		// An invalid leaf may have been skipped while parsing the chain.
		return false, false
	}
	name := strings.TrimSuffix(hs.ClientHello.SNI, ".")
	if len(name) == 0 || len(name) > 253 {
		return false, false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false, false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false, false
		}
		for i := range len(label) {
			c := label[i]
			if c != '-' && !isASCIIAlphaNum(c) {
				return false, false
			}
		}
	}
	leaf := &hs.Certificates[0]
	if len(leaf.DNSNames) == 0 {
		return false, false
	}
	cert := x509.Certificate{DNSNames: leaf.DNSNames}
	if cert.VerifyHostname(name) == nil {
		return true, true
	}
	return false, !leaf.SANsTruncated || len(leaf.DNSNames) < MaxTLSCertSANsPerKind
}

// TLSRecord associates a parsed [TLSHandshake] with its 5-tuple flow metadata
// in a [Capture].
type TLSRecord struct {
	FlowIndex int
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Handshake TLSHandshake
}

// IsGREASE reports whether v is a RFC 8701 TLS GREASE value ((v & 0x0f0f) == 0x0a0a
// where high and low bytes are equal).
func IsGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// ParseTLSRecords parses one or more TLS handshake records from stream (such as
// a TCP payload or reassembled directional TCP stream) and extracts ClientHello,
// ServerHello, Certificate chains, JA4, JA4S, and JA4X fingerprints.
// It coalesces fragments across plaintext warning alerts and returns [ErrTLSLimit]
// (wrapped) if the plaintext handshake needs more than [MaxTLSHandshakeRecords].
func ParseTLSRecords(stream []byte) (TLSHandshake, error) {
	if len(stream) < 5 {
		return TLSHandshake{}, fmt.Errorf("%w: buffer shorter than 5-byte TLS record header", ErrInvalidTLS)
	}
	if stream[0] != TLSRecordHandshake {
		return TLSHandshake{}, fmt.Errorf("%w: record content type %d is not Handshake (22)", ErrInvalidTLS, stream[0])
	}

	var hsBuf bytes.Buffer
	var firstRecordVersion uint16
	var out TLSHandshake
	var sawCCS, encryptedHandshakes, sawApplicationData bool
	offset := 0

	for records := 0; len(stream)-offset >= 5; records++ {
		contentType := stream[offset]
		if records == MaxTLSHandshakeRecords {
			if encryptedHandshakes || contentType == TLSRecordApplicationData || (sawApplicationData && contentType != TLSRecordHandshake) {
				break // The plaintext hello is still useful on a long connection.
			}
			return TLSHandshake{}, fmt.Errorf("%w: more than %d TLS records", ErrTLSLimit, MaxTLSHandshakeRecords)
		}
		recVer := binary.BigEndian.Uint16(stream[offset+1 : offset+3])
		if recVer < TLSVersionSSL30 || recVer > TLSVersion13 {
			if offset == 0 {
				return TLSHandshake{}, fmt.Errorf("%w: unsupported TLS record version %#04x", ErrInvalidTLS, recVer)
			}
			break
		}
		recLen := int(binary.BigEndian.Uint16(stream[offset+3 : offset+5]))
		if recLen > MaxTLSRecordBytes {
			if offset == 0 {
				return TLSHandshake{}, fmt.Errorf("%w: TLS record length %d exceeds %d", ErrTLSLimit, recLen, MaxTLSRecordBytes)
			}
			break
		}
		if firstRecordVersion == 0 && contentType == TLSRecordHandshake && recLen != 0 {
			firstRecordVersion = recVer
		}
		bodyStart := offset + 5
		bodyEnd := bodyStart + min(recLen, len(stream)-bodyStart)
		if bodyEnd-bodyStart < recLen {
			out.Anomalies.TruncatedRecord = true
		}
		if contentType == TLSRecordApplicationData {
			sawApplicationData = true
		}
		if !encryptedHandshakes && contentType == TLSRecordAlert {
			// Only a complete, non-closing warning can interrupt a plaintext handshake.
			if bodyEnd-bodyStart != 2 || recLen != 2 || stream[bodyStart] != 1 || stream[bodyStart+1] == 0 {
				break
			}
		}
		if contentType == TLSRecordChangeCipherSpec && !sawCCS {
			// TLS 1.2 subsequent handshake records are ciphertext. TLS 1.3
			// allows a compatibility CCS between a retry and the final hello.
			sawCCS = true
			encryptedHandshakes = bodyEnd-bodyStart != 1 || stream[bodyStart] != 1 || !containsHelloRetry(hsBuf.Bytes())
		}
		if contentType == TLSRecordHandshake && !encryptedHandshakes {
			if hsBuf.Len()+(bodyEnd-bodyStart) > MaxTLSHandshakeBytes {
				return TLSHandshake{}, fmt.Errorf("%w: coalesced TLS handshake exceeds %d bytes", ErrTLSLimit, MaxTLSHandshakeBytes)
			}
			hsBuf.Write(stream[bodyStart:bodyEnd])
		}
		offset = bodyEnd
		if out.Anomalies.TruncatedRecord {
			break
		}
	}

	hsData := hsBuf.Bytes()
	if len(hsData) < 4 {
		return TLSHandshake{}, fmt.Errorf("%w: TLS handshake payload shorter than 4 bytes", ErrInvalidTLS)
	}

	hsOffset := 0
	parsedAny := false
	var checkedRetryFollowup bool
	for hsOffset+4 <= len(hsData) {
		msgType := hsData[hsOffset]
		msgLen := int(hsData[hsOffset+1])<<16 | int(hsData[hsOffset+2])<<8 | int(hsData[hsOffset+3])
		if msgLen > MaxTLSHandshakeBytes {
			return TLSHandshake{}, fmt.Errorf("%w: handshake message length %d exceeds %d", ErrTLSLimit, msgLen, MaxTLSHandshakeBytes)
		}
		msgStart := hsOffset + 4
		msgEnd := msgStart + msgLen
		if msgEnd > len(hsData) {
			out.Anomalies.TruncatedRecord = true
			break
		}
		body := hsData[msgStart:msgEnd]

		switch msgType {
		case TLSHandshakeClientHello:
			if !out.HasClientHello {
				ch, err := parseTLSClientHelloWithRecordVersion(body, firstRecordVersion, false)
				if err != nil {
					if !parsedAny {
						return TLSHandshake{}, err
					}
					break
				}
				out.ClientHello = ch
				out.HasClientHello = true
				out.Anomalies = mergeTLSAnomalies(out.Anomalies, ch.Anomalies)
				parsedAny = true
			}
		case TLSHandshakeServerHello:
			if !out.HasServerHello || (out.ServerHello.IsHelloRetryRequest && !checkedRetryFollowup) {
				checkedRetryFollowup = out.HasServerHello
				sh, err := parseTLSServerHelloWithRecordVersion(body, firstRecordVersion, false)
				if err != nil {
					if !parsedAny {
						return TLSHandshake{}, err
					}
					break
				}
				if !out.HasServerHello {
					out.ServerHello = sh // Preserve the first hello and its JA4S.
					out.HasServerHello = true
				}
				if !sh.IsHelloRetryRequest {
					out.IsResumed = sh.NegotiatedVersion == TLSVersion13 && sh.HasPSK
				}
				out.Anomalies = mergeTLSAnomalies(out.Anomalies, sh.Anomalies)
				parsedAny = true
			}
		case TLSHandshakeCertificateRequest:
			if !out.HasClientHello {
				out.HasCertificateRequest = true
				parsedAny = true
			}
		case TLSHandshakeCertificate:
			if len(out.Certificates) == 0 {
				certs, certAnom, err := parseTLSCertificateBody(body)
				if err == nil {
					out.Anomalies = mergeTLSAnomalies(out.Anomalies, certAnom)
					if len(certs) > 0 {
						out.Certificates = certs
						parsedAny = true
					}
				}
			}
		}

		hsOffset = msgEnd
	}

	if !parsedAny {
		return TLSHandshake{}, fmt.Errorf("%w: no complete TLS handshake message found", ErrInvalidTLS)
	}
	if out.HasClientHello && !out.HasServerHello {
		out.ClientCertificates, out.Certificates = out.Certificates, nil
	}
	out.IsResumed = out.IsResumed || out.hasResumedSessionID()
	return out, nil
}

// containsHelloRetry examines complete handshake messages preceding a CCS.
func containsHelloRetry(data []byte) bool {
	for len(data) >= 4 {
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if n > len(data)-4 {
			return false
		}
		if data[0] == TLSHandshakeServerHello {
			return n >= 34 && bytes.Equal(data[6:38], helloRetryRandom[:])
		}
		data = data[4+n:]
	}
	return false
}

func (hs *TLSHandshake) hasResumedSessionID() bool {
	return hs.HasServerHello && hs.ServerHello.NegotiatedVersion == TLSVersion12 &&
		!hs.ServerHello.IsHelloRetryRequest && hs.HasClientHello && len(hs.Certificates) == 0 &&
		len(hs.ClientHello.SessionID) != 0 && bytes.Equal(hs.ClientHello.SessionID, hs.ServerHello.SessionID)
}

// ParseTLSClientHello parses a raw TLS ClientHello handshake body (excluding the
// 4-byte handshake header and 5-byte TLS record header) and computes its JA4
// fingerprint assuming TCP transport ('t').
func ParseTLSClientHello(body []byte) (TLSClientHello, error) {
	return parseTLSClientHelloWithRecordVersion(body, TLSVersion12, false)
}

func parseTLSClientHelloWithRecordVersion(body []byte, recordVer uint16, isQUIC bool) (TLSClientHello, error) {
	if len(body) < 38 {
		return TLSClientHello{}, fmt.Errorf("%w: ClientHello body shorter than 38 bytes", ErrInvalidTLS)
	}
	hsVer := binary.BigEndian.Uint16(body[0:2])
	ch := TLSClientHello{
		RecordVersion:     recordVer,
		HandshakeVersion:  hsVer,
		NegotiatedVersion: hsVer,
	}
	copy(ch.Random[:], body[2:34])

	offset := 34
	sidLen := int(body[offset])
	offset++
	if sidLen > 32 || offset+sidLen > len(body) {
		return TLSClientHello{}, fmt.Errorf("%w: invalid ClientHello session ID length %d", ErrInvalidTLS, sidLen)
	}
	ch.SessionID = bytes.Clone(body[offset : offset+sidLen])
	offset += sidLen

	if offset+2 > len(body) {
		return TLSClientHello{}, fmt.Errorf("%w: truncated ClientHello cipher suites length", ErrInvalidTLS)
	}
	csBytesLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if csBytesLen == 0 || csBytesLen%2 != 0 || offset+csBytesLen > len(body) {
		return TLSClientHello{}, fmt.Errorf("%w: invalid ClientHello cipher suites byte length %d", ErrInvalidTLS, csBytesLen)
	}
	csCount := csBytesLen / 2
	if csCount > MaxTLSCipherSuites {
		return TLSClientHello{}, fmt.Errorf("%w: cipher suite count %d exceeds %d", ErrTLSLimit, csCount, MaxTLSCipherSuites)
	}
	ch.CipherSuites = make([]uint16, csCount)
	for i := range csCount {
		ch.CipherSuites[i] = binary.BigEndian.Uint16(body[offset+i*2 : offset+i*2+2])
	}
	offset += csBytesLen

	if offset+1 > len(body) {
		return TLSClientHello{}, fmt.Errorf("%w: truncated ClientHello compression methods", ErrInvalidTLS)
	}
	compLen := int(body[offset])
	offset++
	if compLen == 0 || offset+compLen > len(body) {
		return TLSClientHello{}, fmt.Errorf("%w: invalid ClientHello compression methods length %d", ErrInvalidTLS, compLen)
	}
	ch.CompressionMethods = bytes.Clone(body[offset : offset+compLen])
	offset += compLen

	if offset+2 <= len(body) {
		extTotalLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+extTotalLen > len(body) {
			return TLSClientHello{}, fmt.Errorf("%w: ClientHello extensions length %d exceeds body", ErrInvalidTLS, extTotalLen)
		}
		extEnd := offset + extTotalLen
		var seenNonGREASE [MaxTLSExtensions]uint16
		seenCount := 0

		for offset < extEnd {
			if extEnd-offset < 4 {
				return TLSClientHello{}, fmt.Errorf("%w: truncated ClientHello extension header", ErrInvalidTLS)
			}
			if len(ch.Extensions) >= MaxTLSExtensions {
				return TLSClientHello{}, fmt.Errorf("%w: extension count exceeds %d", ErrTLSLimit, MaxTLSExtensions)
			}
			extType := binary.BigEndian.Uint16(body[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
			offset += 4
			if offset+extLen > extEnd {
				return TLSClientHello{}, fmt.Errorf("%w: extension %#04x length %d exceeds extensions block", ErrInvalidTLS, extType, extLen)
			}
			extData := body[offset : offset+extLen]
			offset += extLen

			ch.Extensions = append(ch.Extensions, extType)
			if !IsGREASE(extType) {
				if slices.Contains(seenNonGREASE[:seenCount], extType) {
					ch.Anomalies.DuplicateExtension = true
				} else if seenCount < len(seenNonGREASE) {
					seenNonGREASE[seenCount] = extType
					seenCount++
				}
			}

			switch extType {
			case TLSExtSessionTicket:
				ch.HasSessionTicket = true
			case TLSExtPreSharedKey:
				ch.HasPSK = true
			case TLSExtServerName:
				parseSNIExtension(extData, &ch)
			case TLSExtALPN:
				parseALPNExtension(extData, &ch, isQUIC)
			case TLSExtSupportedVersions:
				parseClientSupportedVersions(extData, &ch)
			case TLSExtSignatureAlgorithms:
				parseSignatureAlgorithms(extData, &ch)
			case TLSExtSupportedGroups:
				parseSupportedGroups(extData, &ch)
			case TLSExtKeyShare:
				ch.KeyShareGroups = appendClientKeyShareGroups(ch.KeyShareGroups, extData)
			case TLSExtECH:
				ch.HasECH = ch.HasECH || len(extData) > 0
			}
		}
	}

	ch.JA4 = computeJA4(&ch, isQUIC)
	return ch, nil
}

func parseSNIExtension(extData []byte, ch *TLSClientHello) {
	if len(extData) < 2 {
		ch.Anomalies.EmptySNI = true
		return
	}
	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	if 2+listLen > len(extData) {
		return
	}
	cur := 2
	end := 2 + listLen
	for cur+3 <= end {
		nameType := extData[cur]
		nameLen := int(binary.BigEndian.Uint16(extData[cur+1 : cur+3]))
		cur += 3
		if cur+nameLen > end {
			return
		}
		if nameType == 0 {
			if nameLen == 0 {
				ch.Anomalies.EmptySNI = true
			} else {
				ch.SNI = string(extData[cur : cur+nameLen])
				if _, err := netip.ParseAddr(ch.SNI); err == nil {
					ch.Anomalies.SNIIPLiteral = true
				}
			}
			return
		}
		cur += nameLen
	}
}

func parseALPNExtension(extData []byte, ch *TLSClientHello, isQUIC bool) {
	if len(extData) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	if 2+listLen > len(extData) {
		return
	}
	cur := 2
	end := 2 + listLen
	for cur < end && len(ch.ALPNs) < MaxTLSALPNProtocols {
		pLen := int(extData[cur])
		cur++
		if pLen == 0 || cur+pLen > end {
			break
		}
		proto := string(extData[cur : cur+pLen])
		ch.ALPNs = append(ch.ALPNs, proto)
		if !isQUIC && (proto == "h3" || strings.HasPrefix(proto, "h3-")) {
			ch.Anomalies.ALPNTransportMismatch = true
		}
		cur += pLen
	}
}

func parseClientSupportedVersions(extData []byte, ch *TLSClientHello) {
	if len(extData) < 1 {
		return
	}
	listLen := int(extData[0])
	if listLen%2 != 0 || 1+listLen > len(extData) {
		return
	}
	count := listLen / 2
	var maxVer uint16
	for i := range count {
		v := binary.BigEndian.Uint16(extData[1+i*2 : 1+i*2+2])
		ch.SupportedVersions = append(ch.SupportedVersions, v)
		if (v == TLSVersionSSL30 || v == TLSVersion10 || v == TLSVersion11 || v == TLSVersion12 || v == TLSVersion13) && v > maxVer {
			maxVer = v
		}
	}
	if maxVer != 0 {
		ch.NegotiatedVersion = maxVer
	}
}

func parseSignatureAlgorithms(extData []byte, ch *TLSClientHello) {
	if len(extData) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	if listLen%2 != 0 || 2+listLen > len(extData) {
		return
	}
	count := min(listLen/2, MaxTLSSignatureSchemes)
	for i := range count {
		sig := binary.BigEndian.Uint16(extData[2+i*2 : 2+i*2+2])
		ch.SignatureSchemes = append(ch.SignatureSchemes, sig)
	}
}

func parseSupportedGroups(extData []byte, ch *TLSClientHello) {
	if len(extData) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	if listLen%2 != 0 || 2+listLen > len(extData) {
		return
	}
	for i := 2; i < 2+listLen && len(ch.SupportedGroups) < MaxTLSExtensions; i += 2 {
		grp := binary.BigEndian.Uint16(extData[i : i+2])
		if !IsGREASE(grp) {
			ch.SupportedGroups = append(ch.SupportedGroups, grp)
		}
	}
}

// Publish group IDs only after validating the complete vector. Its uint16
// length bounds the walk, including GREASE entries and entries past the cap.
func appendClientKeyShareGroups(groups []uint16, data []byte) []uint16 {
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		return groups
	}
	var offered [MaxTLSExtensions]uint16
	n := 0
	for data = data[2:]; len(data) > 0; {
		if len(data) < 4 {
			return groups
		}
		group := binary.BigEndian.Uint16(data)
		size := int(binary.BigEndian.Uint16(data[2:]))
		if size == 0 || size > len(data)-4 {
			return groups
		}
		if n < MaxTLSExtensions-len(groups) && !IsGREASE(group) {
			offered[n] = group
			n++
		}
		data = data[4+size:]
	}
	return append(groups, offered[:n]...)
}

var helloRetryRandom = sha256.Sum256([]byte("HelloRetryRequest"))

// ParseTLSServerHello parses a raw TLS ServerHello handshake body (excluding the
// 4-byte handshake header and 5-byte TLS record header) and computes its JA4S
// fingerprint assuming TCP transport ('t').
func ParseTLSServerHello(body []byte) (TLSServerHello, error) {
	return parseTLSServerHelloWithRecordVersion(body, TLSVersion12, false)
}

func parseTLSServerHelloWithRecordVersion(body []byte, recordVer uint16, isQUIC bool) (TLSServerHello, error) {
	if len(body) < 38 {
		return TLSServerHello{}, fmt.Errorf("%w: ServerHello body shorter than 38 bytes", ErrInvalidTLS)
	}
	hsVer := binary.BigEndian.Uint16(body[0:2])
	sh := TLSServerHello{
		RecordVersion:     recordVer,
		HandshakeVersion:  hsVer,
		NegotiatedVersion: hsVer,
	}
	copy(sh.Random[:], body[2:34])
	sh.IsHelloRetryRequest = sh.Random == helloRetryRandom

	offset := 34
	sidLen := int(body[offset])
	offset++
	if sidLen > 32 || offset+sidLen > len(body) {
		return TLSServerHello{}, fmt.Errorf("%w: invalid ServerHello session ID length %d", ErrInvalidTLS, sidLen)
	}
	sh.SessionID = bytes.Clone(body[offset : offset+sidLen])
	offset += sidLen

	if offset+3 > len(body) {
		return TLSServerHello{}, fmt.Errorf("%w: truncated ServerHello cipher suite or compression", ErrInvalidTLS)
	}
	sh.CipherSuite = binary.BigEndian.Uint16(body[offset : offset+2])
	sh.CompressionMethod = body[offset+2]
	offset += 3

	if offset+2 <= len(body) {
		extTotalLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+extTotalLen > len(body) {
			return TLSServerHello{}, fmt.Errorf("%w: ServerHello extensions length %d exceeds body", ErrInvalidTLS, extTotalLen)
		}
		extEnd := offset + extTotalLen
		for offset < extEnd {
			if extEnd-offset < 4 {
				return TLSServerHello{}, fmt.Errorf("%w: truncated ServerHello extension header", ErrInvalidTLS)
			}
			if len(sh.Extensions) >= MaxTLSExtensions {
				return TLSServerHello{}, fmt.Errorf("%w: extension count exceeds %d", ErrTLSLimit, MaxTLSExtensions)
			}
			extType := binary.BigEndian.Uint16(body[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
			offset += 4
			if offset+extLen > extEnd {
				return TLSServerHello{}, fmt.Errorf("%w: ServerHello extension %#04x exceeds block", ErrInvalidTLS, extType)
			}
			extData := body[offset : offset+extLen]
			offset += extLen

			sh.Extensions = append(sh.Extensions, extType)
			switch extType {
			case TLSExtSessionTicket:
				sh.HasSessionTicket = true
			case TLSExtPreSharedKey:
				sh.HasPSK = len(extData) == 2
			case TLSExtKeyShare:
				if sh.IsHelloRetryRequest {
					if len(extData) == 2 {
						sh.SelectedGroup = binary.BigEndian.Uint16(extData)
					}
				} else if len(extData) > 4 && int(binary.BigEndian.Uint16(extData[2:])) == len(extData)-4 {
					sh.SelectedGroup = binary.BigEndian.Uint16(extData)
				}
			case TLSExtSupportedVersions:
				if len(extData) == 2 {
					v := binary.BigEndian.Uint16(extData[0:2])
					sh.SupportedVersion = v
					sh.NegotiatedVersion = v
				}
			case TLSExtALPN:
				if len(extData) >= 4 {
					listLen := int(binary.BigEndian.Uint16(extData[0:2]))
					pLen := int(extData[2])
					if 2+listLen <= len(extData) && 3+pLen <= 2+listLen && pLen > 0 {
						sh.ALPN = string(extData[3 : 3+pLen])
					}
				}
			}
		}
	}

	sh.JA4S = computeJA4S(&sh, isQUIC)
	return sh, nil
}

func ja4VersionCode(v uint16) string {
	switch v {
	case TLSVersion13:
		return "13"
	case TLSVersion12:
		return "12"
	case TLSVersion11:
		return "11"
	case TLSVersion10:
		return "10"
	case TLSVersionSSL30:
		return "s3"
	default:
		return "00"
	}
}

func ja4ALPNCode(alpn string) [2]byte {
	if len(alpn) == 0 {
		return [2]byte{'0', '0'}
	}
	first := alpn[0]
	last := alpn[len(alpn)-1]
	if !isASCIIAlphaNum(first) || !isASCIIAlphaNum(last) {
		var hexPair [2]byte
		hex.Encode(hexPair[:], []byte{first})
		if len(alpn) > 1 {
			var lastHex [2]byte
			hex.Encode(lastHex[:], []byte{last})
			hexPair[1] = lastHex[1]
		}
		return hexPair
	}
	return [2]byte{first, last}
}

func isASCIIAlphaNum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func appendTwoDigits(dst []byte, n int) []byte {
	if n > 99 {
		n = 99
	}
	return append(dst, byte('0'+n/10), byte('0'+n%10))
}

func appendHex16(dst []byte, v uint16) []byte {
	const hexDigits = "0123456789abcdef"
	return append(dst,
		hexDigits[(v>>12)&0x0f],
		hexDigits[(v>>8)&0x0f],
		hexDigits[(v>>4)&0x0f],
		hexDigits[v&0x0f],
	)
}

func appendTruncSHA256Hex12(dst []byte, b []byte) []byte {
	if len(b) == 0 {
		return append(dst, "000000000000"...)
	}
	sum := sha256.Sum256(b)
	var hexBuf [12]byte
	hex.Encode(hexBuf[:], sum[:6])
	return append(dst, hexBuf[:]...)
}

func computeJA4(ch *TLSClientHello, isQUIC bool) string {
	// Filter non-GREASE ciphers and extensions using stack backing arrays.
	var ciphersBacking [64]uint16
	ciphers := ciphersBacking[:0]
	for _, c := range ch.CipherSuites {
		if !IsGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	var extCount int
	var extsBacking [64]uint16
	hashExts := extsBacking[:0]
	for _, e := range ch.Extensions {
		if IsGREASE(e) {
			continue
		}
		extCount++
		if e != TLSExtServerName && e != TLSExtALPN {
			hashExts = append(hashExts, e)
		}
	}

	// Part a (10 chars): [t|q][version][d|i][ciphers:2][exts:2][alpn:2]
	var out [36]byte
	b := out[:0]
	if isQUIC {
		b = append(b, 'q')
	} else {
		b = append(b, 't')
	}
	b = append(b, ja4VersionCode(ch.NegotiatedVersion)...)
	if ch.SNI != "" && !ch.Anomalies.SNIIPLiteral {
		b = append(b, 'd')
	} else {
		b = append(b, 'i')
	}
	b = appendTwoDigits(b, len(ciphers))
	b = appendTwoDigits(b, extCount)
	var firstALPN string
	if len(ch.ALPNs) > 0 {
		firstALPN = ch.ALPNs[0]
	}
	alpnChars := ja4ALPNCode(firstALPN)
	b = append(b, alpnChars[0], alpnChars[1], '_')

	// Part b: sorted non-GREASE ciphers hash (12 chars).
	if len(ciphers) == 0 {
		b = append(b, "000000000000"...)
	} else {
		slices.Sort(ciphers)
		var csBacking [256]byte
		csBuf := csBacking[:0]
		for i, c := range ciphers {
			if i > 0 {
				csBuf = append(csBuf, ',')
			}
			csBuf = appendHex16(csBuf, c)
		}
		b = appendTruncSHA256Hex12(b, csBuf)
	}
	b = append(b, '_')

	// Part c: sorted non-GREASE extensions (excluding SNI & ALPN) + "_" + original-order signature schemes.
	if len(hashExts) == 0 {
		b = append(b, "000000000000"...)
	} else {
		slices.Sort(hashExts)
		var extBacking [512]byte
		extBuf := extBacking[:0]
		for i, e := range hashExts {
			if i > 0 {
				extBuf = append(extBuf, ',')
			}
			extBuf = appendHex16(extBuf, e)
		}
		// Append non-GREASE signature algorithms in wire order.
		firstSig := true
		for _, sig := range ch.SignatureSchemes {
			if IsGREASE(sig) {
				continue
			}
			if firstSig {
				extBuf = append(extBuf, '_')
				firstSig = false
			} else {
				extBuf = append(extBuf, ',')
			}
			extBuf = appendHex16(extBuf, sig)
		}
		b = appendTruncSHA256Hex12(b, extBuf)
	}

	return string(b)
}

func computeJA4S(sh *TLSServerHello, isQUIC bool) string {
	var out [32]byte
	b := out[:0]
	if isQUIC {
		b = append(b, 'q')
	} else {
		b = append(b, 't')
	}
	b = append(b, ja4VersionCode(sh.NegotiatedVersion)...)
	b = appendTwoDigits(b, len(sh.Extensions))
	alpnChars := ja4ALPNCode(sh.ALPN)
	b = append(b, alpnChars[0], alpnChars[1], '_')
	b = appendHex16(b, sh.CipherSuite)
	b = append(b, '_')

	if len(sh.Extensions) == 0 {
		b = append(b, "000000000000"...)
	} else {
		var extBacking [256]byte
		extBuf := extBacking[:0]
		for i, e := range sh.Extensions {
			if i > 0 {
				extBuf = append(extBuf, ',')
			}
			extBuf = appendHex16(extBuf, e)
		}
		b = appendTruncSHA256Hex12(b, extBuf)
	}
	return string(b)
}

func parseTLSCertificateBody(body []byte) ([]TLSCertificate, TLSAnomalies, error) {
	var anomalies TLSAnomalies
	if len(body) < 3 {
		return nil, anomalies, fmt.Errorf("%w: Certificate handshake body too short", ErrInvalidTLS)
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	offset := 3
	if offset+listLen > len(body) {
		anomalies.TruncatedRecord = true
		listLen = len(body) - offset
	}
	end := offset + listLen

	var certs []TLSCertificate
	for offset+3 <= end && len(certs) < MaxTLSCertificates {
		certLen := int(body[offset])<<16 | int(body[offset+1])<<8 | int(body[offset+2])
		offset += 3
		if certLen <= 0 || offset+certLen > end {
			anomalies.TruncatedRecord = true
			break
		}
		der := bytes.Clone(body[offset : offset+certLen])
		offset += certLen

		certs = appendTLSCertificate(certs, der, &anomalies)
	}

	return certs, anomalies, nil
}

func appendTLSCertificate(certs []TLSCertificate, der []byte, anomalies *TLSAnomalies) []TLSCertificate {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		anomalies.InvalidCertificateDER = true
		return certs
	}
	selfSigned := bytes.Equal(parsed.RawIssuer, parsed.RawSubject)
	if len(certs) == 0 && selfSigned {
		anomalies.SelfSignedCertificate = true
	}
	ja4x := JA4XFromCert(parsed)
	var serialHex string
	if parsed.SerialNumber != nil {
		serialHex = hex.EncodeToString(parsed.SerialNumber.Bytes())
	}
	names := parsed.DNSNames
	if len(names) > MaxTLSCertSANsPerKind {
		// Release the backing array and strings for names beyond the limit.
		names = slices.Clone(names[:MaxTLSCertSANsPerKind])
	}
	ipCount := min(len(parsed.IPAddresses), MaxTLSCertSANsPerKind)
	var ips []netip.Addr
	if ipCount > 0 {
		ips = make([]netip.Addr, ipCount)
		for i, ip := range parsed.IPAddresses[:ipCount] {
			// x509 accepts only four- and sixteen-byte IP SANs.
			ips[i], _ = netip.AddrFromSlice(ip)
		}
	}
	return append(certs, TLSCertificate{
		Version:       parsed.Version,
		Serial:        serialHex,
		Subject:       parsed.Subject.String(),
		Issuer:        parsed.Issuer.String(),
		NotBefore:     parsed.NotBefore.Unix(),
		NotAfter:      parsed.NotAfter.Unix(),
		DNSNames:      names,
		IPAddresses:   ips,
		SANsTruncated: len(parsed.DNSNames) > len(names) || len(parsed.IPAddresses) > ipCount,
		SelfSigned:    selfSigned,
		JA4X:          ja4x,
		RawDER:        der,
	})
}

// JA4XFromDER parses a DER-encoded X.509 certificate and returns its FoxIO JA4X
// structural fingerprint (<issuer_rdn_hash>_<subject_rdn_hash>_<extension_oid_hash>).
func JA4XFromDER(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidTLS, err)
	}
	return JA4XFromCert(cert), nil
}

// JA4XFromCert computes the FoxIO JA4X fingerprint for an already-parsed
// [x509.Certificate].
func JA4XFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return "000000000000_000000000000_000000000000"
	}
	var out [38]byte
	var scratch [256]byte
	b := appendTruncSHA256Hex12(out[:0], appendRDNOIDHexList(scratch[:0], cert.RawIssuer))
	b = append(b, '_')
	b = appendTruncSHA256Hex12(b, appendRDNOIDHexList(scratch[:0], cert.RawSubject))
	b = append(b, '_')
	extOIDs := scratch[:0]
	for i, ext := range cert.Extensions {
		rawOID, err := asn1.Marshal(ext.Id)
		if err != nil {
			continue
		}
		var oidRaw asn1.RawValue
		if _, err := asn1.Unmarshal(rawOID, &oidRaw); err != nil || oidRaw.Tag != asn1.TagOID {
			continue
		}
		if i > 0 && len(extOIDs) > 0 {
			extOIDs = append(extOIDs, ',')
		}
		extOIDs = hex.AppendEncode(extOIDs, oidRaw.Bytes)
	}

	return string(appendTruncSHA256Hex12(b, extOIDs))
}

func appendRDNOIDHexList(out, rawRDNSeq []byte) []byte {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(rawRDNSeq, &seq); err != nil {
		return out
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var rdnSet asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rdnSet)
		if err != nil {
			break
		}
		setBytes := rdnSet.Bytes
		for len(setBytes) > 0 {
			var atv asn1.RawValue
			setBytes, err = asn1.Unmarshal(setBytes, &atv)
			if err != nil {
				break
			}
			var oidRaw asn1.RawValue
			if _, err := asn1.Unmarshal(atv.Bytes, &oidRaw); err != nil || oidRaw.Tag != asn1.TagOID {
				continue
			}
			if len(out) > 0 {
				out = append(out, ',')
			}
			out = hex.AppendEncode(out, oidRaw.Bytes)
		}
	}
	return out
}

func mergeTLSAnomalies(a, b TLSAnomalies) TLSAnomalies {
	return TLSAnomalies{
		TruncatedRecord:       a.TruncatedRecord || b.TruncatedRecord,
		SNIIPLiteral:          a.SNIIPLiteral || b.SNIIPLiteral,
		EmptySNI:              a.EmptySNI || b.EmptySNI,
		DuplicateExtension:    a.DuplicateExtension || b.DuplicateExtension,
		ALPNTransportMismatch: a.ALPNTransportMismatch || b.ALPNTransportMismatch,
		SelfSignedCertificate: a.SelfSignedCertificate || b.SelfSignedCertificate,
		InvalidCertificateDER: a.InvalidCertificateDER || b.InvalidCertificateDER,
	}
}

// TLS extracts TLS handshakes (ClientHello, ServerHello, X.509 certificates,
// JA4, JA4S, and JA4X) across all reassembled TCP streams in the capture.
// Parsing in each direction stops at its first known TCP sequence gap.
// When the capture contains PcapNG Decryption Secrets Blocks (DSB) with
// matching TLS 1.3 handshake traffic secrets, TLS also extracts the authenticated
// handshake messages from each direction for which a secret is available.
// See [Capture.UnsupportedLinkTypePackets] for link-type coverage.
func (c *Capture) TLS(data []byte) ([]TLSRecord, error) {
	return c.TLSWithKeyLog(data, nil)
}

// TLSWithKeyLog extracts TLS handshakes across all reassembled TCP streams in
// the capture, using embedded PcapNG Decryption Secrets Blocks (DSB) and
// optional extraKeyLog bytes to decrypt client and server TLS 1.3 certificate chains.
// Parsing in each direction stops at its first known TCP sequence gap.
func (c *Capture) TLSWithKeyLog(data []byte, extraKeyLog []byte) ([]TLSRecord, error) {
	var meta []streamMetadata
	streams, err := collectStreams(ipFrameSource{capture: c, data: data}, 0, &meta, tcpWireNone)
	if err != nil {
		return nil, err
	}
	return c.tlsFromStreams(streams, meta, extraKeyLog)
}

func (c *Capture) tlsFromStreams(streams []TCPStream, meta []streamMetadata, extraKeyLog []byte) ([]TLSRecord, error) {
	if len(streams) == 0 {
		return nil, nil
	}

	keyLog, err := c.TLSKeyLog(extraKeyLog)
	if err != nil {
		return nil, err
	}

	return tlsRecordsFromStreams(streams, meta, keyLog)
}

func tlsRecordsFromStreams(streams []TCPStream, meta []streamMetadata, keyLog *TLSKeyLog) ([]TLSRecord, error) {
	var records []TLSRecord
	for i := range streams {
		st := streams[i]
		st.Client.Data = st.Client.Data[:meta[i].clientPrefix]
		st.Server.Data = st.Server.Data[:meta[i].serverPrefix]
		st, _, _ = proxyStream(st)
		cData, sData := st.Client.Data, st.Server.Data
		srcAddr, dstAddr, srcPort, dstPort := st.SrcAddr, st.DstAddr, st.SrcPort, st.DstPort
		var merged TLSHandshake
		var found bool

		var clientHS, serverHS TLSHandshake
		var hasC, hasS bool
		if hasTLSHandshakeStart(cData) {
			if hs, err := ParseTLSRecords(cData); err == nil {
				clientHS, hasC = hs, true
			}
		}
		if hasTLSHandshakeStart(sData) {
			if hs, err := ParseTLSRecords(sData); err == nil {
				serverHS, hasS = hs, true
			}
		}
		if !clientHS.HasClientHello && (serverHS.HasClientHello || clientHS.HasServerHello || clientHS.HasCertificateRequest) {
			clientHS, serverHS = serverHS, clientHS
			hasC, hasS = hasS, hasC
			cData, sData = sData, cData
			srcAddr, dstAddr = dstAddr, srcAddr
			srcPort, dstPort = dstPort, srcPort
		}

		if hasC && clientHS.HasClientHello {
			merged.ClientHello = clientHS.ClientHello
			merged.HasClientHello = true
			merged.Anomalies = mergeTLSAnomalies(merged.Anomalies, clientHS.Anomalies)
			merged.ClientCertificates = clientHS.ClientCertificates
			found = true
		}

		if hasC && !clientHS.HasClientHello && (serverHS.HasServerHello || serverHS.HasCertificateRequest) {
			merged.ClientCertificates = clientHS.Certificates
			merged.Anomalies = mergeTLSAnomalies(merged.Anomalies, clientHS.Anomalies)
		}
		if hasS {
			merged.HasCertificateRequest = serverHS.HasCertificateRequest
			found = found || merged.HasCertificateRequest
			if serverHS.HasServerHello {
				merged.IsResumed = serverHS.IsResumed && serverHS.ServerHello.NegotiatedVersion == TLSVersion13
				merged.ServerHello = serverHS.ServerHello
				merged.HasServerHello = true
				found = true
			}
			if len(serverHS.Certificates) > 0 {
				merged.Certificates = serverHS.Certificates
				found = true
			}
			merged.Anomalies = mergeTLSAnomalies(merged.Anomalies, serverHS.Anomalies)
		}

		if merged.HasClientHello && merged.HasServerHello && merged.ServerHello.NegotiatedVersion == TLSVersion13 && keyLog != nil {
			if entry, ok := keyLog.Entries[merged.ClientHello.Random]; ok {
				merged.readTLS13CertificateFlight(sData, entry.ServerHandshakeSecret, false)
				merged.readTLS13CertificateFlight(cData, entry.ClientHandshakeSecret, true)
			}
		}

		if found {
			merged.IsResumed = merged.IsResumed || merged.hasResumedSessionID()
			if len(records) >= MaxTLSHandshakesPerScan {
				return nil, fmt.Errorf("%w: exceeds %d TLS handshakes", ErrTLSLimit, MaxTLSHandshakesPerScan)
			}
			records = append(records, TLSRecord{
				FlowIndex: st.FlowIndex,
				SrcAddr:   srcAddr,
				DstAddr:   dstAddr,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Handshake: merged,
			})
		}
	}

	return records, nil
}

func (out *TLSHandshake) readTLS13CertificateFlight(stream, secret []byte, client bool) {
	if len(secret) == 0 {
		return
	}
	chain := &out.Certificates
	if client {
		chain = &out.ClientCertificates
	}
	hsData, _, err := DecryptTLS13Records(stream, out.ServerHello.CipherSuite, secret, nil)
	if err != nil {
		return
	}
	offset := 0
	for offset+4 <= len(hsData) {
		msgType := hsData[offset]
		msgLen := int(hsData[offset+1])<<16 | int(hsData[offset+2])<<8 | int(hsData[offset+3])
		if msgLen > MaxTLSHandshakeBytes || offset+4+msgLen > len(hsData) {
			break
		}
		body := hsData[offset+4 : offset+4+msgLen]
		offset += 4 + msgLen

		if msgType == TLSHandshakeCertificateRequest && !client {
			out.HasCertificateRequest = true
		}
		if msgType == TLSHandshakeCertificate && len(*chain) == 0 {
			if certs, certAnom, err := parseTLSCertificateWithTLS13Context(body); err == nil {
				out.Anomalies = mergeTLSAnomalies(out.Anomalies, certAnom)
				if len(certs) > 0 {
					*chain = certs
					return
				}
			}
		}
	}
}

// parseTLSCertificateWithTLS13Context parses a TLS 1.3 Certificate handshake
// body (RFC 8446 §4.4.2: 1-byte certificate_request_context length + context,
// followed by 3-byte certificate_list length and entries where each entry has
// a 3-byte cert_data length, DER bytes, and a 2-byte extensions length) or
// falls back to TLS 1.2 Certificate body layout.
func parseTLSCertificateWithTLS13Context(body []byte) ([]TLSCertificate, TLSAnomalies, error) {
	var anomalies TLSAnomalies
	if len(body) < 4 {
		return nil, anomalies, ErrInvalidTLS
	}
	ctxLen := int(body[0])
	if 1+ctxLen+3 > len(body) {
		return parseTLSCertificateBody(body)
	}
	pos := 1 + ctxLen
	listLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
	pos += 3
	if pos+listLen != len(body) {
		// Fall back to TLS 1.2 layout (no certificate_request_context prefix or per-cert extensions).
		return parseTLSCertificateBody(body)
	}

	end := pos + listLen
	var certs []TLSCertificate
	for pos+3 <= end && len(certs) < MaxTLSCertificates {
		certLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
		pos += 3
		if certLen <= 0 || pos+certLen > end {
			anomalies.TruncatedRecord = true
			break
		}
		der := bytes.Clone(body[pos : pos+certLen])
		pos += certLen

		// TLS 1.3 CertificateEntry carries a 2-byte extensions length after cert_data.
		if pos+2 > end {
			anomalies.TruncatedRecord = true
			break
		}
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		if pos+2+extLen > end {
			anomalies.TruncatedRecord = true
			break
		}
		pos += 2 + extLen

		certs = appendTLSCertificate(certs, der, &anomalies)
	}
	return certs, anomalies, nil
}

func hasTLSHandshakeStart(buf []byte) bool {
	if len(buf) < 6 || buf[0] != TLSRecordHandshake || buf[1] != 0x03 || buf[2] > 0x04 {
		return false
	}
	if buf[3] == 0 && buf[4] == 0 {
		return true // Let ParseTLSRecords charge leading empty records to its budget.
	}
	hsType := buf[5]
	return hsType == TLSHandshakeClientHello || hsType == TLSHandshakeServerHello || hsType == TLSHandshakeCertificate || hsType == TLSHandshakeCertificateRequest
}

// HasTLSJA4 reports whether any TLS ClientHello in the capture matches the
// supplied JA4 fingerprint string.
func (c *Capture) HasTLSJA4(data []byte, ja4 string) (bool, error) {
	records, err := c.TLS(data)
	if err != nil {
		return false, err
	}
	for i := range records {
		if records[i].Handshake.HasClientHello && records[i].Handshake.ClientHello.JA4 == ja4 {
			return true, nil
		}
	}
	return false, nil
}

// HasTLSSNI reports whether any TLS ClientHello in the capture matches sni
// (case-insensitive ASCII comparison).
func (c *Capture) HasTLSSNI(data []byte, sni string) (bool, error) {
	records, err := c.TLS(data)
	if err != nil {
		return false, err
	}
	for i := range records {
		if records[i].Handshake.HasClientHello && strings.EqualFold(records[i].Handshake.ClientHello.SNI, sni) {
			return true, nil
		}
	}
	return false, nil
}

// Unused helper imports check.
var (
	_ = cmp.Compare[int]
	_ = strconv.Itoa
)
