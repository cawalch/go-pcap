package pcap

import "errors"

// Capture container formats.
type Format uint8

const (
	FormatUnknown Format = iota
	FormatPCAP
	FormatPCAPNG
)

// String returns the short name of the capture format ("pcap", "pcapng", or "unknown").
func (f Format) String() string {
	switch f {
	case FormatPCAP:
		return "pcap"
	case FormatPCAPNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// Classic PCAP and PcapNG magic numbers.
const (
	PCAPMagicMicroLE         uint32 = 0xa1b2c3d4
	PCAPMagicMicroBE         uint32 = 0xd4c3b2a1
	PCAPMagicNanoLE          uint32 = 0xa1b23c4d
	PCAPMagicNanoBE          uint32 = 0x4d3cb2a1
	PCAPNGSectionHeaderMagic uint32 = 0x0a0d0d0a
	PCAPNGByteOrderMagic     uint32 = 0x1a2b3c4d
)

// LinkType identifies a link-layer encapsulation type (LINKTYPE_* / DLT_*).
type LinkType uint16

const (
	LinkTypeNull              LinkType = 0   // BSD loopback encapsulation
	LinkTypeEthernet          LinkType = 1   // IEEE 802.3 Ethernet
	LinkTypeRaw               LinkType = 101 // Raw IP (IPv4 or IPv6)
	LinkTypeIEEE80211         LinkType = 105 // IEEE 802.11 MAC frames
	LinkTypeLinuxSLL          LinkType = 113 // Linux cooked capture v1
	LinkTypeIEEE80211RadioTap LinkType = 127 // Radiotap followed by IEEE 802.11
	LinkTypeIPv4              LinkType = 228 // Raw IPv4
	LinkTypeIPv6              LinkType = 229 // Raw IPv6
	LinkTypeLinuxSLL2         LinkType = 276 // Linux cooked capture v2
)

// PcapNG block type codes.
const (
	BlockTypeSectionHeader      uint32 = 0x0a0d0d0a
	BlockTypeInterfaceDesc      uint32 = 0x00000001
	blockTypeLegacyPacket       uint32 = 0x00000002
	BlockTypeSimplePacket       uint32 = 0x00000003
	BlockTypeNameResolution     uint32 = 0x00000004
	BlockTypeInterfaceStats     uint32 = 0x00000005
	BlockTypeEnhancedPacket     uint32 = 0x00000006
	BlockTypeDecryptionSecrets  uint32 = 0x0000000a
	BlockTypeDarwinProcessEvent uint32 = 0x80000001
)

// PcapNG option and record codes.
const (
	optEndOfOpt uint16 = 0
	optComment  uint16 = 1

	// Section Header Block (SHB) options.
	optSHBHardware uint16 = 2
	optSHBOS       uint16 = 3
	optSHBUserAppl uint16 = 4

	// Interface Description Block (IDB) options.
	optIDBName        uint16 = 2
	optIDBDescription uint16 = 3
	optIDBTsResol     uint16 = 9
	optIDBOS          uint16 = 12
	optIDBTsOffset    uint16 = 14

	// Enhanced Packet Block (EPB) options.
	optEPBFlags     uint16 = 2
	optEPBDropCount uint16 = 4
	optEPBPacketID  uint16 = 5
	optEPBQueue     uint16 = 6

	// Apple assigns 0x8001 to the primary process block index. Early go-pcap
	// files used 0x8000 for that index and 0x8001–0x8006 for inline metadata.
	optEPBDarwinProcessIndex uint16 = 0x8001
	optEPBLegacyProcessIndex uint16 = 0x8000
	optEPBLegacyThreadID     uint16 = 0x8002
	optEPBLegacyProcessName  uint16 = 0x8003
	optEPBLegacyProcessArgs  uint16 = 0x8004
	optEPBLegacyUserID       uint16 = 0x8005
	optEPBLegacyContainerID  uint16 = 0x8006

	// Name Resolution Block (NRB) record types.
	nrbRecordEnd  uint16 = 0x0000
	nrbRecordIPv4 uint16 = 0x0001
	nrbRecordIPv6 uint16 = 0x0002

	// Interface Statistics Block (ISB) options.
	optISBStartTime uint16 = 2
	optISBEndTime   uint16 = 3
	optISBIfRecv    uint16 = 4
	optISBIfDrop    uint16 = 5

	// Darwin Process Event Block (DPEB) options.
	optDPEBProcessName uint16 = 2
)

// PcapNG Decryption Secrets Block (DSB) secret types.
const (
	SecretsTypeTLSKeyLog       uint32 = 0x544c534b // "TLSK" (NSS Key Log format)
	SecretsTypeWireGuardKeyLog uint32 = 0x57474b4c // "WGKL"
	SecretsTypeZigBeeNWKKey    uint32 = 0x5a4e574b // "ZNWK"
	SecretsTypeZigBeeAPSKey    uint32 = 0x5a415053 // "ZAPS"
)

// Ethernet protocol types (EtherType).
const (
	EtherTypeIPv4          uint16 = 0x0800
	EtherTypeARP           uint16 = 0x0806
	EtherTypeTransparentBr uint16 = 0x6558 // Transparent Ethernet Bridging (GRE inner Ethernet)
	EtherTypeVLAN          uint16 = 0x8100 // IEEE 802.1Q
	EtherTypeIPv6          uint16 = 0x86dd
	EtherTypeMPLSUnicast   uint16 = 0x8847
	EtherTypeMPLSMulticast uint16 = 0x8848
	EtherTypePPPoESession  uint16 = 0x8864
	EtherTypeQinQ          uint16 = 0x88a8 // IEEE 802.1ad
	EtherTypeQinQLegacy    uint16 = 0x9100
)

// IP protocol numbers.
const (
	IPProtoHopByHop  uint8 = 0
	IPProtoICMP      uint8 = 1
	IPProtoTCP       uint8 = 6
	IPProtoUDP       uint8 = 17
	IPProtoIPv6      uint8 = 41
	IPProtoIPv6Route uint8 = 43
	IPProtoIPv6Frag  uint8 = 44
	IPProtoGRE       uint8 = 47
	IPProtoESP       uint8 = 50
	IPProtoAH        uint8 = 51
	IPProtoIPv6ICMP  uint8 = 58
	IPProtoIPv6NoNxt uint8 = 59
	IPProtoIPv6Opts  uint8 = 60
	IPProtoSCTP      uint8 = 132
)

// TCP control flags.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
	TCPFlagECE uint8 = 0x40
	TCPFlagCWR uint8 = 0x80
)

// LayerProto identifies a decoded protocol layer inside a [Frame].
type LayerProto uint8

const (
	LayerNone LayerProto = iota
	LayerEthernet
	LayerVLAN
	LayerLinuxSLL
	LayerLinuxSLL2
	LayerLoopback
	LayerRawIP
	LayerARP
	LayerMPLS
	LayerPPPoE
	LayerGRE
	LayerVXLAN
	LayerGeneve
	LayerIPv4
	LayerIPv6
	LayerIPv6Ext
	LayerTCP
	LayerUDP
	LayerICMPv4
	LayerICMPv6
	LayerRadiotap
	LayerIEEE80211
	LayerESP
	LayerIKEv2
)

// String returns the lowercase layer identifier.
func (p LayerProto) String() string {
	switch p {
	case LayerEthernet:
		return "ethernet"
	case LayerVLAN:
		return "vlan"
	case LayerLinuxSLL:
		return "linux_sll"
	case LayerLinuxSLL2:
		return "linux_sll2"
	case LayerLoopback:
		return "loopback"
	case LayerRawIP:
		return "raw_ip"
	case LayerARP:
		return "arp"
	case LayerMPLS:
		return "mpls"
	case LayerPPPoE:
		return "pppoe"
	case LayerGRE:
		return "gre"
	case LayerVXLAN:
		return "vxlan"
	case LayerGeneve:
		return "geneve"
	case LayerIPv4:
		return "ipv4"
	case LayerIPv6:
		return "ipv6"
	case LayerIPv6Ext:
		return "ipv6_ext"
	case LayerTCP:
		return "tcp"
	case LayerUDP:
		return "udp"
	case LayerICMPv4:
		return "icmpv4"
	case LayerICMPv6:
		return "icmpv6"
	case LayerRadiotap:
		return "radiotap"
	case LayerIEEE80211:
		return "ieee80211"
	case LayerESP:
		return "esp"
	case LayerIKEv2:
		return "ikev2"
	default:
		return "none"
	}
}

// Work and output limits.
const (
	MaxDecompressedCaptureBytes = 64 << 20 // 64 MiB of output across gzip members.
	MaxInterfaces               = 256
	MaxPackets                  = 1_048_576
	MaxPCAPNGBlocks             = 2 * MaxPackets // All block types across all sections.
	MaxFlows                    = 65_536
	MaxDecryptionSecrets        = 256
	MaxDecryptionSecretBytes    = 4 << 20 // 4 MiB across all DSB blocks
	MaxNameResolutionRecords    = 16_384
	MaxNamesPerRecord           = 64 // Nonempty names in one PcapNG name resolution record.
	MaxInterfaceStats           = 1024
	MaxProcessEvents            = 16_384
	MaxOptionsPerBlock          = 64
	MaxOptionStringBytes        = 4096
	MaxSnapLen                  = 16 << 20 // 16 MiB
	MaxFrameLayers              = 8
	MaxVLANTags                 = 4
	MaxMPLSLabels               = 8
	MaxIPv6ExtHeaders           = 8

	// TCP stream reassembly limits.
	MaxSegmentsPerFlow  = 4096
	MaxFlowStreamBytes  = 4 << 20  // 4 MiB per direction per flow
	MaxTotalStreamBytes = 64 << 20 // 64 MiB total reassembled stream bytes per call
	MaxTCPOptions       = 32

	// DNS parser limits.
	MaxDNSQuestions        = 64
	MaxDNSResourceRecords  = 256
	MaxDNSCompressionJumps = 16
	MaxDNSNameBytes        = 255
	MaxDNSTXTStrings       = 32
	MaxDNSALPNProtocols    = 32 // Maximum ALPN identifiers per SVCB or HTTPS record.
	MaxDNSMessagesPerScan  = 65_536

	// TLS parser limits.
	MaxTLSRecordBytes         = 16384 + 2048 // RFC 8446 record expansion limit
	MaxTLSHandshakeRecords    = 128          // Maximum records inspected per directional plaintext handshake scan.
	MaxTLSHandshakeBytes      = 256 << 10    // 256 KiB coalesced handshake message
	MaxTLSCipherSuites        = 256
	MaxTLSExtensions          = 128
	MaxTLSSignatureSchemes    = 128
	MaxTLSALPNProtocols       = 32
	MaxTLSCertificates        = 16
	MaxTLSCertSANsPerKind     = 64 // Maximum DNS names and IP addresses retained per certificate, independently.
	MaxTLSHandshakesPerScan   = 16_384
	MaxTLSKeyUpdatesPerStream = 32 // Maximum application traffic key updates per direction.
	MaxTLSKeyLogEntries       = 4096

	// QUIC Initial parser limits.
	MaxQUICConnIDBytes    = 20
	MaxQUICTokenBytes     = 4096
	MaxQUICCryptoBytes    = 64 << 10 // 64 KiB reassembled CRYPTO stream
	MaxQUICPacketsPerFlow = 64
	MaxQUICFlowsPerScan   = 16_384

	// HTTP parser limits.
	MaxHTTPHeaders         = 128
	MaxHTTPHeaderLineBytes = 8192
	MaxHTTPCookies         = 64
	MaxHTTPBodyBytes       = 4 << 20 // 4 MiB carved HTTP payload per message

	// MaxHTTPDecodedBodyBytesPerScan caps the total bytes charged to HTTP/1.x
	// content decoding in one [Capture.HTTP] call. It counts bytes produced by
	// failed decoding attempts and charges at most [MaxHTTPBodyBytes] per body.
	MaxHTTPDecodedBodyBytesPerScan = 64 << 20
	MaxHTTPMessagesPerScan         = 16_384

	// SSH parser limits.
	MaxSSHBannerBytes       = 255
	MaxSSHKexPacketBytes    = 32768
	MaxSSHNameListBytes     = 16384
	MaxSSHHandshakesPerScan = 16_384

	// SMB2 / NTLM parser limits.
	MaxSMB2PacketBytes   = 64 << 10
	MaxNTLMTokenBytes    = 16 << 10
	MaxNTLMAvPairs       = 32
	MaxSMBRecordsPerScan = 16_384

	// Live capture and ReaderAt scan limits.
	MaxBPFFilterInstructions = 4096
	DefaultLiveSnapLen       = 65535
	DefaultLiveBufferSize    = 256 << 10
	MaxReaderAtScanBytes     = 64 << 20 // 64 MiB per call: all flow/DNS/TLS/QUIC scan reads

	// IPv4 / IPv6 defragmentation limits.
	MaxFragmentGroups           = 1024
	MaxFragmentsPerGroup        = 16
	MaxReassembledIPPacketBytes = 65535

	// MaxWebSocketFramesPerStream bounds frames in each direction, including continuations.
	MaxWebSocketFramesPerStream = 1024

	// HTTP/2 parser limits.
	MaxHTTP2FramesPerStream     = 1024
	MaxHTTP2Settings            = 64
	MaxHTTP2DynamicTableBytes   = 4096
	MaxHTTP2DynamicTableEntries = 128
	MaxHTTP2HeaderBlockBytes    = 64 << 10
	MaxHTTP2DecodedHeaderBytes  = 4 << 20 // Logical header storage budget, shared per scan.
	MaxHTTP2FramePayload        = 1 << 20

	// Kerberos v5 and RDP parser limits.
	MaxKRB5PacketBytes    = 64 << 10
	MaxKRB5PrincipalParts = 16
	MaxKRB5ETypes         = 32
	MaxKRB5RecordsPerScan = 16_384
	MaxRDPPacketBytes     = 16 << 10
	MaxRDPCookieBytes     = 512
	MaxRDPRecordsPerScan  = 16_384
)

// Kerberos v5 message types and encryption types (RFC 4120).
const (
	KRB5MsgASReq  uint8 = 10
	KRB5MsgASRep  uint8 = 11
	KRB5MsgTGSReq uint8 = 12
	KRB5MsgTGSRep uint8 = 13
	KRB5MsgError  uint8 = 30

	KRB5ETypeAES128CTS int32 = 17
	KRB5ETypeAES256CTS int32 = 18
	KRB5ETypeRC4HMAC   int32 = 23
)

// RDP negotiation protocol flags (MS-RDPBCGR §2.2.1.1.1).
const (
	RDPProtoStandard uint32 = 0x00000000
	RDPProtoTLS      uint32 = 0x00000001
	RDPProtoCredSSP  uint32 = 0x00000002
	RDPProtoRDSTLS   uint32 = 0x00000004
	RDPProtoHybridEx uint32 = 0x00000008
)

// SMB2 command codes and NTLM message types.
const (
	SMB2CommandNegotiate    uint16 = 0x0000
	SMB2CommandSessionSetup uint16 = 0x0001
	SMB2CommandTreeConnect  uint16 = 0x0003
	SMB2CommandCreate       uint16 = 0x0005

	NTLMNegotiateMessage    uint32 = 1
	NTLMChallengeMessage    uint32 = 2
	NTLMAuthenticateMessage uint32 = 3
)

// QUIC protocol versions (RFC 9000 and RFC 9369).
const (
	QUICVersion1           uint32 = 0x00000001
	QUICVersion2           uint32 = 0x6b3343cf
	QUICVersionNegotiation uint32 = 0x00000000
)

// TLS 1.2 and TLS 1.3 cipher suites supported for offline decryption.
const (
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_AES_128_GCM_SHA256                  uint16 = 0x1301
	TLS_AES_256_GCM_SHA384                  uint16 = 0x1302
)

// DNS record types (TYPE_*).
const (
	DNSTypeA     uint16 = 1
	DNSTypeNS    uint16 = 2
	DNSTypeCNAME uint16 = 5
	DNSTypeSOA   uint16 = 6
	DNSTypePTR   uint16 = 12
	DNSTypeMX    uint16 = 15
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeSRV   uint16 = 33
	DNSTypeOPT   uint16 = 41
	DNSTypeSVCB  uint16 = 64
	DNSTypeHTTPS uint16 = 65
)

// DNS response codes (RCODE_*).
const (
	DNSRCodeSuccess        uint8 = 0
	DNSRCodeFormatError    uint8 = 1
	DNSRCodeServerFailure  uint8 = 2
	DNSRCodeNameError      uint8 = 3 // NXDOMAIN
	DNSRCodeNotImplemented uint8 = 4
	DNSRCodeRefused        uint8 = 5
)

// TLS record content types and handshake message types.
const (
	TLSRecordChangeCipherSpec uint8 = 20
	TLSRecordAlert            uint8 = 21
	TLSRecordHandshake        uint8 = 22
	TLSRecordApplicationData  uint8 = 23

	TLSHandshakeClientHello        uint8 = 1
	TLSHandshakeServerHello        uint8 = 2
	TLSHandshakeCertificate        uint8 = 11
	TLSHandshakeCertificateRequest uint8 = 13
	TLSHandshakeKeyUpdate          uint8 = 24
)

// TLS protocol versions.
const (
	TLSVersionSSL30 uint16 = 0x0300
	TLSVersion10    uint16 = 0x0301
	TLSVersion11    uint16 = 0x0302
	TLSVersion12    uint16 = 0x0303
	TLSVersion13    uint16 = 0x0304
)

// TLS extension numbers.
const (
	TLSExtServerName          uint16 = 0x0000
	TLSExtSupportedGroups     uint16 = 0x000a
	TLSExtECPointFormats      uint16 = 0x000b
	TLSExtSignatureAlgorithms uint16 = 0x000d
	TLSExtALPN                uint16 = 0x0010
	TLSExtSessionTicket       uint16 = 0x0023
	TLSExtPreSharedKey        uint16 = 0x0029
	TLSExtSupportedVersions   uint16 = 0x002b
	TLSExtKeyShare            uint16 = 0x0033
	TLSExtECH                 uint16 = 0xfe0d
)

// TLS named groups commonly observed in key_share.
const (
	TLSGroupSecp256r1             uint16 = 0x0017
	TLSGroupX25519                uint16 = 0x001d
	TLSGroupX25519Kyber768Draft00 uint16 = 0x6399
	TLSGroupSecP256r1MLKEM768     uint16 = 0x11eb
	TLSGroupX25519MLKEM768        uint16 = 0x11ec
)

// Parser and validation errors.
var (
	// ErrNotPCAP indicates the input does not begin with a recognized PCAP or PcapNG signature.
	ErrNotPCAP = errors.New("not a PCAP or PcapNG capture")
	// ErrInvalidMagic indicates an unrecognized magic signature or byte-order marker.
	ErrInvalidMagic = errors.New("invalid magic signature")
	// ErrInvalidHeader indicates a malformed or unsupported container header.
	ErrInvalidHeader = errors.New("invalid capture header")
	// ErrInvalidBlock indicates a malformed PcapNG block structure or length mismatch.
	ErrInvalidBlock = errors.New("invalid PcapNG block")
	// ErrInvalidPacket indicates a malformed packet record or missing interface reference.
	ErrInvalidPacket = errors.New("invalid packet record")
	// ErrInvalidFrame indicates a frame that cannot be decoded for its declared link type.
	ErrInvalidFrame = errors.New("invalid network frame")
	// ErrInvalidDNS indicates a malformed DNS header, question, or resource record.
	ErrInvalidDNS = errors.New("invalid DNS message")
	// ErrInvalidTLS indicates a malformed TLS record, handshake, or certificate structure.
	ErrInvalidTLS = errors.New("invalid TLS record or handshake")
	// ErrInvalidQUIC indicates a malformed or undecryptable QUIC Initial packet.
	ErrInvalidQUIC = errors.New("invalid QUIC Initial packet")
	// ErrInvalidHTTP indicates a malformed HTTP/1.x request or response.
	ErrInvalidHTTP = errors.New("invalid HTTP message")
	// ErrInvalidSSH indicates a malformed SSH version banner or KEXINIT packet.
	ErrInvalidSSH = errors.New("invalid SSH handshake")
	// ErrInvalidSMB indicates a malformed SMB2 header or NTLMSSP token.
	ErrInvalidSMB = errors.New("invalid SMB2 or NTLM message")
	// ErrInvalidKRB5 indicates a malformed Kerberos v5 ASN.1 message.
	ErrInvalidKRB5 = errors.New("invalid Kerberos v5 message")
	// ErrInvalidRDP indicates a malformed TPKT/X.224 RDP negotiation PDU.
	ErrInvalidRDP = errors.New("invalid RDP negotiation packet")
	// ErrLiveCaptureUnsupported indicates live interface capture is not supported on the target OS.
	ErrLiveCaptureUnsupported = errors.New("live capture unsupported on this platform")
	// ErrInterfaceLimit indicates the capture exceeds [MaxInterfaces].
	ErrInterfaceLimit = errors.New("interface count exceeds limit")
	// ErrPacketLimit indicates a packet, block, or scan read limit was exceeded.
	ErrPacketLimit = errors.New("packet count exceeds limit")
	// ErrFlowLimit indicates the capture exceeds [MaxFlows].
	ErrFlowLimit = errors.New("flow count exceeds limit")
	// ErrSecretLimit indicates the capture exceeds [MaxDecryptionSecrets] or [MaxDecryptionSecretBytes].
	ErrSecretLimit = errors.New("decryption secrets exceed limit")
	// ErrOptionLimit indicates a PcapNG block exceeds [MaxOptionsPerBlock] or [MaxOptionStringBytes].
	ErrOptionLimit = errors.New("PcapNG block options exceed limit")
	// ErrReassemblyLimit indicates TCP stream reassembly exceeds segment or byte limits.
	ErrReassemblyLimit = errors.New("TCP stream reassembly exceeds limit")
	// ErrFragmentLimit indicates IPv4/IPv6 packet defragmentation exceeds group, fragment, or byte limits.
	ErrFragmentLimit = errors.New("IP fragment reassembly exceeds limit")
	// ErrDNSLimit indicates a DNS message or capture exceeds DNS count or compression limits.
	ErrDNSLimit = errors.New("DNS record or jump count exceeds limit")
	// ErrTLSLimit indicates a TLS handshake or capture exceeds TLS size or item limits.
	ErrTLSLimit = errors.New("TLS handshake exceeds limit")
	// ErrQUICLimit indicates a QUIC flow or capture exceeds QUIC packet or CRYPTO stream limits.
	ErrQUICLimit = errors.New("QUIC Initial flow exceeds limit")
	// ErrInvalidWebSocket indicates invalid or incomplete WebSocket framing.
	ErrInvalidWebSocket = errors.New("invalid WebSocket frame")
	// ErrWebSocketLimit indicates a WebSocket count or size limit was exceeded.
	ErrWebSocketLimit = errors.New("WebSocket limit exceeded")

	// ErrHTTPLimit indicates an HTTP message or capture exceeds header or body limits.
	ErrHTTPLimit = errors.New("HTTP message exceeds limit")
	// ErrSSHLimit indicates an SSH handshake or capture exceeds banner or KEXINIT limits.
	ErrSSHLimit = errors.New("SSH handshake exceeds limit")
	// ErrSMBLimit indicates an SMB2 or NTLM message exceeds size or attribute limits.
	ErrSMBLimit = errors.New("SMB2 or NTLM message exceeds limit")
	// ErrKRB5Limit indicates a Kerberos v5 message or capture exceeds limits.
	ErrKRB5Limit = errors.New("Kerberos v5 message exceeds limit")
	// ErrRDPLimit indicates an RDP negotiation message or capture exceeds limits.
	ErrRDPLimit = errors.New("RDP negotiation message exceeds limit")
)
