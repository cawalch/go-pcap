package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PCAPNGWriterOptions configures container and interface metadata written by
// [NewPCAPNGWriter].
type PCAPNGWriterOptions struct {
	LinkType             LinkType
	SnapLen              uint32
	InterfaceName        string
	InterfaceDescription string
	Hardware             string
	OS                   string
	UserApplication      string
}

// PCAPNGWriter writes PcapNG Section Header, Interface Description, Decryption
// Secrets, and Enhanced Packet blocks to an [io.Writer].
type PCAPNGWriter struct {
	w        io.Writer
	linkType LinkType
	snapLen  uint32
}

// NewPCAPNGWriter writes a PcapNG Section Header Block (SHB) and Interface
// Description Block (IDB, interface ID 0 with nanosecond timestamp resolution)
// to w and returns a [PCAPNGWriter].
func NewPCAPNGWriter(w io.Writer, opts PCAPNGWriterOptions) (*PCAPNGWriter, error) {
	if w == nil {
		return nil, fmt.Errorf("%w: nil writer", ErrInvalidHeader)
	}
	linkType := opts.LinkType
	if linkType == 0 && opts.InterfaceName != "lo0" {
		linkType = LinkTypeEthernet
	}
	snapLen := opts.SnapLen
	if snapLen == 0 {
		snapLen = DefaultLiveSnapLen
	}
	if snapLen > MaxSnapLen {
		return nil, fmt.Errorf("%w: snaplen %d exceeds %d", ErrInvalidHeader, snapLen, MaxSnapLen)
	}

	var buf bytes.Buffer

	// 1. Section Header Block (SHB).
	var shb bytes.Buffer
	var shbFixed [16]byte
	binary.LittleEndian.PutUint32(shbFixed[0:4], PCAPNGByteOrderMagic)
	binary.LittleEndian.PutUint16(shbFixed[4:6], 1)
	binary.LittleEndian.PutUint16(shbFixed[6:8], 0)
	binary.LittleEndian.PutUint64(shbFixed[8:16], 0xffffffffffffffff)
	shb.Write(shbFixed[:])
	hasSHBOpts := false
	if opts.Hardware != "" {
		writePCAPNGOptionLE(&shb, optSHBHardware, []byte(opts.Hardware))
		hasSHBOpts = true
	}
	if opts.OS != "" {
		writePCAPNGOptionLE(&shb, optSHBOS, []byte(opts.OS))
		hasSHBOpts = true
	}
	if opts.UserApplication != "" {
		writePCAPNGOptionLE(&shb, optSHBUserAppl, []byte(opts.UserApplication))
		hasSHBOpts = true
	}
	if hasSHBOpts {
		writePCAPNGOptionLE(&shb, optEndOfOpt, nil)
	}
	writePCAPNGBlockLE(&buf, BlockTypeSectionHeader, shb.Bytes())

	// 2. Interface Description Block (IDB) with nanosecond timestamp resolution (10^-9 s).
	var idb bytes.Buffer
	var idbFixed [8]byte
	binary.LittleEndian.PutUint16(idbFixed[0:2], uint16(linkType))
	binary.LittleEndian.PutUint32(idbFixed[4:8], snapLen)
	idb.Write(idbFixed[:])
	if opts.InterfaceName != "" {
		writePCAPNGOptionLE(&idb, optIDBName, []byte(opts.InterfaceName))
	}
	if opts.InterfaceDescription != "" {
		writePCAPNGOptionLE(&idb, optIDBDescription, []byte(opts.InterfaceDescription))
	}
	writePCAPNGOptionLE(&idb, optIDBTsResol, []byte{9}) // 10^-9 s (nanoseconds)
	writePCAPNGOptionLE(&idb, optEndOfOpt, nil)
	writePCAPNGBlockLE(&buf, BlockTypeInterfaceDesc, idb.Bytes())

	if _, err := w.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return &PCAPNGWriter{
		w:        w,
		linkType: linkType,
		snapLen:  snapLen,
	}, nil
}

// WriteDecryptionSecrets writes a PcapNG Decryption Secrets Block (DSB), such
// as [SecretsTypeTLSKeyLog] or [SecretsTypeWireGuardKeyLog].
func (pw *PCAPNGWriter) WriteDecryptionSecrets(secretsType uint32, secretData []byte) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	if len(secretData) > MaxDecryptionSecretBytes {
		return fmt.Errorf("%w: secret payload %d exceeds %d", ErrSecretLimit, len(secretData), MaxDecryptionSecretBytes)
	}
	var body bytes.Buffer
	var fixed [8]byte
	binary.LittleEndian.PutUint32(fixed[0:4], secretsType)
	binary.LittleEndian.PutUint32(fixed[4:8], uint32(len(secretData)))
	body.Write(fixed[:])
	body.Write(secretData)
	if rem := len(secretData) % 4; rem != 0 {
		body.Write(make([]byte, 4-rem))
	}
	var block bytes.Buffer
	writePCAPNGBlockLE(&block, BlockTypeDecryptionSecrets, body.Bytes())
	_, err := pw.w.Write(block.Bytes())
	return err
}

// WritePacket writes an Enhanced Packet Block (EPB) with nanosecond timestamp
// resolution and any process/thread attribution present on pkt.
func (pw *PCAPNGWriter) WritePacket(pkt PacketRecord, payload []byte) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	if len(payload) > MaxSnapLen {
		return fmt.Errorf("%w: packet payload %d exceeds %d", ErrInvalidPacket, len(payload), MaxSnapLen)
	}
	capLen := uint32(len(payload))
	origLen := pkt.OriginalLen
	if origLen < capLen {
		origLen = capLen
	}
	var ts uint64
	if pkt.TimestampNs > 0 {
		ts = uint64(pkt.TimestampNs)
	}

	var body bytes.Buffer
	var fixed [20]byte
	binary.LittleEndian.PutUint32(fixed[0:4], pkt.InterfaceID)
	binary.LittleEndian.PutUint32(fixed[4:8], uint32(ts>>32))
	binary.LittleEndian.PutUint32(fixed[8:12], uint32(ts&0xffffffff))
	binary.LittleEndian.PutUint32(fixed[12:16], capLen)
	binary.LittleEndian.PutUint32(fixed[16:20], origLen)
	body.Write(fixed[:])
	body.Write(payload)
	if rem := len(payload) % 4; rem != 0 {
		body.Write(make([]byte, 4-rem))
	}

	hasOpts := false
	if pkt.Flags != 0 {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], pkt.Flags)
		writePCAPNGOptionLE(&body, optEPBFlags, b[:])
		hasOpts = true
	}
	if pkt.DropCount != 0 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], pkt.DropCount)
		writePCAPNGOptionLE(&body, optEPBDropCount, b[:])
		hasOpts = true
	}
	if pkt.HasProcessID {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], pkt.ProcessID)
		writePCAPNGOptionLE(&body, optEPBProcessID, b[:])
		hasOpts = true
	}
	if pkt.HasThreadID {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], pkt.ThreadID)
		writePCAPNGOptionLE(&body, optEPBThreadID, b[:])
		hasOpts = true
	}
	if hasOpts {
		writePCAPNGOptionLE(&body, optEndOfOpt, nil)
	}

	var block bytes.Buffer
	writePCAPNGBlockLE(&block, BlockTypeEnhancedPacket, body.Bytes())
	_, err := pw.w.Write(block.Bytes())
	return err
}

func writePCAPNGBlockLE(buf *bytes.Buffer, blockType uint32, body []byte) {
	paddedLen := len(body)
	if rem := paddedLen % 4; rem != 0 {
		paddedLen += 4 - rem
	}
	totalLen := uint32(12 + paddedLen)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], blockType)
	binary.LittleEndian.PutUint32(hdr[4:8], totalLen)
	buf.Write(hdr[:])
	buf.Write(body)
	if pad := paddedLen - len(body); pad > 0 {
		buf.Write(make([]byte, pad))
	}
	binary.LittleEndian.PutUint32(hdr[0:4], totalLen)
	buf.Write(hdr[0:4])
}

func writePCAPNGOptionLE(buf *bytes.Buffer, code uint16, val []byte) {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], code)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
	buf.Write(hdr[:])
	buf.Write(val)
	if rem := len(val) % 4; rem != 0 {
		buf.Write(make([]byte, 4-rem))
	}
}
