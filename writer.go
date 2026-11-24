package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// PCAPNGWriterOptions configures container and interface metadata written by
// [NewPCAPNGWriter].
type PCAPNGWriterOptions struct {
	LinkType LinkType
	// LinkTypeSet preserves LinkType verbatim in [NewPCAPNGWriter], including
	// [LinkTypeNull] (0), instead of defaulting a zero LinkType to [LinkTypeEthernet].
	LinkTypeSet          bool
	SnapLen              uint32
	InterfaceName        string
	InterfaceDescription string
	Hardware             string
	OS                   string
	UserApplication      string
}

// PCAPNGWriter writes PcapNG blocks to an [io.Writer].
type PCAPNGWriter struct {
	captureOutput
	interfaceSnapLens []uint32
	processIndices    map[ProcessEvent]uint32
}

// NewPCAPNGWriter writes a PcapNG Section Header Block (SHB) and Interface
// Description Block (IDB, interface ID 0 with nanosecond timestamp resolution)
// to w and returns a [PCAPNGWriter]. When LinkTypeSet is false, a zero LinkType
// defaults to [LinkTypeEthernet] unless InterfaceName is "lo0". Set LinkTypeSet
// to true to preserve [LinkTypeNull] on interface 0 for any interface name. A
// zero SnapLen defaults to [DefaultLiveSnapLen].
func NewPCAPNGWriter(w io.Writer, opts PCAPNGWriterOptions) (*PCAPNGWriter, error) {
	if !opts.LinkTypeSet && opts.LinkType == 0 && opts.InterfaceName != "lo0" {
		opts.LinkType = LinkTypeEthernet
	}
	if opts.SnapLen == 0 {
		opts.SnapLen = DefaultLiveSnapLen
	}
	return newPCAPNGWriter(w, opts)
}

// newPCAPNGWriter accepts the exact link type and snaplen, including zero.
func newPCAPNGWriter(w io.Writer, opts PCAPNGWriterOptions) (*PCAPNGWriter, error) {
	if w == nil {
		return nil, fmt.Errorf("%w: nil writer", ErrInvalidHeader)
	}
	if len(opts.Hardware) > MaxOptionStringBytes || len(opts.OS) > MaxOptionStringBytes || len(opts.UserApplication) > MaxOptionStringBytes {
		return nil, ErrOptionLimit
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
	if opts.Hardware != "" {
		writePCAPNGOptionLE(&shb, optSHBHardware, []byte(opts.Hardware))
	}
	if opts.OS != "" {
		writePCAPNGOptionLE(&shb, optSHBOS, []byte(opts.OS))
	}
	if opts.UserApplication != "" {
		writePCAPNGOptionLE(&shb, optSHBUserAppl, []byte(opts.UserApplication))
	}
	if shb.Len() > len(shbFixed) {
		writePCAPNGOptionLE(&shb, optEndOfOpt, nil)
	}
	writePCAPNGBlockLE(&buf, BlockTypeSectionHeader, shb.Bytes())

	if err := appendInterfaceBlock(&buf, opts); err != nil {
		return nil, err
	}
	pw := &PCAPNGWriter{
		captureOutput:     captureOutput{w: w},
		interfaceSnapLens: []uint32{opts.SnapLen},
	}
	if err := pw.write(buf.Bytes()); err != nil {
		return nil, err
	}
	return pw, nil
}

// AddInterface writes an Interface Description Block and returns its section-local ID.
// LinkType is used verbatim, including [LinkTypeNull]. SnapLen defaults to
// [DefaultLiveSnapLen]. Hardware, OS and UserApplication are section options.
func (pw *PCAPNGWriter) AddInterface(opts PCAPNGWriterOptions) (uint32, error) {
	if pw == nil || pw.w == nil {
		return 0, ErrInvalidHeader
	}
	if len(pw.interfaceSnapLens) >= MaxInterfaces {
		return 0, ErrInterfaceLimit
	}
	if opts.SnapLen == 0 {
		opts.SnapLen = DefaultLiveSnapLen
	}
	var buf bytes.Buffer
	if err := appendInterfaceBlock(&buf, opts); err != nil {
		return 0, err
	}
	if err := pw.write(buf.Bytes()); err != nil {
		return 0, err
	}
	id := uint32(len(pw.interfaceSnapLens))
	pw.interfaceSnapLens = append(pw.interfaceSnapLens, opts.SnapLen)
	return id, nil
}

func appendInterfaceBlock(buf *bytes.Buffer, opts PCAPNGWriterOptions) error {
	if len(opts.InterfaceName) > MaxOptionStringBytes || len(opts.InterfaceDescription) > MaxOptionStringBytes {
		return ErrOptionLimit
	}
	snapLen := opts.SnapLen
	if snapLen > MaxSnapLen {
		return ErrInvalidHeader
	}
	var idb bytes.Buffer
	var idbFixed [8]byte
	binary.LittleEndian.PutUint16(idbFixed[0:2], uint16(opts.LinkType))
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
	writePCAPNGBlockLE(buf, BlockTypeInterfaceDesc, idb.Bytes())
	return nil
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
	return pw.write(block.Bytes())
}

// WritePacket writes an Enhanced Packet Block (EPB) with nanosecond timestamp
// resolution. A process ID or name uses a Darwin Process Event Block shared
// by packets with the same attribution. ID 0xffffffff is reserved for entries
// with no process ID. Other attribution fields use go-pcap packet comments.
// More than [MaxProcessEvents] distinct process entries returns [ErrOptionLimit]
// before writing the packet.
func (pw *PCAPNGWriter) WritePacket(pkt PacketRecord, payload []byte) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	if uint64(pkt.InterfaceID) >= uint64(len(pw.interfaceSnapLens)) {
		return fmt.Errorf("%w: undeclared interface %d", ErrInvalidPacket, pkt.InterfaceID)
	}
	if pkt.TimestampNs < 0 {
		return fmt.Errorf("%w: negative timestamp %d", ErrInvalidPacket, pkt.TimestampNs)
	}
	if len(payload) > MaxSnapLen {
		return fmt.Errorf("%w: packet payload %d exceeds %d", ErrInvalidPacket, len(payload), MaxSnapLen)
	}
	if len(pkt.ProcessName) > MaxOptionStringBytes || len(pkt.ProcessArgs) > MaxOptionStringBytes || len(pkt.ContainerID) > MaxOptionStringBytes {
		return ErrOptionLimit
	}
	if pkt.HasProcessID && pkt.ProcessID == math.MaxUint32 {
		return fmt.Errorf("%w: process ID %#x is reserved", ErrInvalidPacket, pkt.ProcessID)
	}
	origLen := pkt.OriginalLen
	if origLen < uint32(len(payload)) {
		origLen = uint32(len(payload))
	}
	snapLen := pw.interfaceSnapLens[pkt.InterfaceID]
	if snapLen > 0 && uint32(len(payload)) > snapLen {
		payload = payload[:snapLen]
	}
	capLen := uint32(len(payload))
	ts := uint64(pkt.TimestampNs)

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

	optionsStart := body.Len()
	if pkt.Flags != 0 {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], pkt.Flags)
		writePCAPNGOptionLE(&body, optEPBFlags, b[:])
	}
	if pkt.DropCount != 0 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], pkt.DropCount)
		writePCAPNGOptionLE(&body, optEPBDropCount, b[:])
	}
	var block bytes.Buffer
	var process ProcessEvent
	var processIndex uint32
	var newProcess bool
	if pkt.HasProcessID || pkt.ProcessName != "" {
		process = ProcessEvent{ProcessID: pkt.ProcessID, ProcessName: pkt.ProcessName}
		if !pkt.HasProcessID {
			process.ProcessID = math.MaxUint32
		}
		var exists bool
		processIndex, exists = pw.processIndices[process]
		if !exists {
			processIndex = uint32(len(pw.processIndices))
			if processIndex >= MaxProcessEvents {
				return fmt.Errorf("%w: DPEB count exceeds %d", ErrOptionLimit, MaxProcessEvents)
			}
			var processBody bytes.Buffer
			var id [4]byte
			binary.LittleEndian.PutUint32(id[:], process.ProcessID)
			processBody.Write(id[:])
			if process.ProcessName != "" {
				writePCAPNGOptionLE(&processBody, optDPEBProcessName, []byte(process.ProcessName))
				writePCAPNGOptionLE(&processBody, optEndOfOpt, nil)
			}
			writePCAPNGBlockLE(&block, BlockTypeDarwinProcessEvent, processBody.Bytes())
			newProcess = true
		}
		var index [4]byte
		binary.LittleEndian.PutUint32(index[:], processIndex)
		writePCAPNGOptionLE(&body, optEPBDarwinProcessIndex, index[:])
	}
	if pkt.HasThreadID {
		writeProcessCommentLE(&body, processCommentThread, strconv.FormatUint(uint64(pkt.ThreadID), 10))
	}
	if pkt.ProcessArgs != "" {
		writeProcessCommentLE(&body, processCommentArgs, pkt.ProcessArgs)
	}
	if pkt.HasUserID {
		writeProcessCommentLE(&body, processCommentUser, strconv.FormatUint(uint64(pkt.UserID), 10))
	}
	if pkt.ContainerID != "" {
		writeProcessCommentLE(&body, processCommentContainer, pkt.ContainerID)
	}
	if body.Len() > optionsStart {
		writePCAPNGOptionLE(&body, optEndOfOpt, nil)
	}

	writePCAPNGBlockLE(&block, BlockTypeEnhancedPacket, body.Bytes())
	if err := pw.write(block.Bytes()); err != nil {
		return err
	}
	if newProcess {
		if pw.processIndices == nil {
			pw.processIndices = make(map[ProcessEvent]uint32)
		}
		pw.processIndices[process] = processIndex
	}
	return nil
}

func writeProcessCommentLE(body *bytes.Buffer, prefix, value string) {
	// When a value fills the option budget itself, retain it across two
	// consecutive comments without splitting a UTF-8 code point.
	n := MaxOptionStringBytes - len(prefix)
	if len(value) > n {
		for limit := n - utf8.UTFMax + 1; n > limit && !utf8.RuneStart(value[n]); n-- {
		}
		writePCAPNGOptionLE(body, optComment, []byte(prefix+value[:n]))
		value = value[n:]
	}
	writePCAPNGOptionLE(body, optComment, []byte(prefix+value))
}

// WriteNameResolution writes a PcapNG Name Resolution Block (NRB) containing
// IPv4 and IPv6 hostname mappings, with at most [MaxNamesPerRecord] names
// per record.
func (pw *PCAPNGWriter) WriteNameResolution(records []NameResolutionRecord) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	if len(records) > MaxNameResolutionRecords {
		return fmt.Errorf("%w: NRB records exceed %d", ErrOptionLimit, MaxNameResolutionRecords)
	}
	var body bytes.Buffer
	for i := range records {
		rec := &records[i]
		if !rec.Addr.IsValid() || len(rec.Names) == 0 {
			continue
		}
		var val bytes.Buffer
		var recType uint16
		if rec.Addr.Is4() {
			recType = nrbRecordIPv4
			a4 := rec.Addr.As4()
			val.Write(a4[:])
		} else {
			recType = nrbRecordIPv6
			a16 := rec.Addr.As16()
			val.Write(a16[:])
		}
		wroteName := false
		names := 0
		for _, name := range rec.Names {
			if name == "" {
				continue
			}
			if len(name) > MaxOptionStringBytes-val.Len()-1 {
				return fmt.Errorf("%w: NRB record length exceeds %d", ErrOptionLimit, MaxOptionStringBytes)
			}
			for part := range strings.SplitSeq(name, "\x00") {
				if strings.TrimSpace(part) != "" {
					names++
				}
			}
			if names > MaxNamesPerRecord {
				return fmt.Errorf("%w: NRB record exceeds %d names", ErrOptionLimit, MaxNamesPerRecord)
			}
			val.WriteString(name)
			val.WriteByte(0)
			wroteName = true
		}
		if !wroteName {
			continue
		}
		writePCAPNGOptionLE(&body, recType, val.Bytes())
	}
	writePCAPNGOptionLE(&body, nrbRecordEnd, nil)

	var block bytes.Buffer
	writePCAPNGBlockLE(&block, BlockTypeNameResolution, body.Bytes())
	return pw.write(block.Bytes())
}

// WriteInterfaceStats writes a PcapNG Interface Statistics Block (ISB) with
// nanosecond timestamp resolution.
func (pw *PCAPNGWriter) WriteInterfaceStats(stat InterfaceStatistics) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	if uint64(stat.InterfaceID) >= uint64(len(pw.interfaceSnapLens)) {
		return fmt.Errorf("%w: undeclared interface %d", ErrInvalidBlock, stat.InterfaceID)
	}
	if stat.TimestampNs < 0 || (stat.HasStartTime && stat.StartTimeNs < 0) || (stat.HasEndTime && stat.EndTimeNs < 0) {
		return fmt.Errorf("%w: negative timestamp", ErrInvalidBlock)
	}
	var body bytes.Buffer
	var fixed [12]byte
	ts := uint64(stat.TimestampNs)
	binary.LittleEndian.PutUint32(fixed[0:4], stat.InterfaceID)
	binary.LittleEndian.PutUint32(fixed[4:8], uint32(ts>>32))
	binary.LittleEndian.PutUint32(fixed[8:12], uint32(ts&0xffffffff))
	body.Write(fixed[:])

	writeTSOpt := func(code uint16, ns int64) {
		u := uint64(ns)
		var b [8]byte
		binary.LittleEndian.PutUint32(b[0:4], uint32(u>>32))
		binary.LittleEndian.PutUint32(b[4:8], uint32(u&0xffffffff))
		writePCAPNGOptionLE(&body, code, b[:])
	}
	if stat.HasStartTime {
		writeTSOpt(optISBStartTime, stat.StartTimeNs)
	}
	if stat.HasEndTime {
		writeTSOpt(optISBEndTime, stat.EndTimeNs)
	}
	if stat.HasPacketsReceived {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], stat.PacketsReceived)
		writePCAPNGOptionLE(&body, optISBIfRecv, b[:])
	}
	if stat.HasPacketsDropped {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], stat.PacketsDropped)
		writePCAPNGOptionLE(&body, optISBIfDrop, b[:])
	}
	if body.Len() > len(fixed) {
		writePCAPNGOptionLE(&body, optEndOfOpt, nil)
	}

	var block bytes.Buffer
	writePCAPNGBlockLE(&block, BlockTypeInterfaceStats, body.Bytes())
	return pw.write(block.Bytes())
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
	writePCAPNGOption(buf, binary.LittleEndian, code, val)
}

func writePCAPNGOption(buf *bytes.Buffer, order binary.ByteOrder, code uint16, val []byte) {
	var hdr [4]byte
	order.PutUint16(hdr[0:2], code)
	order.PutUint16(hdr[2:4], uint16(len(val)))
	buf.Write(hdr[:])
	buf.Write(val)
	if rem := len(val) % 4; rem != 0 {
		buf.Write(make([]byte, 4-rem))
	}
}

// captureOutput retains the first I/O failure: after a partial record the
// stream cannot safely accept further records.
type captureOutput struct {
	w   io.Writer
	err error
}

func (out *captureOutput) write(data []byte) error {
	if out.err == nil {
		var n int
		n, out.err = out.w.Write(data)
		if out.err == nil && n != len(data) {
			out.err = io.ErrShortWrite
		}
	}
	return out.err
}

// PCAPWriter writes classic little-endian PCAP records with nanosecond timestamps.
type PCAPWriter struct {
	captureOutput
	snapLen uint32
	header  [16]byte
}

// NewPCAPWriter writes the global PCAP header for linkType to w. A zero snapLen
// selects [DefaultLiveSnapLen].
func NewPCAPWriter(w io.Writer, linkType LinkType, snapLen uint32) (*PCAPWriter, error) {
	if w == nil || snapLen > MaxSnapLen {
		return nil, ErrInvalidHeader
	}
	if snapLen == 0 {
		snapLen = DefaultLiveSnapLen
	}
	pw := &PCAPWriter{captureOutput: captureOutput{w: w}, snapLen: snapLen}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[:4], PCAPMagicNanoLE)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))
	if err := pw.write(hdr[:]); err != nil {
		return nil, err
	}
	return pw, nil
}

// WritePacket writes one packet with timestampNs in Unix nanoseconds. It saves
// up to the configured snaplen and records the full payload length on the wire.
// The PCAP seconds and original-length fields must fit unsigned 32-bit values.
func (pw *PCAPWriter) WritePacket(timestampNs int64, payload []byte) error {
	return pw.WritePacketWithOriginalLen(timestampNs, payload, uint32(len(payload)))
}

// WritePacketWithOriginalLen writes captured bytes with their original wire
// length and timestamp in Unix nanoseconds. It saves up to the writer's snaplen.
// It returns [ErrInvalidPacket] if originalLen is smaller than len(payload)
// or the timestamp cannot be represented in classic PCAP.
func (pw *PCAPWriter) WritePacketWithOriginalLen(timestampNs int64, payload []byte, originalLen uint32) error {
	if pw == nil || pw.w == nil {
		return ErrInvalidHeader
	}
	sec := timestampNs / 1_000_000_000
	if timestampNs < 0 || sec > math.MaxUint32 || uint64(len(payload)) > uint64(originalLen) {
		return ErrInvalidPacket
	}
	n := min(uint32(len(payload)), pw.snapLen)
	binary.LittleEndian.PutUint32(pw.header[:4], uint32(sec))
	binary.LittleEndian.PutUint32(pw.header[4:8], uint32(timestampNs%1_000_000_000))
	binary.LittleEndian.PutUint32(pw.header[8:12], n)
	binary.LittleEndian.PutUint32(pw.header[12:16], originalLen)
	if err := pw.write(pw.header[:]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return pw.write(payload[:n])
}
