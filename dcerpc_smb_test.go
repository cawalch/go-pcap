package pcap

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestDCERPCSMB2Capture(t *testing.T) {
	raw := smbRPCFixture(445)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.DCERPC(raw)
	if err != nil {
		t.Fatal(err)
	}
	at, err := c.DCERPCFromReaderAt(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(rows, at) {
		t.Fatalf("ReaderAt parity: %v, %v", at, err)
	}
	packets, err := c.Packets(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		packet  int
		command uint16
		opnum   uint16
		server  bool
	}{
		{2, 9, 42, false},
		{2, 9, 43, false},
		{5, 8, 44, true},
		{6, 8, 45, true},
		{7, 11, 46, false},
		{8, 11, 47, true},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		got := rows[i]
		source, destination := uint16(50100), uint16(445)
		if w.server {
			source, destination = destination, source
		}
		if got.PacketIndex != w.packet || got.TimestampNs != packets[w.packet].TimestampNs || got.FlowIndex != 0 ||
			got.Source.Port() != source || got.Destination.Port() != destination ||
			got.SMB2Command != w.command || got.Message.Opnum != w.opnum {
			t.Fatalf("record %d: %+v, want %+v", i, got, w)
		}
	}
}

func TestDCERPCSMB2NetBIOSSession(t *testing.T) {
	raw := smbRPCFixture(139)
	c, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.DCERPC(raw)
	if err != nil || len(rows) != 6 || rows[0].Destination.Port() != 139 {
		t.Fatalf("got %v, %v", rows, err)
	}
}

func TestDCERPCSMB2RejectsUnattributedAndUnboundedBuffers(t *testing.T) {
	le := binary.LittleEndian
	const pipe, disk, absent = 17, 18, 19
	const requestID, pendingID = 5, 100
	rpc := smbRPCFixturePDU(42)
	c := smbRPCFixtureTCP{port: 445}

	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(pipe, 2)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(disk, 1)))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(disk, rpc)))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(absent, rpc)))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(pipe, append([]byte("prefix"), rpc...))))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(pipe, rpc[:len(rpc)-1])))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(pipe, rpc[len(rpc)-1:])))

	// The first compound command's WRITE cannot read into the next header.
	bad := smbRPCFixtureWrite(pipe, rpc[:16])
	le.PutUint32(bad[20:24], uint32(len(bad)))
	le.PutUint32(bad[68:72], uint32(len(rpc)))
	c.add(false, smbRPCFixtureFrame(append(bad, smbRPCFixtureCommand(0, 0, 0, 0, pipe, rpc)...)))
	wrongControl := smbRPCFixtureIOCTL(false, rpc)
	le.PutUint32(wrongControl[68:72], 0x00110018)
	c.add(false, smbRPCFixtureFrame(wrongControl))
	outOfRange := smbRPCFixtureIOCTL(false, rpc)
	le.PutUint32(outOfRange[88:92], ^uint32(0))
	c.add(false, smbRPCFixtureFrame(outOfRange))

	c.add(false, smbRPCFixtureFrame(smbRPCFixtureReadRequest(pipe, requestID)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureCommand(8, 3, 0x103, requestID, pendingID, nil)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureReadResponse(3, requestID+1, pendingID, rpc)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureReadResponse(3, requestID, pendingID+1, rpc)))
	disconnect := []byte{4, 0, 0, 0}
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureCommand(4, 1, 0, 0, pipe, disconnect)))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(pipe, rpc)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(pipe, 2)))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureReadRequest(pipe, requestID+2)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureCommand(2, 1, 0, 0, 0, disconnect)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(pipe, 2)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureReadResponse(3, requestID+2, pendingID, rpc)))

	// Start another TCP opening with the same ports, session ID, and tree ID.
	c.clientSeq += 100
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	c.frames = append(c.frames, buildEthernetIPv4TCPFrame(src, dst, 50100, c.port, c.clientSeq, 0, TCPFlagSYN, nil))
	c.clientSeq++
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureWrite(pipe, rpc)))
	raw := c.capture()
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := capture.DCERPC(raw)
	if err != nil || len(rows) != 0 {
		t.Fatalf("unexpected DCE/RPC evidence: %v, %v", rows, err)
	}
}

func TestDCERPCSMB2RelatedCompound(t *testing.T) {
	first := smbRPCFixtureWrite(17, smbRPCFixturePDU(42))
	bind := dcerpcTestPacket(binary.LittleEndian, DCERPCBind, 3, dcerpcTestBindBody(binary.LittleEndian, 1))
	second := smbRPCFixtureWrite(uint64(^uint32(0)), bind)
	le := binary.LittleEndian
	le.PutUint32(first[20:24], uint32(len(first)))
	le.PutUint32(second[16:20], 4)
	le.PutUint64(second[40:48], ^uint64(0))
	c := smbRPCFixtureTCP{port: 445}
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(17, 2)))
	c.add(false, smbRPCFixtureFrame(append(first, second...)))
	raw := c.capture()
	capture, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := capture.DCERPC(raw)
	if err != nil || len(rows) != 2 || rows[0].Message.Opnum != 42 || rows[1].Message.PacketType != DCERPCBind {
		t.Fatalf("got %v, %v", rows, err)
	}
	contexts := rows[1].Message.Contexts
	if len(contexts) != 1 || contexts[0].AbstractSyntaxUUID != "11223344-5566-7788-99aa-bbccddeeff00" {
		t.Fatalf("got %v, %v", rows, err)
	}
}

func BenchmarkDCERPCSMB2Capture(b *testing.B) {
	raw := smbRPCFixture(445)
	c, err := New(raw)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(raw)
	b.Run("slice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if rows, err := c.DCERPC(raw); err != nil || len(rows) != 6 {
				b.Fatalf("got %d records, %v", len(rows), err)
			}
		}
	})
	b.Run("reader", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if rows, err := c.DCERPCFromReaderAt(r); err != nil || len(rows) != 6 {
				b.Fatalf("got %d records, %v", len(rows), err)
			}
		}
	})
}

func smbRPCFixture(port uint16) []byte {
	const tree, id, asyncID = 17, 3, 125
	c := smbRPCFixtureTCP{port: port}
	if port == 139 {
		name := append([]byte{32}, bytes.Repeat([]byte{'A'}, 32)...)
		name = append(name, 0)
		names := append(bytes.Clone(name), name...)
		c.add(false, append([]byte{0x81, 0, 0, byte(len(names))}, names...))
		c.add(true, []byte{0x82, 0, 0, 0})
	}
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureTree(tree, 2)))
	rpc := append(smbRPCFixturePDU(42), smbRPCFixturePDU(43)...)
	write := smbRPCFixtureFrame(smbRPCFixtureWrite(tree, rpc))
	c.add(false, write[:116])
	c.add(false, write[116:])
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureReadRequest(tree, id)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureCommand(8, 3, 0x103, id, asyncID, nil)))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureReadResponse(3, id, asyncID, smbRPCFixturePDU(44))))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureReadResponse(1, id+1, tree, smbRPCFixturePDU(45))))
	c.add(false, smbRPCFixtureFrame(smbRPCFixtureIOCTL(false, smbRPCFixturePDU(46))))
	c.add(true, smbRPCFixtureFrame(smbRPCFixtureIOCTL(true, smbRPCFixturePDU(47))))
	return c.capture()
}

func smbRPCFixturePDU(opnum uint16) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[6:8], opnum)
	return dcerpcTestPacket(binary.LittleEndian, DCERPCRequest, 3, body)
}

func smbRPCFixtureCommand(cmd uint16, flags, status uint32, id, treeOrAsync uint64, body []byte) []byte {
	le := binary.LittleEndian
	buf := make([]byte, 64, 64+len(body))
	copy(buf, "\xfeSMB")
	le.PutUint16(buf[4:6], 64)
	le.PutUint32(buf[8:12], status)
	le.PutUint16(buf[12:14], cmd)
	le.PutUint32(buf[16:20], flags)
	le.PutUint64(buf[24:32], id)
	if flags&2 != 0 {
		le.PutUint64(buf[32:40], treeOrAsync)
	} else {
		le.PutUint32(buf[36:40], uint32(treeOrAsync))
	}
	le.PutUint64(buf[40:48], 1)
	return append(buf, body...)
}

func smbRPCFixtureFrame(cmd []byte) []byte {
	return append([]byte{0, byte(len(cmd) >> 16), byte(len(cmd) >> 8), byte(len(cmd))}, cmd...)
}

func smbRPCFixtureTree(tree uint64, share byte) []byte {
	body := make([]byte, 16)
	body[0], body[2] = 16, share
	return smbRPCFixtureCommand(3, 1, 0, 1, tree, body)
}

func smbRPCFixtureWrite(tree uint64, rpc []byte) []byte {
	body := make([]byte, 48, 48+len(rpc))
	body[0], body[2] = 49, 112
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(rpc)))
	return smbRPCFixtureCommand(9, 0, 0, 2, tree, append(body, rpc...))
}

func smbRPCFixtureReadRequest(tree, id uint64) []byte {
	body := make([]byte, 48)
	body[0] = 49
	return smbRPCFixtureCommand(8, 0, 0, id, tree, body)
}

func smbRPCFixtureReadResponse(flags uint32, id, treeOrAsync uint64, rpc []byte) []byte {
	body := make([]byte, 16, 16+len(rpc))
	body[0], body[2] = 17, 80
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(rpc)))
	return smbRPCFixtureCommand(8, flags, 0, id, treeOrAsync, append(body, rpc...))
}

func smbRPCFixtureIOCTL(response bool, rpc []byte) []byte {
	le := binary.LittleEndian
	if response {
		body := make([]byte, 48, 48+len(rpc))
		body[0] = 49
		le.PutUint32(body[4:8], 0x0011c017)
		le.PutUint32(body[32:36], 112)
		le.PutUint32(body[36:40], uint32(len(rpc)))
		return smbRPCFixtureCommand(11, 1, 0x80000005, 12, 91, append(body, rpc...))
	}
	body := make([]byte, 56, 56+len(rpc))
	body[0] = 57
	le.PutUint32(body[4:8], 0x0011c017)
	le.PutUint32(body[24:28], 120)
	le.PutUint32(body[28:32], uint32(len(rpc)))
	le.PutUint32(body[48:52], 1)
	return smbRPCFixtureCommand(11, 0, 0, 12, 91, append(body, rpc...))
}

type smbRPCFixtureTCP struct {
	port                 uint16
	clientSeq, serverSeq uint32
	frames               [][]byte
}

func (c *smbRPCFixtureTCP) add(server bool, payload []byte) {
	src, dst := [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}
	if server {
		c.frames = append(c.frames, buildEthernetIPv4TCPFrame(dst, src, c.port, 50100, c.serverSeq, 0, TCPFlagACK, payload))
		c.serverSeq += uint32(len(payload))
	} else {
		c.frames = append(c.frames, buildEthernetIPv4TCPFrame(src, dst, 50100, c.port, c.clientSeq, 0, TCPFlagACK, payload))
		c.clientSeq += uint32(len(payload))
	}
}

func (c *smbRPCFixtureTCP) capture() []byte {
	return buildClassicPCAP(binary.LittleEndian, false, LinkTypeEthernet, 65535, c.frames)
}
