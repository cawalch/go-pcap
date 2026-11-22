//go:build linux || darwin

package pcap

import (
	"errors"
	"os"
)

// Stats returns kernel receive and buffer-drop totals since OpenLive.
// Poll before either native 32-bit counter advances by 2^32 packets.
// Stats calls can run concurrently with each other and with ReadPacket.
func (lc *LiveCapture) Stats() (LiveStats, error) {
	if lc == nil || lc.file == nil || lc.buf == nil {
		return LiveStats{}, ErrInvalidHeader
	}
	lc.statsMu.Lock()
	defer lc.statsMu.Unlock()
	if lc.closed {
		return LiveStats{}, ErrInvalidHeader
	}
	rawConn, err := lc.file.SyscallConn()
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return LiveStats{}, ErrInvalidHeader
		}
		return LiveStats{}, err
	}
	var delta LiveStats
	var deltaErr error
	if err := rawConn.Control(func(fd uintptr) {
		delta, deltaErr = lc.statsDelta(int(fd))
	}); err != nil {
		if lc.closed || errors.Is(err, os.ErrClosed) {
			return LiveStats{}, ErrInvalidHeader
		}
		return LiveStats{}, err
	}
	if deltaErr != nil {
		return LiveStats{}, deltaErr
	}
	lc.stats.PacketsReceived += delta.PacketsReceived
	lc.stats.PacketsDropped += delta.PacketsDropped
	return lc.stats, nil
}

// Close closes the underlying live capture descriptor and unblocks any
// concurrent ReadPacket call.
func (lc *LiveCapture) Close() error {
	if lc == nil || lc.file == nil {
		return nil
	}
	lc.statsMu.Lock()
	if lc.closed {
		lc.statsMu.Unlock()
		return nil
	}
	lc.closed = true
	lc.statsMu.Unlock()

	err := lc.file.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
