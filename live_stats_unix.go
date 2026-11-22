//go:build linux || darwin

package pcap

import "syscall"

// Stats returns kernel receive and buffer-drop totals since OpenLive.
// Poll before either native 32-bit counter advances by 2^32 packets.
// Stats calls can run concurrently with each other and with ReadPacket.
func (lc *LiveCapture) Stats() (LiveStats, error) {
	if lc == nil {
		return LiveStats{}, ErrInvalidHeader
	}
	lc.statsMu.Lock()
	defer lc.statsMu.Unlock()
	if lc.fd < 0 || lc.buf == nil {
		return LiveStats{}, ErrInvalidHeader
	}
	delta, err := lc.statsDelta()
	if err != nil {
		return LiveStats{}, err
	}
	lc.stats.PacketsReceived += delta.PacketsReceived
	lc.stats.PacketsDropped += delta.PacketsDropped
	return lc.stats, nil
}

// Close closes the underlying live capture descriptor.
func (lc *LiveCapture) Close() error {
	if lc == nil {
		return nil
	}
	lc.statsMu.Lock()
	defer lc.statsMu.Unlock()
	if lc.fd < 0 || lc.buf == nil {
		return nil
	}
	fd := lc.fd
	lc.fd = -1
	return syscall.Close(fd)
}
