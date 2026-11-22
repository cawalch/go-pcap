//go:build !linux && !darwin

package pcap

import (
	"errors"
	"testing"
)

func TestLiveStatsUnsupported(t *testing.T) {
	if _, err := new(LiveCapture).Stats(); !errors.Is(err, ErrLiveCaptureUnsupported) {
		t.Fatalf("Stats() error = %v, want ErrLiveCaptureUnsupported", err)
	}
}
