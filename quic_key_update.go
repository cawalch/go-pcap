package pcap

import "fmt"

// MaxQUICKeyUpdates bounds the number of authenticated transitions per sender.
const MaxQUICKeyUpdates = 32

// QUIC1RTTKeyTracker authenticates one sender's short-header packets across
// application key updates. A tracker retains the current, next and immediately
// previous payload keys. Use one tracker per sender and call it in capture
// order. Callers synchronize concurrent access to the same tracker.
type QUIC1RTTKeyTracker struct {
	headerDecoder               *QUIC1RTTDecoder
	version                     uint32
	suite                       uint16
	current, next, previous     quicPacketKeys
	nextSecret                  []byte
	generation                  uint8
	first, highest              uint64
	highestPrevious, priorFence uint64
}

// NewQUIC1RTTKeyTracker starts at key generation zero using the same supported
// QUIC versions, AES-GCM suites and traffic secret inputs as [NewQUIC1RTTDecoder].
func NewQUIC1RTTKeyTracker(version uint32, cipherSuite uint16, trafficSecret []byte) (*QUIC1RTTKeyTracker, error) {
	decoder, err := NewQUIC1RTTDecoder(version, cipherSuite, trafficSecret)
	if err != nil {
		return nil, err
	}
	t := &QUIC1RTTKeyTracker{
		headerDecoder: decoder, version: version, suite: cipherSuite,
		current: decoder.keys, first: quicPacketNumberLimit,
	}
	t.nextSecret, t.next, err = t.deriveNext(trafficSecret)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Open returns the authenticated packet number, key generation and owned
// frame bytes. Supply the same destination CID and expected packet number as
// [QUIC1RTTDecoder.Open]. A failed authentication leaves the last observed
// generation usable. If an update was missed, the generation can remain
// unknown and Open returns an error matching [ErrInvalidQUIC]. An authenticated
// transition above [MaxQUICKeyUpdates] returns [ErrQUICLimit].
func (t *QUIC1RTTKeyTracker) Open(packet, dcid []byte, expected uint64) (uint64, uint8, []byte, error) {
	if t == nil || t.headerDecoder == nil {
		return 0, 0, nil, ErrInvalidQUIC
	}
	pn, generation, payload, err := t.headerDecoder.open(packet, dcid, expected, t)
	if err != nil {
		return 0, 0, nil, err
	}
	if err := t.accept(pn, generation); err != nil {
		return 0, 0, nil, err
	}
	return pn, generation, payload, nil
}

func (t *QUIC1RTTKeyTracker) selectKeys(pn uint64, phase uint8) (quicPacketKeys, uint8) {
	if phase == t.generation&1 {
		if t.generation > 0 && pn <= t.highestPrevious {
			return quicPacketKeys{}, 0
		}
		return t.current, t.generation
	}
	if t.generation > 0 && pn < t.first {
		if t.generation > 1 && pn <= t.priorFence {
			return quicPacketKeys{}, 0
		}
		return t.previous, t.generation - 1
	}
	if pn > t.highest {
		return t.next, t.generation + 1
	}
	return quicPacketKeys{}, 0
}

func (t *QUIC1RTTKeyTracker) accept(pn uint64, generation uint8) error {
	switch {
	case generation < t.generation:
		t.highestPrevious = max(t.highestPrevious, pn)
	case generation == t.generation:
		t.first = min(t.first, pn)
		t.highest = max(t.highest, pn)
	default:
		if generation > MaxQUICKeyUpdates {
			return fmt.Errorf("%w: too many QUIC 1-RTT key updates", ErrQUICLimit)
		}
		nextSecret, next, err := t.deriveNext(t.nextSecret)
		if err != nil {
			return err
		}
		t.previous, t.current, t.next = t.current, t.next, next
		t.headerDecoder.keys = t.current
		t.nextSecret = nextSecret
		t.priorFence, t.highestPrevious = t.highestPrevious, t.highest
		t.first, t.highest, t.generation = pn, pn, generation
	}
	return nil
}

func (t *QUIC1RTTKeyTracker) deriveNext(secret []byte) ([]byte, quicPacketKeys, error) {
	hashFn, keyLen := tls13SuiteParams(t.suite)
	label := "quic ku"
	if t.version == QUICVersion2 {
		label = "quicv2 ku"
	}
	next, err := tls13ExpandLabelHash(hashFn, secret, label, nil, hashFn().Size())
	if err != nil {
		return nil, quicPacketKeys{}, err
	}
	keys, err := deriveQUICPacketKeys(next, t.version, hashFn, keyLen)
	// Header protection uses the original header protection key throughout
	// application key updates. Only payload protection changes.
	keys.hp = t.headerDecoder.keys.hp
	return next, keys, err
}
