package device

import (
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

func TestSleptSinceAwake(t *testing.T) {
	if slept := sleptSince(time.Now().Add(-time.Minute)); slept < -time.Second || slept > time.Second {
		t.Fatalf("sleptSince reported %v without any suspend", slept)
	}
}

// After a long suspend, the peer that stayed awake has dropped the session. The
// sleeper must handshake right after its first packet instead of sending with
// dead keys until the 15s "stopped hearing back" timer fires, whichever side
// started the session.
func TestRekeyRightAfterSuspend(t *testing.T) {
	t.Run("sleeper initiated", func(t *testing.T) { testRekeyRightAfterSuspend(t, Ping) })
	t.Run("sleeper responded", func(t *testing.T) { testRekeyRightAfterSuspend(t, Pong) })
}

// first picks who starts the session: pair[1] (the sleeper) for Ping, pair[0] for Pong.
func testRekeyRightAfterSuspend(t *testing.T, first SendDirection) {
	var wokeAt atomic.Pointer[time.Time]
	orig := sleptSince
	t.Cleanup(func() { sleptSince = orig }) // registered first, so it runs after the devices close
	sleptSince = func(at time.Time) time.Duration {
		if w := wokeAt.Load(); w != nil && at.Before(*w) {
			return time.Hour
		}
		return 0
	}

	pair := genTestPair(t, false)
	pair.Send(t, first, nil)

	awake, sleeper := pair[0].dev, pair[1].dev
	awake.LookupPeer(sleeper.staticIdentity.publicKey).ZeroAndFlushAll()
	time.Sleep(50 * time.Millisecond) // keep the old keys strictly before wake; Windows' clock is coarse
	now := time.Now()
	wokeAt.Store(&now)

	// The first packet still goes out on the old keys (lost here, like it would
	// be for real); it triggers the handshake. Send waits 6s for the next one,
	// well under the 15s it takes without suspend awareness.
	pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, pair[1].ip)
	time.Sleep(200 * time.Millisecond)
	pair.Send(t, Ping, nil)
}

// A forward clock step makes keys look old, but they still work: traffic must
// keep flowing on them even if the extra handshake never completes.
func TestClockStepKeepsTrafficFlowing(t *testing.T) {
	var steppedAt atomic.Pointer[time.Time]
	orig := sleptSince
	t.Cleanup(func() { sleptSince = orig })
	sleptSince = func(at time.Time) time.Duration {
		if s := steppedAt.Load(); s != nil && at.Before(*s) {
			return time.Hour
		}
		return 0
	}

	pair := genTestPair(t, false)
	pair.Send(t, Ping, nil)

	// The receiver gets a new identity, so the sender's handshakes fail, but
	// the session keys it already has still decrypt the sender's packets.
	newKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pair[0].dev.IpcSet(uapiCfg("private_key", hex.EncodeToString(newKey[:]))); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	now := time.Now()
	steppedAt.Store(&now)

	for i := 0; i < 5; i++ {
		pair.Send(t, Ping, nil)
	}
}
