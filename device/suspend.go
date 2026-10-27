package device

import "time"

// sleptSince reports how long the system has been suspended since t.
//
// time.Since uses Go's monotonic clock, which stops while the device is in
// deep sleep on Android (CLOCK_MONOTONIC) and iOS (mach_absolute_time), while
// the wall clock keeps running. The difference between the two is the time
// spent asleep. Where the monotonic clock keeps counting during sleep, this is
// zero, and so is the error it corrects. A wall clock stepped forward reads as
// sleep too; callers only use it to start handshakes early, never to stop
// using keys, so the cost is one extra handshake. A backward step is ignored
// by realSince.
//
// It is a variable so tests can simulate a suspend.
var sleptSince = func(t time.Time) time.Duration {
	now := time.Now()
	return now.Round(0).Sub(t.Round(0)) - now.Sub(t)
}

// realSince is time.Since plus any time the system spent suspended, so rekey
// decisions and handshake pacing match what a peer that stayed awake sees.
// Without it, a phone waking from a long sleep keeps sending with keys the
// other side has already expired, until the 15s "stopped hearing back" timer
// fires.
func realSince(t time.Time) time.Duration {
	elapsed := time.Since(t)
	if slept := sleptSince(t); slept > 0 {
		elapsed += slept
	}
	return elapsed
}
