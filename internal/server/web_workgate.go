package server

import "net/http"

// Argon2id verification deliberately uses 64 MiB of memory per call. Moving it
// outside authMu keeps the authentication lock short, but would otherwise let a
// burst of requests allocate gigabytes. workGate caps how many expensive
// verifications run at once; a saturated gate rejects immediately instead of
// queueing, so it never becomes a lock or a body-read bottleneck.
const defaultPasswordWorkSlots = 2

type workGate struct {
	slots chan struct{}
}

func newWorkGate(capacity int) *workGate {
	if capacity < 1 {
		capacity = 1
	}
	return &workGate{slots: make(chan struct{}, capacity)}
}

// tryAcquire never blocks. It reports whether a slot was free.
func (g *workGate) tryAcquire() bool {
	if g == nil {
		return true
	}
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *workGate) release() {
	if g != nil {
		<-g.slots
	}
}

// acquirePasswordWork reserves a slot for one expensive password operation.
// Callers must not hold authMu when calling it and must release the returned
// function as soon as the hash/verify work finishes.
func (w *Web) acquirePasswordWork(rw http.ResponseWriter) (func(), bool) {
	if w == nil || w.passwordGate == nil {
		return func() {}, true
	}
	if !w.passwordGate.tryAcquire() {
		rw.Header().Set("Retry-After", "1")
		http.Error(rw, "验证请求过多，请稍后重试", http.StatusTooManyRequests)
		return nil, false
	}
	return w.passwordGate.release, true
}

// verifyPasswordGated runs Argon2 only when a work slot is available. The
// second return value is false when the caller should stop because a 429 (or
// another error) was already written.
func (w *Web) verifyPasswordGated(rw http.ResponseWriter, password, hash string) (bool, bool) {
	release, ok := w.acquirePasswordWork(rw)
	if !ok {
		return false, false
	}
	defer release()
	return verifyPassword(password, hash), true
}
