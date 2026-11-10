package server

import (
	"net/http"
	"sync"
	"time"
)

const (
	defaultSourceLimit      = 30
	defaultSourceWindow     = time.Minute
	defaultSourceMaxEntries = 4096
)

type sourceEntry struct {
	start time.Time
	last  time.Time
	count int
}

// sourceLimiter bounds authentication traffic per client source. It is a
// fixed-window counter with a hard entry cap: expired entries are swept before
// the map can grow without bound, and the oldest entry is evicted if a burst of
// distinct sources still fills it. That keeps anonymous traffic from consuming
// memory while leaving the account-wide limiter to bound password guessing.
type sourceLimiter struct {
	entries    map[string]sourceEntry
	limit      int
	window     time.Duration
	maxEntries int
	mu         sync.Mutex
}

func newSourceLimiter(limit int, window time.Duration, maxEntries int) *sourceLimiter {
	if limit <= 0 {
		limit = defaultSourceLimit
	}
	if window <= 0 {
		window = defaultSourceWindow
	}
	if maxEntries <= 0 {
		maxEntries = defaultSourceMaxEntries
	}
	return &sourceLimiter{
		entries:    map[string]sourceEntry{},
		limit:      limit,
		window:     window,
		maxEntries: maxEntries,
	}
}

func (l *sourceLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if key == "" {
		key = "unknown"
	}
	entry, exists := l.entries[key]
	if exists && now.Sub(entry.start) >= l.window {
		entry = sourceEntry{start: now}
		exists = false
	}
	if !exists {
		l.cleanupLocked(now)
		if len(l.entries) >= l.maxEntries {
			l.evictOldestLocked()
		}
		entry = sourceEntry{start: now}
	}
	if entry.count >= l.limit {
		entry.last = now
		l.entries[key] = entry
		return false
	}
	entry.count++
	entry.last = now
	l.entries[key] = entry
	return true
}

func (l *sourceLimiter) cleanupLocked(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.start) >= l.window {
			delete(l.entries, key)
		}
	}
}

func (l *sourceLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range l.entries {
		if oldestKey == "" || entry.last.Before(oldest) {
			oldestKey, oldest = key, entry.last
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}

// allowSourceAttempt applies the per-source limiter. It runs before the
// account-wide limiter and before Web.authMu, so a flood from one address
// cannot consume the administrator's ten attempts per minute.
func (w *Web) allowSourceAttempt(rw http.ResponseWriter, r *http.Request) bool {
	if w.sourceLimiter == nil {
		return true
	}
	var proxies []string
	if w.srv != nil {
		proxies = w.srv.cfg.TrustedProxies
	}
	if !w.sourceLimiter.allow(loginClientIP(r, proxies), w.nowTime()) {
		rw.Header().Set("Retry-After", "60")
		http.Error(rw, "请求过于频繁，请稍后重试", http.StatusTooManyRequests)
		return false
	}
	return true
}
