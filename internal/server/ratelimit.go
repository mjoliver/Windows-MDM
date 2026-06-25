package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a minimal per-client fixed-window limiter used to throttle
// sensitive unauthenticated endpoints (login, emergency access). It is
// dependency-free and bounds its own memory by evicting expired windows.
type rateLimiter struct {
	mu        sync.Mutex
	windows   map[string]*window
	limit     int
	window    time.Duration
	lastSweep time.Time
}

type window struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(limit int, per time.Duration) *rateLimiter {
	return &rateLimiter{
		windows:   make(map[string]*window),
		limit:     limit,
		window:    per,
		lastSweep: time.Now(),
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastSweep) > rl.window {
		rl.lastSweep = now
		for k, w := range rl.windows {
			if now.After(w.resetAt) {
				delete(rl.windows, k)
			}
		}
	}

	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		rl.windows[key] = &window{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if w.count >= rl.limit {
		return false
	}
	w.count++
	return true
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			respondJSON(w, http.StatusTooManyRequests, `{"error":"rate limit exceeded"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	// RealIP middleware already normalises RemoteAddr to the client IP.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
