package agent

import (
	"sync"
	"time"
)

// TokenBucket is a thread-safe token bucket rate limiter.
// It implements the RateLimiter interface expected by transport.ServerMux.
type TokenBucket struct {
	rate   float64 // tokens per second
	burst  float64 // maximum token capacity
	tokens float64 // current token count
	last   time.Time
	mu     sync.Mutex
}

// NewTokenBucket creates a TokenBucket with the given rate (tokens/sec) and
// burst (maximum tokens that can accumulate).
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst), // start full
		last:   time.Now(),
	}
}

// refill adds tokens based on elapsed time since the last refill.
// Must be called with mu held.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}
}

// Wait blocks until n tokens are available and consumes them.
// This satisfies the transport.RateLimiter interface.
func (tb *TokenBucket) Wait(n int) {
	for {
		tb.mu.Lock()
		tb.refill()
		if tb.tokens >= float64(n) {
			tb.tokens -= float64(n)
			tb.mu.Unlock()
			return
		}
		// Calculate how long to wait for enough tokens.
		needed := float64(n) - tb.tokens
		waitDur := time.Duration(needed/tb.rate*float64(time.Second)) + time.Millisecond
		tb.mu.Unlock()
		time.Sleep(waitDur)
	}
}

// Allow reports whether n tokens are available and consumes them if so.
// Returns false without blocking if insufficient tokens are available.
func (tb *TokenBucket) Allow(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}
