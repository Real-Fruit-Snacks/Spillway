//go:build agent

package agent

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_Allow(t *testing.T) {
	tb := NewTokenBucket(1000, 100)

	// Should allow up to burst.
	if !tb.Allow(50) {
		t.Error("expected Allow(50) to succeed")
	}
	if !tb.Allow(50) {
		t.Error("expected Allow(50) to succeed again")
	}
	// Should fail — no tokens left.
	if tb.Allow(1) {
		t.Error("expected Allow(1) to fail after burst exhausted")
	}
}

func TestTokenBucket_AllowPartial(t *testing.T) {
	tb := NewTokenBucket(1000, 10)
	if !tb.Allow(10) {
		t.Error("expected Allow(10) to succeed")
	}
	if tb.Allow(1) {
		t.Error("expected Allow(1) to fail")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	// Drain all tokens.
	tb.Allow(100)
	if tb.Allow(1) {
		t.Error("expected no tokens after drain")
	}

	// Wait for refill (1000 tokens/sec = 1 token/ms).
	time.Sleep(50 * time.Millisecond)

	// Should have ~50 tokens now.
	if !tb.Allow(10) {
		t.Error("expected tokens after refill")
	}
}

func TestTokenBucket_Wait(t *testing.T) {
	tb := NewTokenBucket(10000, 10)
	// Drain.
	tb.Allow(10)

	start := time.Now()
	tb.Wait(1) // Should block briefly until refill.
	elapsed := time.Since(start)

	// Should have waited some small amount of time (< 100ms at 10000 tokens/sec).
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took too long: %v", elapsed)
	}
}

func TestTokenBucket_WaitLarger(t *testing.T) {
	tb := NewTokenBucket(10000, 100)
	// Drain all.
	tb.Allow(100)

	start := time.Now()
	tb.Wait(10) // Need 10 tokens at 10000/sec = ~1ms
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait(10) took too long: %v", elapsed)
	}
}

func TestTokenBucket_BurstCapacity(t *testing.T) {
	tb := NewTokenBucket(100, 50)
	// Start full at 50 tokens.
	if !tb.Allow(50) {
		t.Error("expected full burst capacity")
	}
	if tb.Allow(1) {
		t.Error("expected empty after burst consumed")
	}
}

func TestTokenBucket_ConcurrentAccess(t *testing.T) {
	tb := NewTokenBucket(100000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				tb.Allow(1)
				tb.Wait(1)
			}
		}()
	}
	wg.Wait()
}
