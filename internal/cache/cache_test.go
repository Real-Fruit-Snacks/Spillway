package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

func TestGetStat_Hit(t *testing.T) {
	c := New(time.Minute, time.Minute)
	st := &protocol.FileStat{Name: "test", Size: 100}
	c.PutStat("/a", st)

	got, ok := c.GetStat("/a")
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Name != "test" || got.Size != 100 {
		t.Errorf("got %+v, want Name=test Size=100", got)
	}
}

func TestGetStat_Miss(t *testing.T) {
	c := New(time.Minute, time.Minute)
	_, ok := c.GetStat("/nonexistent")
	if ok {
		t.Error("expected miss")
	}
}

func TestGetStat_TTLExpiry(t *testing.T) {
	c := New(50*time.Millisecond, time.Minute)
	c.PutStat("/a", &protocol.FileStat{Name: "a"})

	// Should be a hit immediately.
	if _, ok := c.GetStat("/a"); !ok {
		t.Fatal("expected hit before TTL")
	}

	time.Sleep(100 * time.Millisecond)

	// Should be expired now.
	if _, ok := c.GetStat("/a"); ok {
		t.Error("expected miss after TTL expiry")
	}
}

func TestGetDir_Hit(t *testing.T) {
	c := New(time.Minute, time.Minute)
	entries := []protocol.DirEntry{{Name: "f1", IsDir: false}, {Name: "d1", IsDir: true}}
	c.PutDir("/dir", entries)

	got, ok := c.GetDir("/dir")
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
}

func TestGetDir_TTLExpiry(t *testing.T) {
	c := New(time.Minute, 50*time.Millisecond)
	c.PutDir("/dir", []protocol.DirEntry{{Name: "a"}})

	if _, ok := c.GetDir("/dir"); !ok {
		t.Fatal("expected hit before TTL")
	}

	time.Sleep(100 * time.Millisecond)

	if _, ok := c.GetDir("/dir"); ok {
		t.Error("expected miss after TTL expiry")
	}
}

func TestInvalidatePath(t *testing.T) {
	c := New(time.Minute, time.Minute)
	c.PutStat("/a", &protocol.FileStat{Name: "a"})
	c.PutDir("/a", []protocol.DirEntry{{Name: "x"}})

	c.InvalidatePath("/a")

	if _, ok := c.GetStat("/a"); ok {
		t.Error("stat should be invalidated")
	}
	if _, ok := c.GetDir("/a"); ok {
		t.Error("dir should be invalidated")
	}
}

func TestInvalidatePrefix(t *testing.T) {
	c := New(time.Minute, time.Minute)
	c.PutStat("/a/b/c", &protocol.FileStat{Name: "c"})
	c.PutStat("/a/b/d", &protocol.FileStat{Name: "d"})
	c.PutStat("/x/y", &protocol.FileStat{Name: "y"})
	c.PutDir("/a/b", []protocol.DirEntry{{Name: "c"}})

	c.InvalidatePrefix("/a/b")

	if _, ok := c.GetStat("/a/b/c"); ok {
		t.Error("/a/b/c should be invalidated")
	}
	if _, ok := c.GetStat("/a/b/d"); ok {
		t.Error("/a/b/d should be invalidated")
	}
	if _, ok := c.GetDir("/a/b"); ok {
		t.Error("/a/b dir should be invalidated")
	}
	// /x/y should still be there.
	if _, ok := c.GetStat("/x/y"); !ok {
		t.Error("/x/y should still be cached")
	}
}

func TestMaxEntries_StatEviction(t *testing.T) {
	c := New(time.Minute, time.Minute)
	c.maxEntries = 5

	for i := 0; i < 10; i++ {
		c.PutStat(fmt.Sprintf("/file%d", i), &protocol.FileStat{Name: fmt.Sprintf("f%d", i)})
	}

	// Should have at most 5 entries.
	c.mu.RLock()
	count := len(c.statCache)
	c.mu.RUnlock()
	if count > 5 {
		t.Errorf("stat cache has %d entries, want <= 5", count)
	}
}

func TestMaxEntries_DirEviction(t *testing.T) {
	c := New(time.Minute, time.Minute)
	c.maxEntries = 5

	for i := 0; i < 10; i++ {
		c.PutDir(fmt.Sprintf("/dir%d", i), []protocol.DirEntry{{Name: "a"}})
	}

	c.mu.RLock()
	count := len(c.dirCache)
	c.mu.RUnlock()
	if count > 5 {
		t.Errorf("dir cache has %d entries, want <= 5", count)
	}
}

func TestHitMissCounters(t *testing.T) {
	c := New(time.Minute, time.Minute)
	c.PutStat("/a", &protocol.FileStat{Name: "a"})
	c.PutDir("/d", []protocol.DirEntry{{Name: "x"}})

	// Hits
	c.GetStat("/a")
	c.GetStat("/a")
	c.GetDir("/d")

	// Misses
	c.GetStat("/missing")
	c.GetDir("/missing")
	c.GetDir("/missing2")

	if h := c.StatHits.Load(); h != 2 {
		t.Errorf("StatHits = %d, want 2", h)
	}
	if m := c.StatMisses.Load(); m != 1 {
		t.Errorf("StatMisses = %d, want 1", m)
	}
	if h := c.DirHits.Load(); h != 1 {
		t.Errorf("DirHits = %d, want 1", h)
	}
	if m := c.DirMisses.Load(); m != 2 {
		t.Errorf("DirMisses = %d, want 2", m)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(time.Minute, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/path%d", i%10)
			c.PutStat(path, &protocol.FileStat{Name: path})
			c.GetStat(path)
			c.PutDir(path, []protocol.DirEntry{{Name: "a"}})
			c.GetDir(path)
			c.InvalidatePath(path)
		}(i)
	}
	wg.Wait()
}

func TestStartEviction(t *testing.T) {
	c := New(10*time.Millisecond, 10*time.Millisecond)
	c.PutStat("/a", &protocol.FileStat{Name: "a"})
	c.PutDir("/b", []protocol.DirEntry{{Name: "x"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartEviction(ctx)

	// Wait long enough for entries to expire and eviction to run.
	// Eviction runs every 30s by default, but entries expire by TTL.
	// We just test that after TTL, GetStat returns miss.
	time.Sleep(50 * time.Millisecond)

	if _, ok := c.GetStat("/a"); ok {
		t.Error("expected stat to be expired")
	}
	if _, ok := c.GetDir("/b"); ok {
		t.Error("expected dir to be expired")
	}
}
