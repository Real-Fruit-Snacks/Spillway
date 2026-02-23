package cache

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Real-Fruit-Snacks/Spillway/internal/protocol"
)

const (
	DefaultStatTTL = 5 * time.Second
	DefaultDirTTL  = 5 * time.Second
	evictionPeriod = 30 * time.Second
)

type entry struct {
	value  any
	expiry time.Time
}

// Cache is a generic TTL cache for stat and directory listing results.
type Cache struct {
	mu        sync.RWMutex
	statCache map[string]*entry
	dirCache  map[string]*entry
	statTTL   time.Duration
	dirTTL    time.Duration
}

// New creates a Cache with the given TTLs.
func New(statTTL, dirTTL time.Duration) *Cache {
	return &Cache{
		statCache: make(map[string]*entry),
		dirCache:  make(map[string]*entry),
		statTTL:   statTTL,
		dirTTL:    dirTTL,
	}
}

// GetStat returns the cached FileStat for path if present and not expired.
func (c *Cache) GetStat(path string) (*protocol.FileStat, bool) {
	c.mu.RLock()
	e, ok := c.statCache[path]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.value.(*protocol.FileStat), true
}

// PutStat stores a FileStat in the cache with statTTL expiry.
func (c *Cache) PutStat(path string, st *protocol.FileStat) {
	c.mu.Lock()
	c.statCache[path] = &entry{value: st, expiry: time.Now().Add(c.statTTL)}
	c.mu.Unlock()
}

// GetDir returns the cached directory listing for path if present and not expired.
func (c *Cache) GetDir(path string) ([]protocol.DirEntry, bool) {
	c.mu.RLock()
	e, ok := c.dirCache[path]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.value.([]protocol.DirEntry), true
}

// PutDir stores a directory listing in the cache with dirTTL expiry.
func (c *Cache) PutDir(path string, entries []protocol.DirEntry) {
	c.mu.Lock()
	c.dirCache[path] = &entry{value: entries, expiry: time.Now().Add(c.dirTTL)}
	c.mu.Unlock()
}

// InvalidatePath removes the stat and dir cache entries for the exact path.
func (c *Cache) InvalidatePath(path string) {
	c.mu.Lock()
	delete(c.statCache, path)
	delete(c.dirCache, path)
	c.mu.Unlock()
}

// InvalidatePrefix removes all cache entries whose key starts with prefix.
func (c *Cache) InvalidatePrefix(prefix string) {
	c.mu.Lock()
	for k := range c.statCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.statCache, k)
		}
	}
	for k := range c.dirCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.dirCache, k)
		}
	}
	c.mu.Unlock()
}

// StartEviction launches a background goroutine that removes expired entries
// every 30 seconds. It stops when ctx is cancelled.
func (c *Cache) StartEviction(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(evictionPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.evict()
			}
		}
	}()
}

func (c *Cache) evict() {
	now := time.Now()
	c.mu.Lock()
	for k, e := range c.statCache {
		if now.After(e.expiry) {
			delete(c.statCache, k)
		}
	}
	for k, e := range c.dirCache {
		if now.After(e.expiry) {
			delete(c.dirCache, k)
		}
	}
	c.mu.Unlock()
}
