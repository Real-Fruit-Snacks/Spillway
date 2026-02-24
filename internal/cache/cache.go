package cache

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"sync/atomic"
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
	mu         sync.RWMutex
	statCache  map[string]*entry
	dirCache   map[string]*entry
	statOrder  *list.List
	statIndex  map[string]*list.Element
	dirOrder   *list.List
	dirIndex   map[string]*list.Element
	statTTL    time.Duration
	dirTTL     time.Duration
	maxEntries int

	StatHits   atomic.Int64
	StatMisses atomic.Int64
	DirHits    atomic.Int64
	DirMisses  atomic.Int64
}

// New creates a Cache with the given TTLs.
func New(statTTL, dirTTL time.Duration) *Cache {
	return &Cache{
		statCache:  make(map[string]*entry),
		dirCache:   make(map[string]*entry),
		statOrder:  list.New(),
		statIndex:  make(map[string]*list.Element),
		dirOrder:   list.New(),
		dirIndex:   make(map[string]*list.Element),
		statTTL:    statTTL,
		dirTTL:     dirTTL,
		maxEntries: 10000,
	}
}

// GetStat returns the cached FileStat for path if present and not expired.
func (c *Cache) GetStat(path string) (*protocol.FileStat, bool) {
	c.mu.RLock()
	e, ok := c.statCache[path]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		c.StatMisses.Add(1)
		return nil, false
	}
	c.StatHits.Add(1)
	return e.value.(*protocol.FileStat), true
}

// PutStat stores a FileStat in the cache with statTTL expiry.
func (c *Cache) PutStat(path string, st *protocol.FileStat) {
	c.mu.Lock()
	if el, ok := c.statIndex[path]; ok {
		c.statOrder.Remove(el)
	}
	c.statCache[path] = &entry{value: st, expiry: time.Now().Add(c.statTTL)}
	el := c.statOrder.PushBack(path)
	c.statIndex[path] = el
	for len(c.statCache) > c.maxEntries {
		c.evictFront(c.statCache, c.statOrder, c.statIndex)
	}
	c.mu.Unlock()
}

// GetDir returns the cached directory listing for path if present and not expired.
func (c *Cache) GetDir(path string) ([]protocol.DirEntry, bool) {
	c.mu.RLock()
	e, ok := c.dirCache[path]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		c.DirMisses.Add(1)
		return nil, false
	}
	c.DirHits.Add(1)
	return e.value.([]protocol.DirEntry), true
}

// PutDir stores a directory listing in the cache with dirTTL expiry.
func (c *Cache) PutDir(path string, entries []protocol.DirEntry) {
	c.mu.Lock()
	if el, ok := c.dirIndex[path]; ok {
		c.dirOrder.Remove(el)
	}
	c.dirCache[path] = &entry{value: entries, expiry: time.Now().Add(c.dirTTL)}
	el := c.dirOrder.PushBack(path)
	c.dirIndex[path] = el
	for len(c.dirCache) > c.maxEntries {
		c.evictFront(c.dirCache, c.dirOrder, c.dirIndex)
	}
	c.mu.Unlock()
}

// evictFront pops the oldest entry from the FIFO queue and removes it from the map.
func (c *Cache) evictFront(m map[string]*entry, order *list.List, index map[string]*list.Element) {
	front := order.Front()
	if front == nil {
		return
	}
	key := order.Remove(front).(string)
	delete(m, key)
	delete(index, key)
}

// InvalidatePath removes the stat and dir cache entries for the exact path.
func (c *Cache) InvalidatePath(path string) {
	c.mu.Lock()
	delete(c.statCache, path)
	if el, ok := c.statIndex[path]; ok {
		c.statOrder.Remove(el)
		delete(c.statIndex, path)
	}
	delete(c.dirCache, path)
	if el, ok := c.dirIndex[path]; ok {
		c.dirOrder.Remove(el)
		delete(c.dirIndex, path)
	}
	c.mu.Unlock()
}

// InvalidatePrefix removes all cache entries whose key starts with prefix.
func (c *Cache) InvalidatePrefix(prefix string) {
	c.mu.Lock()
	for k := range c.statCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.statCache, k)
			if el, ok := c.statIndex[k]; ok {
				c.statOrder.Remove(el)
				delete(c.statIndex, k)
			}
		}
	}
	for k := range c.dirCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.dirCache, k)
			if el, ok := c.dirIndex[k]; ok {
				c.dirOrder.Remove(el)
				delete(c.dirIndex, k)
			}
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
			if el, ok := c.statIndex[k]; ok {
				c.statOrder.Remove(el)
				delete(c.statIndex, k)
			}
		}
	}
	for k, e := range c.dirCache {
		if now.After(e.expiry) {
			delete(c.dirCache, k)
			if el, ok := c.dirIndex[k]; ok {
				c.dirOrder.Remove(el)
				delete(c.dirIndex, k)
			}
		}
	}
	c.mu.Unlock()
}
