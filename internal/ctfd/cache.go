package ctfd

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxCacheEntries bounds the read cache. A large event has a few hundred
// challenges and users; this is generous while still preventing a long-running
// server from growing without limit.
const maxCacheEntries = 512

// ttlCache is a small, bounded, time-expiring cache of raw API payloads.
//
// Caching matters here for a specific reason: a model exploring a CTF will
// call ctfd_list_challenges repeatedly within a single turn. Serving those
// from cache keeps the client well under CTFd's rate limits and keeps the
// scoreboard's view of this competitor's request volume unremarkable.
type ttlCache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]cacheEntry
	now     func() time.Time
}

type cacheEntry struct {
	data    json.RawMessage
	meta    *Meta
	expires time.Time
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{ttl: ttl, entries: make(map[string]cacheEntry), now: time.Now}
}

// Enabled reports whether caching is active.
func (c *ttlCache) Enabled() bool { return c != nil && c.ttl > 0 }

func (c *ttlCache) get(key string) (json.RawMessage, *Meta, bool) {
	if !c.Enabled() {
		return nil, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, nil, false
	}
	if c.now().After(e.expires) {
		delete(c.entries, key)
		return nil, nil, false
	}
	return e.data, e.meta, true
}

func (c *ttlCache) set(key string, data json.RawMessage, meta *Meta) {
	if !c.Enabled() || len(data) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxCacheEntries {
		c.evictLocked()
	}
	// Copy: the caller's buffer is reused by the JSON decoder.
	cp := make(json.RawMessage, len(data))
	copy(cp, data)
	c.entries[key] = cacheEntry{data: cp, meta: meta, expires: c.now().Add(c.ttl)}
}

func (c *ttlCache) delete(key string) {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Purge drops every entry. It is called after any state-changing operation,
// because a successful flag submission or hint unlock invalidates challenge
// state, scoreboard position, and the user's own solve list at once.
func (c *ttlCache) Purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
}

// evictLocked drops expired entries, falling back to dropping the oldest half
// when nothing has expired. The caller must hold c.mu.
func (c *ttlCache) evictLocked() {
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < maxCacheEntries {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, kv{k, e.expires})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for i := 0; i < len(all)/2; i++ {
		delete(c.entries, all[i].k)
	}
}

// InvalidateCache drops all cached reads. Call after any write.
func (c *Client) InvalidateCache() { c.cache.Purge() }

// cacheKeyFor builds a stable key from a path and its query parameters.
// Parameters are sorted so that semantically identical requests share an entry
// regardless of map iteration order.
func cacheKeyFor(path string, q url.Values) string {
	if len(q) == 0 {
		return path
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(path)
	b.WriteByte('?')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strings.Join(vs, ","))
	}
	return b.String()
}
