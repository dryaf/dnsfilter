package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheEntry struct {
	Msg      *dns.Msg
	StoredAt time.Time
	Expires  time.Time
}

type DNSCache struct {
	items    map[string]CacheEntry
	mu       sync.RWMutex
	capacity int
	minTTL   uint32
}

func NewDNSCache(capacity int, minTTL uint32) *DNSCache {
	if capacity <= 0 {
		capacity = 1000
	}
	cache := &DNSCache{
		items:    make(map[string]CacheEntry),
		capacity: capacity,
		minTTL:   minTTL,
	}
	go cache.cleanupLoop()
	return cache
}

// GenerateKey creates a unique key based on the Question (Name, Type, Class).
func (c *DNSCache) GenerateKey(q dns.Question) string {
	raw := fmt.Sprintf("%s|%d|%d", q.Name, q.Qtype, q.Qclass)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// GenerateRequestKey keeps responses with different DNSSEC and recursion
// semantics separate. Transaction-specific EDNS options and signed messages
// bypass the shared cache.
func (c *DNSCache) GenerateRequestKey(m *dns.Msg) string {
	if m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 || len(m.Answer) != 0 || len(m.Ns) != 0 {
		return ""
	}
	var edns, do bool
	for _, rr := range m.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok || edns || opt.Version() != 0 || len(opt.Option) != 0 {
			return ""
		}
		edns, do = true, opt.Do()
	}
	return fmt.Sprintf("%s|%t|%t|%t|%t|%t", c.GenerateKey(m.Question[0]), m.RecursionDesired, m.CheckingDisabled, m.AuthenticatedData, edns, do)
}

func (c *DNSCache) Get(key string) *dns.Msg {
	if key == "" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.items[key]
	if !found {
		return nil
	}

	now := time.Now()
	if !now.Before(entry.Expires) {
		return nil
	}

	// We must clone the message to ensure thread safety and to modify IDs/TTLs later
	msg := entry.Msg.Copy()

	// Age each record independently; a shorter-lived additional record must
	// never inherit the lifetime of an answer. OPT records are not cached.
	elapsed := max(0, now.Sub(entry.StoredAt)/time.Second)
	ageResponseTTL(msg, uint64(elapsed))

	return msg
}

// Set stores positive or SOA-backed negative responses within their valid lifetime.
func (c *DNSCache) Set(key string, msg *dns.Msg) {
	if key == "" {
		return
	}
	minTTL, cacheable := responseTTL(msg)
	if !cacheable || minTTL == 0 {
		return
	}
	minTTL = min(minTTL, 3600)

	// Ignore entries with TTLs shorter than the configured minimum to avoid thrashing
	if minTTL < c.minTTL {
		return
	}
	// Own the cached message: packing or truncating the caller's response may
	// mutate it concurrently with another request's cache lookup.
	cached := msg.Copy()
	normalizeNegativeTTL(cached)
	extra := cached.Extra[:0]
	for _, rr := range cached.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	cached.Extra = extra

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if full
	if len(c.items) >= c.capacity {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}

	now := time.Now()
	c.items[key] = CacheEntry{
		Msg:      cached,
		StoredAt: now,
		Expires:  now.Add(time.Duration(minTTL) * time.Second),
	}
}

func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		c.prune()
	}
}

func (c *DNSCache) prune() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.items {
		if now.After(entry.Expires) {
			delete(c.items, key)
		}
	}
}
