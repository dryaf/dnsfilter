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
	Msg     *dns.Msg
	Expires time.Time
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

func (c *DNSCache) Get(key string) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.items[key]
	if !found {
		return nil
	}

	if time.Now().After(entry.Expires) {
		return nil
	}

	// We must clone the message to ensure thread safety and to modify IDs/TTLs later
	msg := entry.Msg.Copy()

	// Adjust TTLs based on how much time has passed
	remaining := time.Until(entry.Expires)
	if remaining < 0 {
		return nil
	}

	// Update TTLs in the response to reflect the remaining time in cache
	for _, rr := range msg.Answer {
		rr.Header().Ttl = uint32(remaining.Seconds())
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = uint32(remaining.Seconds())
	}
	for _, rr := range msg.Extra {
		rr.Header().Ttl = uint32(remaining.Seconds())
	}

	return msg
}

func (c *DNSCache) Set(key string, msg *dns.Msg) {
	if msg == nil || len(msg.Answer) == 0 {
		return
	}

	// Determine the shortest TTL in the answer section to set expiration
	minTTL := uint32(3600) // Default max 1 hour
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// Ignore entries with TTLs shorter than the configured minimum to avoid thrashing
	if minTTL < c.minTTL {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if full
	if len(c.items) >= c.capacity {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}

	c.items[key] = CacheEntry{
		Msg:     msg,
		Expires: time.Now().Add(time.Duration(minTTL) * time.Second),
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
