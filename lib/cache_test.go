package lib

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCache_SetAndGet(t *testing.T) {
	// minTTL=1 for testing
	cache := NewDNSCache(10, 1)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := cache.GenerateKey(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		},
	}

	cache.Set(key, msg)

	cachedMsg := cache.Get(key)
	if cachedMsg == nil {
		t.Fatal("Expected cache hit, got nil")
	}

	if len(cachedMsg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(cachedMsg.Answer))
	}

	aRecord, ok := cachedMsg.Answer[0].(*dns.A)
	if !ok || !aRecord.A.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("Cached response corrupted")
	}
}

func TestDNSCache_Expiration(t *testing.T) {
	// minTTL=1 for testing
	cache := NewDNSCache(10, 1)
	q := dns.Question{Name: "expired.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := cache.GenerateKey(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	// Set TTL to 1 second
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.ParseIP("1.2.3.4"),
		},
	}

	cache.Set(key, msg)

	// Immediate check
	if cache.Get(key) == nil {
		t.Fatal("Should exist immediately")
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	if cache.Get(key) != nil {
		t.Error("Should have expired")
	}
}

func TestDNSCache_Eviction(t *testing.T) {
	// minTTL=1, Capacity=2
	cache := NewDNSCache(2, 1)

	// Insert 3 items
	items := []string{"a.com.", "b.com.", "c.com."}
	for _, name := range items {
		q := dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		msg.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4")},
		}
		cache.Set(cache.GenerateKey(q), msg)
	}

	// Check size
	cache.mu.RLock()
	size := len(cache.items)
	cache.mu.RUnlock()

	if size > 2 {
		t.Errorf("Cache size %d exceeded capacity 2", size)
	}
}

func TestDNSCache_TTLDecrement(t *testing.T) {
	cache := NewDNSCache(10, 1)
	q := dns.Question{Name: "ttl.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := cache.GenerateKey(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("1.1.1.1")},
	}

	cache.Set(key, msg)

	time.Sleep(2 * time.Second)

	cachedMsg := cache.Get(key)
	if cachedMsg == nil {
		t.Fatal("Cache miss")
	}

	ttl := cachedMsg.Answer[0].Header().Ttl
	// TTL should be roughly 10 - 2 = 8. Allow some slop.
	if ttl > 8 || ttl < 7 {
		t.Errorf("Expected TTL around 8s, got %d", ttl)
	}
}

func TestDNSCache_Prune(t *testing.T) {
	cache := NewDNSCache(10, 1)
	q := dns.Question{Name: "prune.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := cache.GenerateKey(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("1.1.1.1")},
	}

	cache.Set(key, msg)
	time.Sleep(1100 * time.Millisecond)

	// Call prune manually to test the logic
	cache.prune()

	cache.mu.RLock()
	_, exists := cache.items[key]
	cache.mu.RUnlock()

	if exists {
		t.Error("Item should have been pruned")
	}
}

func TestDNSCache_IgnoreShortTTL(t *testing.T) {
	// MinTTL 10
	cache := NewDNSCache(10, 10)
	q := dns.Question{Name: "short.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := cache.GenerateKey(q)

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP("1.1.1.1")},
	}

	cache.Set(key, msg)
	if cache.Get(key) != nil {
		t.Error("Should have ignored short TTL")
	}
}

func TestDNSCachePreservesRecordLifetimes(t *testing.T) {
	cache := NewDNSCache(10, 1)
	msg := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	for _, record := range []string{
		"example.com. 300 IN A 192.0.2.1",
		"example.com. 30 IN NS ns.example.com.",
		"ns.example.com. 20 IN A 192.0.2.2",
	} {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case rr.Header().Rrtype == dns.TypeNS:
			msg.Ns = append(msg.Ns, rr)
		case len(msg.Answer) == 0:
			msg.Answer = append(msg.Answer, rr)
		default:
			msg.Extra = append(msg.Extra, rr)
		}
	}
	msg.SetEdns0(1232, true)
	cache.Set("key", msg)
	// Advance the entry's age without sleeping.
	cache.mu.Lock()
	entry := cache.items["key"]
	entry.StoredAt = entry.StoredAt.Add(-5 * time.Second)
	entry.Expires = entry.Expires.Add(-5 * time.Second)
	cache.items["key"] = entry
	cache.mu.Unlock()
	hit := cache.Get("key")
	if hit == nil {
		t.Fatal("expected cached response")
	}
	for i, got := range []uint32{hit.Answer[0].Header().Ttl, hit.Ns[0].Header().Ttl, hit.Extra[0].Header().Ttl} {
		want := []uint32{295, 25, 15}[i]
		if got != want {
			t.Errorf("record %d TTL=%d, want %d", i, got, want)
		}
	}
	if hit.IsEdns0() != nil {
		t.Error("transaction-specific OPT record was cached")
	}
	if msg.IsEdns0() == nil || !msg.IsEdns0().Do() {
		t.Error("original EDNS metadata was modified")
	}
	if entry.Expires.Sub(entry.StoredAt) != 20*time.Second {
		t.Error("cache can outlive the additional record")
	}
	msg.Answer[0].Header().Ttl = 1
	hit.Answer[0].Header().Ttl = 1
	if again := cache.Get("key"); again.Answer[0].Header().Ttl < 294 {
		t.Error("cache shares mutable records with its callers")
	}
}
