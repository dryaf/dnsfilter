package lib

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ageCachedEntry(t *testing.T, cache *DNSCache, key string, age time.Duration) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.items[key]
	if !ok {
		t.Fatal("expected a cached entry")
	}
	entry.StoredAt = entry.StoredAt.Add(-age)
	entry.Expires = entry.Expires.Add(-age)
	cache.items[key] = entry
}

func negativeReply(query *dns.Msg, rcode int, ttl, minimum uint32) *dns.Msg {
	reply := new(dns.Msg).SetRcode(query, rcode)
	reply.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "ns.example.", Mbox: "hostmaster.example.", Serial: 1,
		Refresh: 60, Retry: 60, Expire: 3600, Minttl: minimum,
	}}
	return reply
}

func TestFilterPermissionExpiresBeforePrimaryAnswer(t *testing.T) {
	for _, ttl := range []uint32{0, 30} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			var calls atomic.Int32
			primary := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				reply, _ := handlerPass(query)
				reply.Answer[0].Header().Ttl = 3600
				return reply, nil
			}}
			ads := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				if calls.Add(1) > 1 {
					return handlerBlockZeroIP(query)
				}
				reply, _ := handlerPass(query)
				reply.Answer[0].Header().Ttl = ttl
				return reply, nil
			}}
			filter := policyTestFilter(primary, ads)
			query := new(dns.Msg).SetQuestion("policy.example.", dns.TypeA)
			writer := localResponseWriter()
			filter.Resolve(writer, query)
			if writer.lastMsg == nil || len(writer.lastMsg.Answer) != 1 || writer.lastMsg.Answer[0].Header().Ttl != ttl {
				t.Fatalf("client can outlive the filter permission: %v", writer.lastMsg)
			}
			if ttl > 0 {
				key := filter.Cache.GenerateRequestKey(query)
				entry := filter.Cache.items[key]
				if entry.Expires.Sub(entry.StoredAt) != time.Duration(ttl)*time.Second {
					t.Fatal("local cache outlives the filter permission")
				}
				filter.Resolve(writer, query)
				if calls.Load() != 1 {
					t.Fatal("valid filter permission was not cached")
				}
				ageCachedEntry(t, filter.Cache, key, 31*time.Second)
			}
			filter.Resolve(writer, query)
			if calls.Load() != 2 || len(writer.lastMsg.Answer) != 1 || !writer.lastMsg.Answer[0].(*dns.A).A.IsUnspecified() {
				t.Fatalf("expired permission bypassed the new block: calls=%d answer=%v", calls.Load(), writer.lastMsg)
			}
		})
	}
}

func TestFilterPermissionWithoutPositiveRecords(t *testing.T) {
	for _, soa := range []bool{false, true} {
		t.Run(fmt.Sprint(soa), func(t *testing.T) {
			ads := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				if soa {
					return negativeReply(query, dns.RcodeSuccess, 300, 20), nil
				}
				return new(dns.Msg).SetReply(query), nil
			}}
			filter := policyTestFilter(&mockDNSClient{Handler: handlerPass}, ads)
			query := new(dns.Msg).SetQuestion("policy.example.", dns.TypeA)
			query.SetEdns0(1232, true)
			writer := localResponseWriter()
			filter.Resolve(writer, query)
			want := uint32(0)
			if soa {
				want = 20
			}
			if writer.lastMsg.Answer[0].Header().Ttl != want || !writer.lastMsg.IsEdns0().Do() {
				t.Fatalf("incorrect permission lifetime or EDNS flags: %v", writer.lastMsg)
			}
		})
	}
}

func TestFilterPermissionAgesWhileWaitingForPrimary(t *testing.T) {
	adsDone := make(chan struct{})
	primary := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
		<-adsDone
		time.Sleep(1100 * time.Millisecond)
		return handlerPass(query)
	}}
	ads := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
		defer close(adsDone)
		reply, _ := handlerPass(query)
		reply.Answer[0].Header().Ttl = 1
		return reply, nil
	}}
	filter := policyTestFilter(primary, ads)
	filter.Config.RequestTimeout = 3 * time.Second
	writer := localResponseWriter()
	query := new(dns.Msg).SetQuestion("policy.example.", dns.TypeA)
	filter.Resolve(writer, query)
	if writer.lastMsg == nil || writer.lastMsg.Answer[0].Header().Ttl != 0 || filter.Cache.Get(filter.Cache.GenerateRequestKey(query)) != nil {
		t.Fatalf("waiting for the primary renewed the filter permission: %v", writer.lastMsg)
	}
}

func TestNegativeAnswersAreCachedWithSOALifetime(t *testing.T) {
	for _, rcode := range []int{dns.RcodeNameError, dns.RcodeSuccess} {
		for _, cname := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cname=%v", dns.RcodeToString[rcode], cname), func(t *testing.T) {
				var calls atomic.Int32
				primary := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
					calls.Add(1)
					reply := negativeReply(query, rcode, 300, 30)
					if cname {
						reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "missing.example."}}
					}
					return reply, nil
				}}
				filter := policyTestFilter(primary, &mockDNSClient{Handler: handlerPass})
				query := new(dns.Msg).SetQuestion("alias.example.", dns.TypeA)
				writer := localResponseWriter()
				for range 3 {
					query.Id++
					filter.Resolve(writer, query)
					if writer.lastMsg == nil || writer.lastMsg.Rcode != rcode || writer.lastMsg.Id != query.Id {
						t.Fatalf("negative reply changed: %v", writer.lastMsg)
					}
				}
				if calls.Load() != 1 || filter.stats.snapshot().CacheHits != 2 {
					t.Fatalf("negative cache missed: upstream calls=%d", calls.Load())
				}
				key := filter.Cache.GenerateRequestKey(query)
				ageCachedEntry(t, filter.Cache, key, 5*time.Second)
				filter.Resolve(writer, query)
				if writer.lastMsg.Ns[0].Header().Ttl != 25 {
					t.Fatalf("negative TTL was not aged: %v", writer.lastMsg)
				}
				ageCachedEntry(t, filter.Cache, key, 26*time.Second)
				filter.Resolve(writer, query)
				if calls.Load() != 2 {
					t.Fatal("expired negative answer stayed cached")
				}
			})
		}
	}
}

func TestCacheRejectsUncacheableNegativeAnswers(t *testing.T) {
	for _, mode := range []string{"no SOA", "zero minimum", "zero TTL", "truncated", "SERVFAIL"} {
		t.Run(mode, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion("missing.example.", dns.TypeA)
			reply := negativeReply(query, dns.RcodeNameError, 300, 60)
			switch mode {
			case "no SOA":
				reply.Ns = nil
			case "zero minimum":
				reply.Ns[0].(*dns.SOA).Minttl = 0
			case "zero TTL":
				reply.Ns[0].Header().Ttl = 0
			case "truncated":
				reply.Truncated = true
			case "SERVFAIL":
				reply.Rcode = dns.RcodeServerFailure
			}
			cache := NewDNSCache(10, 0)
			cache.Set("negative", reply)
			if cache.Get("negative") != nil {
				t.Fatal("unsafe negative answer was cached")
			}
		})
	}
}
