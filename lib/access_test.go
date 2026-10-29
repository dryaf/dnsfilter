package lib

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestClientAccessBeforeCacheAndUpstream(t *testing.T) {
	for _, configured := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("configured=%v/tcp=%v", configured, tcp), func(t *testing.T) {
				calls := 0
				config := &Config{ListenAddr: "127.0.0.1:0", Resolvers: map[string]*Resolver{
					"resolver_unfiltered": {Addr: "127.0.0.1:853", dnsClient: &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
						calls++
						return handlerPass(query)
					}}},
				}}
				if configured {
					config.AllowedClients = []string{"10.99.0.0/24", "fd00:99::/64"}
				}
				if err := config.Validate(); err != nil {
					t.Fatal(err)
				}
				filter := &DNSFilter{Config: config, Cache: NewDNSCache(10, 1), stats: &Stats{}}
				query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
				// Fill the cache from loopback before testing external access.
				filter.Resolve(localResponseWriter(), query)
				for _, ip := range []string{"127.0.0.2", "::1", "::ffff:127.0.0.1", "10.99.0.2", "::ffff:10.99.0.2", "fd00:99::2", "10.99.1.1", "192.0.2.1", "2001:db8::1"} {
					var remote net.Addr = &net.UDPAddr{IP: net.ParseIP(ip), Port: 53000}
					if tcp {
						remote = &net.TCPAddr{IP: net.ParseIP(ip), Port: 53000}
					}
					allowed := net.ParseIP(ip).IsLoopback() || configured && (ip == "10.99.0.2" || ip == "::ffff:10.99.0.2" || ip == "fd00:99::2")
					writer := &mockResponseWriter{remoteAddr: remote}
					before := filter.stats.snapshot().CacheHits
					filter.Resolve(writer, query)
					want := dns.RcodeRefused
					if allowed {
						want = dns.RcodeSuccess
					}
					if writer.lastMsg == nil || writer.lastMsg.Rcode != want {
						t.Fatalf("%s: response=%v want=%s", ip, writer.lastMsg, dns.RcodeToString[want])
					}
					if !allowed && (filter.stats.snapshot().CacheHits != before || len(writer.lastMsg.Answer) != 0) {
						t.Fatalf("%s read cached DNS data without permission", ip)
					}
				}
				if calls != 1 {
					t.Fatalf("unauthorized request reached upstream: calls=%d", calls)
				}
			})
		}
	}
}
