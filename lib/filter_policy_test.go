package lib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type contextDNSClient func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f contextDNSClient) ExchangeContext(ctx context.Context, m *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	reply, err := f(ctx, m)
	return reply, 0, err
}

func policyTestFilter(primary, ads dnsExchanger) *DNSFilter {
	return &DNSFilter{
		Config: &Config{FilterAds: true, RequestTimeout: time.Second, Resolvers: map[string]*Resolver{
			"resolver_unfiltered": {Name: "primary", dnsClient: primary},
			"resolver_anti_ads":   {Name: "ads", dnsClient: ads},
		}},
		Cache: NewDNSCache(10, 1), stats: &Stats{},
	}
}

func TestAdsOutageIndependentOfCompletionOrder(t *testing.T) {
	for _, primaryFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("primaryFirst=%v", primaryFirst), func(t *testing.T) {
			firstDone := make(chan struct{})
			client := func(primary bool) dnsExchanger {
				return contextDNSClient(func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
					if primary == primaryFirst {
						defer close(firstDone)
					} else {
						select {
						case <-firstDone:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					if primary {
						return handlerPass(query)
					}
					return nil, errors.New("ads unavailable")
				})
			}
			filter := policyTestFilter(client(true), client(false))
			writer := localResponseWriter()
			filter.Resolve(writer, new(dns.Msg).SetQuestion("ads.example.", dns.TypeA))
			if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeServerFailure || len(writer.lastMsg.Answer) != 0 {
				t.Fatalf("outage allowed an unchecked answer: %v", writer.lastMsg)
			}
		})
	}
}

func TestAdsFailuresDoNotCacheUncheckedAnswers(t *testing.T) {
	for _, failure := range []string{"network", "SERVFAIL", "REFUSED", "truncated", "panic", "nil response"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			ads := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				if calls.Add(1) > 1 {
					return handlerBlockZeroIP(query)
				}
				switch failure {
				case "network":
					return nil, errors.New("ads unavailable")
				case "panic":
					panic("ads panic")
				case "nil response":
					return nil, nil
				case "truncated":
					reply := new(dns.Msg).SetReply(query)
					reply.Truncated = true
					return reply, nil
				default:
					return new(dns.Msg).SetRcode(query, dns.StringToRcode[failure]), nil
				}
			}}
			filter := policyTestFilter(&mockDNSClient{Handler: handlerPass}, ads)
			writer := localResponseWriter()
			query := new(dns.Msg).SetQuestion("ads.example.", dns.TypeA)
			filter.Resolve(writer, query)
			if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeServerFailure {
				t.Fatalf("filter failure did not produce SERVFAIL: %v", writer.lastMsg)
			}
			filter.Resolve(writer, query)
			if calls.Load() != 2 || filter.stats.snapshot().CacheHits != 0 || len(writer.lastMsg.Answer) != 1 || !writer.lastMsg.Answer[0].(*dns.A).A.IsUnspecified() {
				t.Fatalf("recovered filter was bypassed: calls=%d response=%v", calls.Load(), writer.lastMsg)
			}
		})
	}
}

func localResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}}
}

func TestWhitelistIgnoresCaseAndPreservesQuestion(t *testing.T) {
	filter := policyTestFilter(&mockDNSClient{Handler: handlerPass}, &mockDNSClient{Handler: handlerBlockNXDOMAIN})
	filter.Config.Whitelist = []string{"eXaMpLe.CoM"}
	for _, name := range []string{"example.com.", "ExAmPlE.CoM.", "EXAMPLE.COM."} {
		query := new(dns.Msg).SetQuestion(name, dns.TypeA)
		writer := localResponseWriter()
		filter.Resolve(writer, query)
		if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeSuccess || len(writer.lastMsg.Answer) != 1 || writer.lastMsg.Question[0] != query.Question[0] {
			t.Fatalf("whitelist did not preserve %q: %v", name, writer.lastMsg)
		}
	}
	writer := localResponseWriter()
	filter.Resolve(writer, new(dns.Msg).SetQuestion("example.com.evil.", dns.TypeA))
	if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeNameError {
		t.Fatalf("whitelist matched a different domain: %v", writer.lastMsg)
	}
}

func TestWhitelistFailureNeverUsesFilteringResolvers(t *testing.T) {
	for _, failure := range []string{"network", "panic", "SERVFAIL"} {
		t.Run(failure, func(t *testing.T) {
			var unfilteredCalls, adsCalls atomic.Int32
			unfiltered := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				if unfilteredCalls.Add(1) > 1 {
					return handlerPass(query)
				}
				switch failure {
				case "network":
					return nil, errors.New("unfiltered resolver down")
				case "panic":
					panic("unfiltered resolver panic")
				default:
					return new(dns.Msg).SetRcode(query, dns.RcodeServerFailure), nil
				}
			}}
			ads := &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				adsCalls.Add(1)
				return handlerBlockZeroIP(query)
			}}
			filter := policyTestFilter(unfiltered, ads)
			filter.Config.Whitelist = []string{"example.com."}
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			writer := localResponseWriter()
			filter.Resolve(writer, query)
			if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeServerFailure || adsCalls.Load() != 0 {
				t.Fatalf("whitelist failed: ads calls=%d response=%v", adsCalls.Load(), writer.lastMsg)
			}
			filter.Resolve(writer, query)
			if unfilteredCalls.Load() != 2 || adsCalls.Load() != 0 || filter.stats.snapshot().CacheHits != 0 || writer.lastMsg.Rcode != dns.RcodeSuccess {
				t.Fatalf("whitelist did not recover: %v", writer.lastMsg)
			}
		})
	}
}

func TestFilteringHonorsExtendedDNSErrors(t *testing.T) {
	for _, record := range []string{
		`ads.example. 60 IN TXT "blocked domain"`,
		`ads.example. 60 IN MX 10 mail.example.`,
		`ads.example. 60 IN HTTPS 1 . alpn="h2" ipv4hint=192.0.2.10`,
	} {
		for _, code := range []uint16{dns.ExtendedErrorCodeBlocked, dns.ExtendedErrorCodeCensored, dns.ExtendedErrorCodeFiltered, dns.ExtendedErrorCodeProhibited, dns.ExtendedErrorCodeStaleAnswer} {
			for _, edns := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ede=%d/edns=%v", record, code, edns), func(t *testing.T) {
					rr, err := dns.NewRR(record)
					if err != nil {
						t.Fatal(err)
					}
					ads := newTestDoHResolver(t, func(query *dns.Msg) *dns.Msg {
						if query.IsEdns0() == nil {
							t.Error("filter lookup did not request EDNS")
						}
						answer := new(dns.Msg).SetReply(query)
						answer.SetEdns0(1232, false)
						answer.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_EDE{InfoCode: code}}
						return answer
					})
					filter := &DNSFilter{
						Config: &Config{FilterAds: true, Resolvers: map[string]*Resolver{
							"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
								answer := new(dns.Msg).SetReply(query)
								answer.Answer = []dns.RR{dns.Copy(rr)}
								return answer, nil
							}}},
							"resolver_anti_ads": ads,
						}},
						Cache: NewDNSCache(10, 1), stats: &Stats{},
					}
					query := new(dns.Msg).SetQuestion(rr.Header().Name, rr.Header().Rrtype)
					if edns {
						query.SetEdns0(1232, false)
					}
					writer := localResponseWriter()
					filter.Resolve(writer, query)
					if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeSuccess {
						t.Fatalf("unexpected reply: %v", writer.lastMsg)
					}
					blocked := code != dns.ExtendedErrorCodeStaleAnswer
					if (len(writer.lastMsg.Answer) == 0) != blocked || (filter.stats.snapshot().BlockedTotal == 1) != blocked {
						t.Fatalf("wrong filtering decision: blocked=%v response=%v", blocked, writer.lastMsg)
					}
					if (query.IsEdns0() != nil) != edns || (writer.lastMsg.IsEdns0() != nil) != edns {
						t.Error("client EDNS negotiation changed")
					}
				})
			}
		}
	}
}
