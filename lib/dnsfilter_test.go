package lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Mock DNS Client ---

type mockDNSClient struct {
	// Handler is a function that simulates a DNS server response.
	Handler func(m *dns.Msg) (*dns.Msg, error)
}

func (c *mockDNSClient) ExchangeContext(ctx context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	if c.Handler == nil {
		panic("mockDNSClient handler is not set")
	}
	r, err := c.Handler(m)
	return r, 0, err
}

// --- Mock Handlers ---

func handlerPass(m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("93.184.216.34"),
	})
	return r, nil
}

func handlerBlockZeroIP(m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("0.0.0.0"),
	})
	return r, nil
}

func handlerBlockNXDOMAIN(m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeNameError)
	return r, nil
}

// --- Test Logic ---

func TestResolveDomainWithMocks(t *testing.T) {
	// Define the mock handlers for our resolvers
	mockUnfiltered := &mockDNSClient{Handler: handlerPass}
	mockMalware := &mockDNSClient{Handler: handlerBlockNXDOMAIN}
	mockAds := &mockDNSClient{Handler: handlerBlockZeroIP}

	baseConfig := `
listen_addr: "127.0.0.1:53"
resolver_unfiltered:
  addr: "1.1.1.1:853"
resolver_anti_malware:
  addr: "9.9.9.9:853"
resolver_anti_ads:
  addr: "94.140.14.14:853"
`
	testCases := []struct {
		name       string
		domain     string
		configExt  string
		wantBlock  bool
		wantResult string // IP or "NXDOMAIN"
	}{
		{
			name:       "Unfiltered request should pass",
			domain:     "example.com.",
			configExt:  "filter_malware: false\nfilter_ads: false",
			wantBlock:  false,
			wantResult: "93.184.216.34",
		},
		{
			name:       "Malware filter should block with NXDOMAIN",
			domain:     "malware.com.",
			configExt:  "filter_malware: true\nfilter_ads: false",
			wantBlock:  true,
			wantResult: "NXDOMAIN",
		},
		{
			name:       "Ads filter should block with 0.0.0.0",
			domain:     "ads.com.",
			configExt:  "filter_malware: false\nfilter_ads: true",
			wantBlock:  true,
			wantResult: "0.0.0.0",
		},
		{
			name:       "Malware filter takes precedence over ads filter",
			domain:     "some-bad-domain.com.",
			configExt:  "filter_malware: true\nfilter_ads: true",
			wantBlock:  true,
			wantResult: "NXDOMAIN",
		},
		{
			name:       "Whitelisted domain should pass even with all filters",
			domain:     "whitelisted.com.",
			configExt:  "whitelist: [whitelisted.com.]\nfilter_malware: true\nfilter_ads: true",
			wantBlock:  false,
			wantResult: "93.184.216.34",
		},
		{
			name:   "Non-FQDN whitelist in config (FQDN Normalization check)",
			domain: "thepiratebay.org.",
			// Config defines whitelist without trailing dot
			configExt:  "whitelist:\n  - \"thepiratebay.org\"\nfilter_malware: true",
			wantBlock:  false,
			wantResult: "93.184.216.34",
		},
	}

	logger := slog.Default()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a filter instance for each test
			filter := newTestFilterWithMocks(t, baseConfig+tc.configExt, map[string]dnsExchanger{
				"resolver_unfiltered":   mockUnfiltered,
				"resolver_anti_malware": mockMalware,
				"resolver_anti_ads":     mockAds,
			})

			msg, err := filter.ResolveDomain(context.Background(), tc.domain, 1, logger)
			if err != nil && msg == nil {
				t.Fatalf("ResolveDomain returned a nil message with error: %v", err)
			}
			if msg == nil {
				t.Fatal("ResolveDomain returned a nil message")
			}

			// Assertions
			if tc.wantBlock {
				if msg.Rcode == dns.RcodeNameError && tc.wantResult == "NXDOMAIN" {
					return // Correctly blocked
				}
				if len(msg.Answer) > 0 {
					if a, ok := msg.Answer[0].(*dns.A); ok && a.A.String() == "0.0.0.0" && tc.wantResult == "0.0.0.0" {
						return // Correctly blocked
					}
				}
				t.Fatalf("Domain should have been blocked, but was not. Rcode: %s, Answer: %v", dns.RcodeToString[msg.Rcode], msg.Answer)
			} else {
				if msg.Rcode != dns.RcodeSuccess {
					t.Fatalf("Expected successful resolution, but got Rcode %s", dns.RcodeToString[msg.Rcode])
				}
				if len(msg.Answer) == 0 {
					t.Fatal("Expected an answer record, but got none")
				}
				if a, ok := msg.Answer[0].(*dns.A); ok {
					if a.A.String() != tc.wantResult {
						t.Errorf("Expected IP %s, but got %s", tc.wantResult, a.A.String())
					}
				} else {
					t.Fatalf("Expected A record, but got %T", msg.Answer[0])
				}
			}
		})
	}
}

func TestResolveDomain_EdgeCases(t *testing.T) {
	logger := slog.Default()

	t.Run("Whitelist missing resolver does not fall through to filtering", func(t *testing.T) {
		var calls atomic.Int32
		filter := &DNSFilter{Config: &Config{Whitelist: []string{"safe.com."}, FilterMalware: true, Resolvers: map[string]*Resolver{
			"resolver_anti_malware": {dnsClient: &mockDNSClient{Handler: func(m *dns.Msg) (*dns.Msg, error) {
				calls.Add(1)
				return handlerBlockNXDOMAIN(m)
			}}},
		}}, stats: &Stats{}}
		_, err := filter.ResolveDomain(context.Background(), "safe.com.", 1, logger)
		if err == nil || calls.Load() != 0 {
			t.Errorf("missing whitelist resolver: err=%v filter calls=%d", err, calls.Load())
		}
	})

	t.Run("Primary fails, Ads succeeds (Fallback logic)", func(t *testing.T) {
		mockPrimary := &mockDNSClient{
			Handler: func(m *dns.Msg) (*dns.Msg, error) { return nil, errors.New("primary failed") },
		}
		mockAds := &mockDNSClient{Handler: handlerPass}

		config := `
listen_addr: "127.0.0.1:53"
filter_malware: true
filter_ads: true
resolver_anti_malware:
  addr: "1.1.1.1:53"
resolver_anti_ads:
  addr: "2.2.2.2:53"
`
		filter := newTestFilterWithMocks(t, config, map[string]dnsExchanger{
			"resolver_anti_malware": mockPrimary,
			"resolver_anti_ads":     mockAds,
		})

		msg, err := filter.ResolveDomain(context.Background(), "test.com.", 1, logger)

		if err == nil {
			t.Error("Expected error from primary resolver")
		}
		if msg != nil {
			t.Error("Expected nil message")
		}
	})
}

func TestWhitelistLogging(t *testing.T) {
	// Capture logs to a buffer
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)

	mockUnfiltered := &mockDNSClient{Handler: handlerPass}
	config := `
listen_addr: "127.0.0.1:53"
whitelist:
  - "logme.com"
resolver_unfiltered:
  name: "super-secure-resolver"
  addr: "1.1.1.1:53"
`
	filter := newTestFilterWithMocks(t, config, map[string]dnsExchanger{
		"resolver_unfiltered": mockUnfiltered,
	})

	// Resolve a whitelisted domain
	_, err := filter.ResolveDomain(context.Background(), "logme.com.", 1, logger)
	if err != nil {
		t.Fatalf("ResolveDomain failed: %v", err)
	}

	// Verify log output
	logOutput := buf.String()
	if !strings.Contains(logOutput, "domain is whitelisted") {
		t.Errorf("Log should contain 'domain is whitelisted', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "\"resolver\":\"super-secure-resolver\"") {
		t.Errorf("Log should contain resolver name, got: %s", logOutput)
	}
}

func TestCacheIntegration(t *testing.T) {
	// Setup filter with mocks
	callCount := 0
	mockUnfiltered := &mockDNSClient{
		Handler: func(m *dns.Msg) (*dns.Msg, error) {
			callCount++
			return handlerPass(m)
		},
	}

	config := `
listen_addr: "127.0.0.1:53"
request_timeout: 1s
cache_size: 100
allowed_clients: ["10.0.0.0/24"]
filter_malware: false
resolver_unfiltered:
  addr: "1.1.1.1:853"
`
	filter := newTestFilterWithMocks(t, config, map[string]dnsExchanger{
		"resolver_unfiltered": mockUnfiltered,
	})

	// Simulate a DNS Writer
	w := &mockResponseWriter{
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234},
	}

	req := new(dns.Msg)
	req.SetQuestion("cached.com.", dns.TypeA)
	req.Id = 1234

	// 1. First Request - Should call backend
	filter.Resolve(w, req)
	if callCount != 1 {
		t.Errorf("Expected 1 backend call, got %d", callCount)
	}
	if atomic.LoadUint64(&filter.stats.CacheHits) != 0 {
		t.Errorf("Expected 0 cache hits, got %d", filter.stats.CacheHits)
	}

	// 2. Second Request - Should NOT call backend
	req.Id = 5678 // New ID
	filter.Resolve(w, req)
	if callCount != 1 {
		t.Errorf("Expected backend call count to remain 1, got %d (Cache Miss)", callCount)
	}
	if atomic.LoadUint64(&filter.stats.CacheHits) != 1 {
		t.Errorf("Expected 1 cache hit, got %d", filter.stats.CacheHits)
	}

	// Verify ID was restored in response
	if w.lastMsg.Id != 5678 {
		t.Errorf("Expected response ID 5678, got %d", w.lastMsg.Id)
	}
}

func TestResolvePreservesQuestion(t *testing.T) {
	for _, whitelisted := range []bool{false, true} {
		for _, record := range []string{
			"example.com. 60 IN A 192.0.2.1",
			"example.com. 60 IN AAAA 2001:db8::1",
			"example.com. 60 IN MX 10 mail.example.com.",
			"example.com. 60 IN TXT \"test\"",
			"example.com. 60 CH TXT \"version\"",
		} {
			t.Run(fmt.Sprintf("whitelist=%t/%s", whitelisted, record), func(t *testing.T) {
				rr, err := dns.NewRR(record)
				if err != nil {
					t.Fatal(err)
				}
				request := new(dns.Msg).SetQuestion(rr.Header().Name, rr.Header().Rrtype)
				request.Question[0].Qclass = rr.Header().Class
				request.RecursionDesired = false
				request.CheckingDisabled = true
				request.AuthenticatedData = true
				var upstream *dns.Msg
				filter := &DNSFilter{
					Config: &Config{Resolvers: map[string]*Resolver{
						"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: func(m *dns.Msg) (*dns.Msg, error) {
							upstream = m.Copy()
							reply := new(dns.Msg).SetReply(m)
							reply.Answer = []dns.RR{dns.Copy(rr)}
							return reply, nil
						}}},
					}},
					Cache: NewDNSCache(10, 1), stats: &Stats{},
				}
				if whitelisted {
					filter.Config.Whitelist = []string{request.Question[0].Name}
				}
				writer := &mockResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
				filter.Resolve(writer, request)
				if upstream == nil || writer.lastMsg == nil {
					t.Fatal("missing upstream request or client response")
				}
				if upstream.Question[0] != request.Question[0] || writer.lastMsg.Question[0] != request.Question[0] {
					t.Fatalf("question changed: request=%v upstream=%v reply=%v", request.Question, upstream.Question, writer.lastMsg.Question)
				}
				if upstream.RecursionDesired || !upstream.CheckingDisabled || !upstream.AuthenticatedData {
					t.Errorf("request flags changed: %v", upstream.MsgHdr)
				}
				if got := writer.lastMsg.Answer[0].Header().Rrtype; got != request.Question[0].Qtype {
					t.Errorf("answer type=%d, want %d", got, request.Question[0].Qtype)
				}
				request.Id++
				filter.Resolve(writer, request)
				if writer.lastMsg.Id != request.Id || writer.lastMsg.Question[0] != request.Question[0] {
					t.Errorf("cached response does not match request: %v", writer.lastMsg)
				}
			})
		}
	}
}

func TestCacheSeparatesRequestSemantics(t *testing.T) {
	calls := 0
	filter := &DNSFilter{
		Config: &Config{Resolvers: map[string]*Resolver{
			"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: func(m *dns.Msg) (*dns.Msg, error) {
				calls++
				reply, err := handlerPass(m)
				if opt := m.IsEdns0(); opt != nil {
					reply.SetEdns0(opt.UDPSize(), opt.Do())
				}
				return reply, err
			}}},
		}},
		Cache: NewDNSCache(10, 1), stats: &Stats{},
	}
	variants := []struct {
		name   string
		change func(*dns.Msg)
	}{
		{"default", func(*dns.Msg) {}},
		{"no recursion", func(m *dns.Msg) { m.RecursionDesired = false }},
		{"checking disabled", func(m *dns.Msg) { m.CheckingDisabled = true }},
		{"authenticated data", func(m *dns.Msg) { m.AuthenticatedData = true }},
		{"EDNS", func(m *dns.Msg) { m.SetEdns0(1232, false) }},
		{"DNSSEC", func(m *dns.Msg) { m.SetEdns0(1232, true) }},
	}
	writer := &mockResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
	for i, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			variant.change(query)
			filter.Resolve(writer, query)
			if calls != i+1 {
				t.Fatalf("different request reused another response: backend calls=%d, want %d", calls, i+1)
			}
			query.Id++
			if opt := query.IsEdns0(); opt != nil {
				opt.SetUDPSize(512)
			}
			filter.Resolve(writer, query)
			if calls != i+1 {
				t.Errorf("identical request missed cache: backend calls=%d", calls)
			}
			if writer.lastMsg.Id != query.Id {
				t.Error("cached response ID was not restored")
			}
			if opt := query.IsEdns0(); opt != nil {
				got := writer.lastMsg.IsEdns0()
				if got == nil || got.Do() != opt.Do() {
					t.Errorf("cached response lost EDNS/DNSSEC: %v", got)
				}
			}
		})
	}
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(1232, false)
	query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}}}
	for i := 0; i < 2; i++ {
		filter.Resolve(writer, query)
	}
	if calls != len(variants)+2 {
		t.Errorf("transaction-specific EDNS query was cached: calls=%d", calls)
	}
}

func TestUDPResponseLimitsAndTCPFallback(t *testing.T) {
	for _, advertised := range []uint16{0, 128, 512, 1232, 4096} {
		t.Run(fmt.Sprintf("EDNS-size=%d", advertised), func(t *testing.T) {
			calls := 0
			filter := &DNSFilter{
				Config: &Config{Resolvers: map[string]*Resolver{
					"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
						calls++
						reply := new(dns.Msg).SetReply(query)
						for i := 1; i <= 100; i++ {
							reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, byte(i))})
						}
						return reply, nil
					}}},
				}},
				Cache: NewDNSCache(10, 1), stats: &Stats{},
			}
			query := new(dns.Msg).SetQuestion("large.example.", dns.TypeA)
			limit := dns.MinMsgSize
			if advertised != 0 {
				query.SetEdns0(advertised, false)
				limit = min(1232, max(512, int(advertised)))
			}
			writer := &mockResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
			for attempt := 0; attempt < 2; attempt++ {
				query.Id++
				filter.Resolve(writer, query)
				wire, err := writer.lastMsg.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if len(wire) > limit || !writer.lastMsg.Truncated {
					t.Errorf("attempt %d: %d bytes, TC=%v; want <=%d and TC=true", attempt, len(wire), writer.lastMsg.Truncated, limit)
				}
				if (writer.lastMsg.IsEdns0() != nil) != (advertised != 0) {
					t.Error("response EDNS does not match client support")
				}
			}
			writer.remoteAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
			filter.Resolve(writer, query)
			if writer.lastMsg.Truncated || len(writer.lastMsg.Answer) != 100 {
				t.Fatalf("TCP fallback received an incomplete cached answer: %v", writer.lastMsg)
			}
			if calls != 1 {
				t.Errorf("expected one upstream call, got %d", calls)
			}
		})
	}
}

func TestMetricsDuringResolution(t *testing.T) {
	filter := &DNSFilter{
		Config: &Config{Resolvers: map[string]*Resolver{
			"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: handlerPass}},
		}},
		Cache: NewDNSCache(10, 1), stats: &Stats{},
	}
	const count = 1000
	done := make(chan struct{})
	go func() {
		defer close(done)
		writer := &mockResponseWriter{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}}
		query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		for i := 0; i < count; i++ {
			filter.Resolve(writer, query)
		}
	}()
	handler := filter.metricsHandler()
	readMetrics := func() Stats {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
			t.Errorf("unexpected metrics response: %v", response.Result())
		}
		var stats Stats
		if err := json.Unmarshal(response.Body.Bytes(), &stats); err != nil {
			t.Fatal(err)
		}
		return stats
	}
	for i := 0; i < count; i++ {
		readMetrics()
	}
	<-done
	stats := readMetrics()
	if stats.RequestsTotal != count || stats.CacheHits != count-1 || stats.ErrorsTotal != 0 {
		t.Errorf("unexpected final metrics: %+v", stats)
	}
}

// newTestFilterWithMocks is a helper to create a DNSFilter and inject mock clients.
func newTestFilterWithMocks(t *testing.T, configYAML string, mocks map[string]dnsExchanger) *DNSFilter {
	t.Helper()
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	err := os.WriteFile(configFile, []byte(configYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp config file: %v", err)
	}

	// Create filter from file first
	// Note: We use NewDNSFilter which now initializes Cache and Stats
	filter, err := NewDNSFilter(configFile, "")
	if err != nil {
		t.Fatalf("Failed to create DNSFilter: %v", err)
	}

	// Now, inject the mocks
	for name, mockClient := range mocks {
		if resolver, ok := filter.Config.Resolvers[name]; ok {
			resolver.dnsClient = mockClient
		}
	}

	return filter
}

// mockResponseWriter implements dns.ResponseWriter
type mockResponseWriter struct {
	lastMsg    *dns.Msg
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockResponseWriter) LocalAddr() net.Addr  { return m.localAddr }
func (m *mockResponseWriter) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.lastMsg = msg
	return nil
}
func (m *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockResponseWriter) Close() error              { return nil }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}
