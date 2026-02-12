package lib

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
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
whitelist:
  - "whitelisted.com."
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
			configExt:  "filter_malware: true\nfilter_ads: true",
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

	t.Run("Whitelist but resolver_unfiltered missing", func(t *testing.T) {
		// Only configure anti_malware, but whitelist a domain
		config := `
listen_addr: "127.0.0.1:53"
whitelist: ["safe.com."]
filter_malware: true
resolver_anti_malware:
  addr: "1.1.1.1:53"
`
		filter := newTestFilterWithMocks(t, config, nil)
		_, err := filter.ResolveDomain(context.Background(), "safe.com.", 1, logger)
		if err == nil {
			t.Error("Expected error due to missing unfiltered resolver")
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
