package lib

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   net.ParseIP("93.184.216.34"),
	})
	return r, nil
}

func handlerBlockZeroIP(m *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a filter instance for each test
			filter := newTestFilterWithMocks(t, baseConfig+tc.configExt, map[string]dnsExchanger{
				"resolver_unfiltered":   mockUnfiltered,
				"resolver_anti_malware": mockMalware,
				"resolver_anti_ads":     mockAds,
			})

			msg, err := filter.ResolveDomain(context.Background(), tc.domain, 1)
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
