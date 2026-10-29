package lib

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestResolver_LoadAndValidate(t *testing.T) {
	tests := []struct {
		name      string
		resolver  Resolver
		isTest    bool
		wantError bool
	}{
		{
			name:      "Empty Addr",
			resolver:  Resolver{Addr: ""},
			isTest:    false,
			wantError: true,
		},
		{
			name:      "Invalid Port",
			resolver:  Resolver{Addr: "1.1.1.1:999999"},
			isTest:    false,
			wantError: true,
		},
		{
			name:      "Invalid IP (Strict Mode)",
			resolver:  Resolver{Addr: "999.999.999.999:53"},
			isTest:    false,
			wantError: true,
		},
		{
			name:      "Valid DoT",
			resolver:  Resolver{Addr: "1.1.1.1:853", TLSServerName: "example.com"},
			isTest:    false,
			wantError: false,
		},
		{
			name:      "Invalid URL",
			resolver:  Resolver{Addr: "1.1.1.1:443", URL: ":/broken"},
			isTest:    false,
			wantError: true,
		},
		{
			name:      "Valid DoH",
			resolver:  Resolver{Addr: "1.1.1.1:443", URL: "https://example.com/dns-query"},
			isTest:    false,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.resolver.LoadAndValidate(tt.isTest)
			if (err != nil) != tt.wantError {
				t.Errorf("LoadAndValidate() error = %v, wantError %v", err, tt.wantError)
			}
			if !tt.wantError && tt.resolver.URL != "" && tt.resolver.httpsClient == nil {
				t.Error("Expected httpsClient to be initialized for DoH")
			}
		})
	}
}

func TestResolver_DoH_Integration(t *testing.T) {
	// 1. Setup a Mock DoH Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			t.Errorf("Unexpected Content-Type: %s", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.Header.Get("Accept") != "application/dns-message" {
			t.Errorf("Unexpected Accept: %s", r.Header.Get("Accept"))
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}

		body, _ := io.ReadAll(r.Body)
		reqMsg := new(dns.Msg)
		reqMsg.Unpack(body)

		// Create a DNS response
		respMsg := new(dns.Msg)
		respMsg.SetReply(reqMsg)
		respMsg.Answer = append(respMsg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: reqMsg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		})

		packed, _ := respMsg.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	defer ts.Close()

	// Extract IP/Port from the test server listener
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())

	// 2. Configure Resolver to use this mock server
	r := Resolver{
		Name: "test-doh",
		Addr: "127.0.0.1:" + port,
		URL:  ts.URL,
	}

	if err := r.LoadAndValidate(true); err != nil {
		t.Fatalf("Failed to init resolver: %v", err)
	}

	// 3. Perform Resolution
	q := new(dns.Msg)
	q.SetQuestion("doh.test.", dns.TypeA)

	resp, filtered, err := r.resolve(context.Background(), q, slog.Default())
	if err != nil {
		t.Fatalf("resolve() failed: %v", err)
	}
	if filtered {
		t.Error("Expected NOT filtered")
	}
	if len(resp.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); ok {
		if a.A.String() != "10.0.0.1" {
			t.Errorf("Expected 10.0.0.1, got %s", a.A.String())
		}
	}
}

func TestResolver_DoH_GarbageResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return garbage bytes
		w.Write([]byte("this is not a dns packet"))
	}))
	defer ts.Close()

	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	r := Resolver{
		Name: "garbage-doh",
		Addr: "127.0.0.1:" + port,
		URL:  ts.URL,
	}
	_ = r.LoadAndValidate(true)

	q := new(dns.Msg)
	q.SetQuestion("garbage.test.", dns.TypeA)

	_, _, err := r.resolve(context.Background(), q, slog.Default())
	if err == nil {
		t.Error("Expected error from garbage response, got nil")
	}
}

func TestResolver_DoH_Errors(t *testing.T) {
	// Server that returns 500
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	r := Resolver{
		Name: "broken-doh",
		Addr: "127.0.0.1:" + port,
		URL:  ts.URL,
	}
	_ = r.LoadAndValidate(true)

	q := new(dns.Msg)
	q.SetQuestion("error.test.", dns.TypeA)

	_, _, err := r.resolve(context.Background(), q, slog.Default())
	if err == nil {
		t.Error("Expected error from 500 status code, got nil")
	}
}

func TestResolver_RequestCreationError(t *testing.T) {
	r := Resolver{URL: "https://valid.url"}
	_ = r.LoadAndValidate(true)

	badMsg := new(dns.Msg)
	badMsg.SetQuestion("bad.", dns.TypeA)
	badMsg.Rcode = -1

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.makeHTTPSRequest(ctx, badMsg, slog.Default())
	if err == nil {
		t.Error("Expected error with cancelled context")
	}
}

func TestResolver_DNSClientError(t *testing.T) {
	mockErr := errors.New("network failure")
	r := Resolver{
		Name: "error-dns",
		Addr: "1.1.1.1:53",
		dnsClient: &mockDNSClient{
			Handler: func(m *dns.Msg) (*dns.Msg, error) {
				return nil, mockErr
			},
		},
	}
	// skip validate to keep mock

	q := new(dns.Msg)
	q.SetQuestion("fail.test.", dns.TypeA)

	_, _, err := r.resolve(context.Background(), q, slog.Default())
	if !errors.Is(err, mockErr) && err.Error() != "dns exchange failed: network failure" {
		t.Errorf("Expected 'network failure', got %v", err)
	}
}

func TestResolver_NilResponse(t *testing.T) {
	r := Resolver{
		Name: "nil-dns",
		Addr: "1.1.1.1:53",
		dnsClient: &mockDNSClient{
			Handler: func(m *dns.Msg) (*dns.Msg, error) {
				return nil, nil // Nil response, nil error
			},
		},
	}

	q := new(dns.Msg)
	q.SetQuestion("nil.test.", dns.TypeA)

	_, _, err := r.resolve(context.Background(), q, slog.Default())
	if err == nil || err.Error() != "resolver returned nil response" {
		t.Errorf("Expected 'resolver returned nil response', got %v", err)
	}
}

func newTestDoHResolver(t *testing.T, handler func(*dns.Msg) *dns.Msg, responseHeaders ...http.Header) *Resolver {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire, err := handler(query).Pack()
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		for _, headers := range responseHeaders {
			for name, values := range headers {
				w.Header()[name] = values
			}
		}
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	resolver := &Resolver{Addr: server.Listener.Addr().String(), URL: server.URL}
	if err := resolver.LoadAndValidate(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.httpsClient.CloseIdleConnections)
	return resolver
}

func TestDoHAccountsForHTTPAge(t *testing.T) {
	for _, tc := range []struct {
		age       string
		ttls      [3]uint32
		wantError bool
	}{
		{"", [3]uint32{60, 30, 10}, false},
		{"1", [3]uint32{59, 29, 9}, false},
		{"59", [3]uint32{1, 0, 0}, false},
		{"60", [3]uint32{}, false},
		{"4294967296", [3]uint32{}, false},
		{"18446744073709551615", [3]uint32{}, false},
		{"18446744073709551616", [3]uint32{}, true},
		{"-1", [3]uint32{}, true},
		{"invalid", [3]uint32{}, true},
	} {
		t.Run("age="+tc.age, func(t *testing.T) {
			resolver := newTestDoHResolver(t, func(query *dns.Msg) *dns.Msg {
				reply, _ := handlerPass(query)
				reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30}, Ns: "ns.example.com."}}
				reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("192.0.2.1")}}
				reply.SetEdns0(1232, true)
				return reply
			}, http.Header{"Age": []string{tc.age}})
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			query.SetEdns0(1232, true)
			reply, _, err := resolver.resolve(context.Background(), query, slog.Default())
			if tc.wantError {
				if err == nil {
					t.Fatal("accepted invalid Age")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := [3]uint32{reply.Answer[0].Header().Ttl, reply.Ns[0].Header().Ttl, reply.Extra[0].Header().Ttl}
			if got != tc.ttls {
				t.Errorf("TTL=%v, want=%v", got, tc.ttls)
			}
			if opt := reply.IsEdns0(); opt == nil || !opt.Do() || opt.UDPSize() != 1232 {
				t.Fatalf("Age changed EDNS: %v", opt)
			}
			if tc.age == "59" {
				cache := NewDNSCache(10, 10)
				key := cache.GenerateRequestKey(query)
				cache.Set(key, reply)
				if cache.Get(key) != nil {
					t.Error("expired records entered the DNS cache")
				}
			}
		})
	}
}

func TestResolverDoHPreservesResponse(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			resolver := newTestDoHResolver(t, func(query *dns.Msg) *dns.Msg {
				reply := new(dns.Msg).SetRcode(query, rcode)
				reply.Id = 0
				reply.Authoritative = true
				reply.RecursionAvailable = true
				reply.AuthenticatedData = true
				return reply
			})
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			query.Id = 1234
			reply, filtered, err := resolver.resolve(context.Background(), query, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if reply.Rcode != rcode || reply.Id != query.Id {
				t.Errorf("upstream status or request ID changed: %v", reply.MsgHdr)
			}
			if !reply.Authoritative || !reply.RecursionAvailable || !reply.AuthenticatedData {
				t.Errorf("response flags changed: %v", reply.MsgHdr)
			}
			if filtered != (rcode == dns.RcodeNameError) {
				t.Errorf("filtered=%v for %s", filtered, dns.RcodeToString[rcode])
			}
		})
	}
}

func TestDoHAdsNXDOMAINBlocksPrimaryAnswer(t *testing.T) {
	ads := newTestDoHResolver(t, func(query *dns.Msg) *dns.Msg {
		return new(dns.Msg).SetRcode(query, dns.RcodeNameError)
	})
	filter := &DNSFilter{
		Config: &Config{FilterAds: true, Resolvers: map[string]*Resolver{
			"resolver_unfiltered": {dnsClient: &mockDNSClient{Handler: handlerPass}},
			"resolver_anti_ads":   ads,
		}},
		stats: &Stats{},
	}
	reply, err := filter.ResolveDomain(context.Background(), "example.com.", 1234, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rcode != dns.RcodeNameError || atomic.LoadUint64(&filter.stats.BlockedTotal) != 1 {
		t.Fatalf("ads NXDOMAIN did not block the primary answer: %v", reply)
	}
}

func TestResolverPreservesEDNS(t *testing.T) {
	for _, name := range []string{"legacy", "edns", "dnssec"} {
		t.Run(name, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeAAAA)
			if name != "legacy" {
				query.SetEdns0(1232, name == "dnssec")
			}
			resolver := newTestDoHResolver(t, func(upstream *dns.Msg) *dns.Msg {
				if len(upstream.Extra) != len(query.Extra) {
					t.Errorf("upstream EDNS count=%d, want %d", len(upstream.Extra), len(query.Extra))
				}
				reply := new(dns.Msg).SetReply(upstream)
				if opt := upstream.IsEdns0(); opt != nil {
					if opt.UDPSize() != 1232 || opt.Do() != (name == "dnssec") {
						t.Errorf("upstream EDNS changed: %v", opt)
					}
					reply.SetEdns0(opt.UDPSize(), opt.Do())
				}
				return reply
			})
			reply, _, err := resolver.resolve(context.Background(), query, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if len(reply.Extra) != len(query.Extra) {
				t.Fatalf("response EDNS count=%d, want %d", len(reply.Extra), len(query.Extra))
			}
			if opt := reply.IsEdns0(); opt != nil && (opt.UDPSize() != 1232 || opt.Do() != (name == "dnssec")) {
				t.Errorf("response EDNS changed: %v", opt)
			}
		})
	}
}

func TestResolverBlocksUnspecifiedAddresses(t *testing.T) {
	for _, record := range []string{"example.com. 60 IN A 0.0.0.0", "example.com. 60 IN AAAA ::"} {
		t.Run(record, func(t *testing.T) {
			rr, err := dns.NewRR(record)
			if err != nil {
				t.Fatal(err)
			}
			resolver := &Resolver{dnsClient: &mockDNSClient{Handler: func(query *dns.Msg) (*dns.Msg, error) {
				reply := new(dns.Msg).SetReply(query)
				reply.Answer = []dns.RR{rr}
				return reply, nil
			}}}
			_, filtered, err := resolver.resolve(context.Background(), new(dns.Msg).SetQuestion(rr.Header().Name, rr.Header().Rrtype), slog.Default())
			if err != nil || !filtered {
				t.Errorf("filtered=%v, error=%v", filtered, err)
			}
		})
	}
}

func TestDoHDialHonorsCancellation(t *testing.T) {
	resolver := &Resolver{Addr: "192.0.2.1:443", URL: "https://resolver.example/dns-query"}
	if err := resolver.LoadAndValidate(false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := resolver.httpsClient.Transport.(*http.Transport).DialContext(ctx, "tcp", "resolver.example:443")
	if conn != nil {
		conn.Close()
		t.Error("cancelled dial opened a connection")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial ignored cancellation: %v", err)
	}
}
