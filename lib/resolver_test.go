package lib

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
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
		if r.Header.Get("Content-Type") != "application/dns-udpwireformat" {
			t.Errorf("Unexpected Content-Type: %s", r.Header.Get("Content-Type"))
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
		w.Header().Set("Content-Type", "application/dns-udpwireformat")
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

	_, err := r.makeHttpsRequest(ctx, badMsg, slog.Default())
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
