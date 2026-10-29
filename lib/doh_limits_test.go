package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

type testHTTPTransport func(*http.Request) (*http.Response, error)

func (f testHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (b *observedBody) Close() error {
	b.closed = true
	return nil
}

func TestDoHResponseSizeLimit(t *testing.T) {
	query := new(dns.Msg).SetQuestion("large.example.", 65280)
	reply := new(dns.Msg).SetReply(query)
	rr := &dns.RFC3597{Hdr: dns.RR_Header{Name: "large.example.", Rrtype: 65280, Class: dns.ClassINET, Ttl: 60}}
	reply.Answer = []dns.RR{rr}
	base, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rr.Rdata = hex.EncodeToString(bytes.Repeat([]byte{1}, dns.MaxMsgSize-len(base)))
	maximum, err := reply.Pack()
	if err != nil || len(maximum) != dns.MaxMsgSize {
		t.Fatalf("invalid maximum-size test message: length=%d error=%v", len(maximum), err)
	}
	for _, tc := range []struct {
		name      string
		wire      []byte
		declared  int64
		wantError bool
		maxRead   int
	}{
		{"maximum valid", maximum, dns.MaxMsgSize, false, dns.MaxMsgSize},
		{"maximum chunked", maximum, -1, false, dns.MaxMsgSize},
		{"declared oversized", append(bytes.Clone(maximum), 0), dns.MaxMsgSize + 1, true, 0},
		{"chunked oversized", append(bytes.Clone(maximum), 0), -1, true, dns.MaxMsgSize + 1},
		{"large valid prefix", append(bytes.Clone(base), make([]byte, 4<<20)...), -1, true, dns.MaxMsgSize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: bytes.NewReader(tc.wire)}
			resolver := &Resolver{URL: "https://resolver.example/dns-query", httpsClient: &http.Client{Transport: testHTTPTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/dns-message"}}, ContentLength: tc.declared, Body: body}, nil
			})}}
			got, _, err := resolver.resolve(context.Background(), query, slog.Default())
			if (err != nil) != tc.wantError || (tc.wantError && got != nil) {
				t.Fatalf("unexpected response: answer=%v error=%v", got != nil, err)
			}
			if body.read > tc.maxRead || !body.closed {
				t.Fatalf("body read=%d (max %d), closed=%v", body.read, tc.maxRead, body.closed)
			}
		})
	}
}

func TestDoHAgeReducesSOAMinimumLifetime(t *testing.T) {
	resolver := newTestDoHResolver(t, func(query *dns.Msg) *dns.Msg {
		return negativeReply(query, dns.RcodeNameError, 300, 60)
	}, http.Header{"Age": []string{"20"}})
	query := new(dns.Msg).SetQuestion("missing.example.", dns.TypeA)
	reply, _, err := resolver.resolve(context.Background(), query, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	cache := NewDNSCache(10, 1)
	cache.Set("negative", reply)
	if hit := cache.Get("negative"); hit == nil || hit.Ns[0].Header().Ttl != 40 {
		t.Fatalf("HTTP cache time was not deducted from the negative lifetime: %v", hit)
	}
}
