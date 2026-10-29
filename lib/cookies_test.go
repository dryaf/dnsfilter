package lib

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCookiesStayScopedToRealUDPUpstreams(t *testing.T) {
	start := func(suffix string) *Resolver {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		done := make(chan error, 1)
		server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
			cookie := firstCookie(query).Cookie
			reply, _ := handlerPass(query)
			if len(cookie) == 16 || cookie[16:] != suffix {
				reply.SetRcode(query, dns.RcodeBadCookie)
				reply.Answer = nil
			}
			reply.SetEdns0(1232, false)
			reply.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie[:16] + suffix}}
			if err := w.WriteMsg(reply); err != nil {
				t.Error(err)
			}
		})}
		go func() { done <- server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			_ = server.Shutdown()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		resolver := &Resolver{Addr: packet.LocalAddr().String(), Protocol: "udp"}
		if err := resolver.LoadAndValidate(false); err != nil {
			t.Fatal(err)
		}
		return resolver
	}
	filter := &DNSFilter{Config: &Config{FilterAds: true, Resolvers: map[string]*Resolver{
		"resolver_unfiltered": start("1111111111111111"), "resolver_anti_ads": start("2222222222222222"),
	}}, Cache: NewDNSCache(10, 1), stats: &Stats{}}
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(1232, false)
	query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "1234567890abcdef"}}
	writer := localResponseWriter()
	filter.Resolve(writer, query)
	if writer.lastMsg == nil || writer.lastMsg.Rcode != dns.RcodeSuccess {
		t.Fatalf("initial UDP query: %v", writer.lastMsg)
	}
	query.IsEdns0().Option = writer.lastMsg.IsEdns0().Option
	query.Id++
	filter.Resolve(writer, query)
	if writer.lastMsg.Rcode != dns.RcodeSuccess {
		t.Errorf("second real UDP lookup returned %s after receiving a valid cookie from this proxy", dns.RcodeToString[writer.lastMsg.Rcode])
	}
}

func TestCookieChallengeValidationAndRetryLimit(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "wrong client", "short", "repeated", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			const original = "1234567890abcdefaaaaaaaaaaaaaaaa"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			client := cookieChallengeClient(t, mode, original, cancel, &calls)
			resolver := &Resolver{dnsClient: client}
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			query.SetEdns0(1232, true)
			query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: original}}
			reply, _, err := resolver.resolve(ctx, query, slog.Default())
			if (err == nil) != (mode == "valid") || (mode == "valid" && (reply == nil || reply.Rcode != dns.RcodeSuccess)) {
				t.Fatalf("unexpected cookie outcome: reply=%v error=%v", reply, err)
			}
			wantCalls := 1
			if mode == "valid" || mode == "repeated" || mode == "cancelled" {
				wantCalls = 2
			}
			if calls != wantCalls || firstCookie(query).Cookie != original || !query.IsEdns0().Do() {
				t.Fatalf("calls=%d, want=%d; original query=%v", calls, wantCalls, query)
			}
		})
	}
}

func TestMalformedClientCookiesNeverReachUpstreams(t *testing.T) {
	for _, cookie := range []string{"", "bad", "zzzzzzzzzzzzzzzz", "1234567890abcdef1234"} {
		t.Run(fmt.Sprintf("cookie=%q", cookie), func(t *testing.T) {
			resolver := &Resolver{dnsClient: &mockDNSClient{Handler: func(*dns.Msg) (*dns.Msg, error) {
				t.Fatal("forwarded a malformed cookie")
				return nil, nil
			}}}
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			query.SetEdns0(1232, false)
			query.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie}}
			if _, _, err := resolver.resolve(context.Background(), query, slog.Default()); err == nil {
				t.Fatal("accepted a malformed cookie")
			}
		})
	}
}

func cookieChallengeClient(t *testing.T, mode, original string, cancel context.CancelFunc, calls *int) dnsExchanger {
	t.Helper()
	return contextDNSClient(func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		(*calls)++
		cookie := firstCookie(query).Cookie
		if *calls == 1 && cookie != original[:16] {
			t.Fatalf("forwarded a different upstream's server cookie: %s", cookie)
		}
		if *calls == 2 {
			if cookie != original[:16]+"bbbbbbbbbbbbbbbb" {
				t.Fatalf("retry did not use this upstream's challenge: %s", cookie)
			}
			if mode == "cancelled" {
				return nil, ctx.Err()
			}
			if mode == "valid" {
				return handlerPass(query)
			}
		}
		reply := new(dns.Msg).SetRcode(query, dns.RcodeBadCookie)
		reply.SetEdns0(1232, true)
		value := original[:16] + "bbbbbbbbbbbbbbbb"
		switch mode {
		case "wrong client":
			value = "ffffffffffffffffbbbbbbbbbbbbbbbb"
		case "short":
			value = original[:16]
		case "cancelled":
			cancel()
		}
		if mode != "missing" {
			reply.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: value}}
		}
		return reply, nil
	})
}
