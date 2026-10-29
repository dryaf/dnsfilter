package lib

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolverTransportConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, url, wantNetwork string
		wantError                        bool
	}{
		{"legacy TLS", "", "", "tcp-tls", false},
		{"legacy DoH", "", "https://resolver.example/dns-query", "", false},
		{"UDP", "udp", "", "udp", false},
		{"TCP", "tcp", "", "tcp", false},
		{"TLS", "tls", "", "tcp-tls", false},
		{"DoH", "https", "https://resolver.example/dns-query", "", false},
		{"DoH without URL", "https", "", "", true},
		{"conflicting UDP URL", "udp", "https://resolver.example/dns-query", "", true},
		{"conflicting TCP URL", "tcp", "https://resolver.example/dns-query", "", true},
		{"conflicting TLS URL", "tls", "https://resolver.example/dns-query", "", true},
		{"unknown protocol", "quic", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &Resolver{Addr: "127.0.0.1:853", Protocol: tc.protocol, URL: tc.url}
			err := resolver.LoadAndValidate(false)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if err != nil {
				return
			}
			if tc.wantNetwork == "" {
				if resolver.httpsClient == nil {
					t.Fatal("DoH client is missing")
				}
			} else if client, ok := resolver.dnsClient.(*realDNSClient); !ok || client.client.Net != tc.wantNetwork {
				t.Fatalf("wrong DNS transport: %#v", resolver.dnsClient)
			}
		})
	}
}

func TestStandardDNSUpstreams(t *testing.T) {
	for _, mode := range []string{"udp", "tcp", "udp with TCP fallback"} {
		t.Run(mode, func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tcp.Close() })
			udp, err := net.ListenPacket("udp", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = udp.Close() })
			var udpQueries, tcpQueries atomic.Int32
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
				reply, _ := handlerPass(query)
				if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
					tcpQueries.Add(1)
				} else {
					udpQueries.Add(1)
					if mode == "udp with TCP fallback" {
						reply.Truncated = true
						reply.Answer = nil
					}
				}
				if err := w.WriteMsg(reply); err != nil {
					t.Error(err)
				}
			})
			for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
				started := make(chan struct{})
				done := make(chan error, 1)
				server.NotifyStartedFunc = func() { close(started) }
				go func() { done <- server.ActivateAndServe() }()
				<-started
				t.Cleanup(func() {
					if err := server.Shutdown(); err != nil {
						t.Error(err)
					}
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
			}
			protocol := "udp"
			if mode == "tcp" {
				protocol = "tcp"
			}
			resolver := &Resolver{Addr: tcp.Addr().String(), Protocol: protocol}
			if err := resolver.LoadAndValidate(false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			reply, _, err := resolver.resolve(ctx, query, slog.Default())
			if err != nil || reply == nil || reply.Truncated || len(reply.Answer) != 1 {
				t.Fatalf("plain DNS exchange failed: response=%v error=%v", reply, err)
			}
			wantUDP, wantTCP := int32(1), int32(0)
			if mode == "tcp" {
				wantUDP, wantTCP = 0, 1
			} else if mode == "udp with TCP fallback" {
				wantTCP = 1
			}
			if udpQueries.Load() != wantUDP || tcpQueries.Load() != wantTCP {
				t.Fatalf("UDP/TCP queries=%d/%d, want=%d/%d", udpQueries.Load(), tcpQueries.Load(), wantUDP, wantTCP)
			}
		})
	}
}
