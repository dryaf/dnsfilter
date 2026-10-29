package lib

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSProbeRequiresBothTransportsAndSuccessfulAnswers(t *testing.T) {
	for _, mode := range []string{"healthy", "UDP truncated", "TCP failure", "UDP failure"} {
		t.Run(mode, func(t *testing.T) {
			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tcp.Close() })
			udp, err := net.ListenPacket("udp4", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = udp.Close() })
			var udpCalls, tcpCalls atomic.Int32
			handler := probeTestHandler(t, mode, &udpCalls, &tcpCalls)
			for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
				ready := make(chan struct{})
				done := make(chan error, 1)
				server.NotifyStartedFunc = func() { close(ready) }
				go func() { done <- server.ActivateAndServe() }()
				<-ready
				t.Cleanup(func() {
					if err := server.Shutdown(); err != nil {
						t.Error(err)
					}
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = CheckDNS(ctx, tcp.Addr().String())
			wantSuccess := mode == "healthy" || mode == "UDP truncated"
			if (err == nil) != wantSuccess {
				t.Fatalf("probe returned %v for %s", err, mode)
			}
			if wantSuccess && (udpCalls.Load() != 1 || tcpCalls.Load() != 1) {
				t.Fatal("successful probe did not check both transports")
			}
		})
	}
}

func probeTestHandler(t *testing.T, mode string, udpCalls, tcpCalls *atomic.Int32) dns.Handler {
	t.Helper()
	return dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		if tcp {
			tcpCalls.Add(1)
		} else {
			udpCalls.Add(1)
		}
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."}}
		if !tcp && mode == "UDP truncated" {
			reply.Truncated = true
			reply.Answer = nil
		}
		if (tcp && mode == "TCP failure") || (!tcp && mode == "UDP failure") {
			reply.Rcode = dns.RcodeServerFailure
			reply.Answer = nil
		}
		if err := w.WriteMsg(reply); err != nil {
			t.Error(err)
		}
	})
}
