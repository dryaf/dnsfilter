package lib

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Reserve the addresses together so the kernel cannot return the same port
// for DNS and metrics after an earlier temporary listener has been closed.
func getFreeTestPorts(t *testing.T, count int) []int {
	t.Helper()
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	var ports []int
	for range count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func TestIntegration_RunAndResolve(t *testing.T) {
	// 1. Prepare Environment
	ports := getFreeTestPorts(t, 2)
	dnsPort, metricsPort := ports[0], ports[1]

	// Create a dummy config
	configContent := fmt.Sprintf(`
listen_addr: "127.0.0.1:%d"
metrics_addr: "127.0.0.1:%d"
request_timeout: 2s
cache_size: 100
filter_ads: true
whitelist:
  - "good.com."
resolver_unfiltered:
  addr: "1.1.1.1:53"
  name: "dummy"
resolver_anti_ads:
  addr: "1.1.1.1:53"
  name: "dummy"
`, dnsPort, metricsPort)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Initialize Filter
	filter, err := NewDNSFilter(configFile, "")
	if err != nil {
		t.Fatalf("NewDNSFilter failed: %v", err)
	}

	// Mock the resolvers inside the filter to avoid external network calls during integration test
	mockResolver := &mockDNSClient{
		Handler: func(m *dns.Msg) (*dns.Msg, error) {
			if m.Question[0].Name == "panic.com." {
				panic("forced panic")
			}
			r := new(dns.Msg)
			r.SetReply(m)
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("1.2.3.4"),
			})
			return r, nil
		},
	}
	filter.Config.Resolvers["resolver_unfiltered"].dnsClient = mockResolver
	filter.Config.Resolvers["resolver_anti_ads"].dnsClient = mockResolver

	// 3. Run Server in Goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case err := <-errCh:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				t.Error("DNS service did not stop during cleanup")
			}
		}
	})
	go func() {
		errCh <- filter.RunContext(ctx)
	}()

	waitForHealth(t, filter.Config.MetricsAddr)

	// 4. Test DNS Resolution (UDP)
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion("good.com.", dns.TypeA)
	r, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil {
		t.Fatalf("DNS Exchange failed: %v", err)
	}
	if r == nil || len(r.Answer) == 0 {
		t.Fatal("Expected answer, got empty")
	}
	c.Net = "tcp"
	if r, _, err := c.Exchange(m, filter.Config.ListenAddr); err != nil || r == nil || len(r.Answer) == 0 {
		t.Fatalf("TCP resolution failed: response=%v error=%v", r, err)
	}
	c.Net = "udp"

	// 5. Test Metrics Endpoint
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err != nil {
		t.Fatalf("Metrics check failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK from metrics, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. The mock's panic behavior was installed before starting the service.
	mPanic := new(dns.Msg)
	mPanic.SetQuestion("panic.com.", dns.TypeA)
	panicReply, _, err := c.Exchange(mPanic, filter.Config.ListenAddr)
	if err != nil || panicReply == nil || panicReply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("panic did not produce SERVFAIL: response=%v error=%v", panicReply, err)
	}

	// Check if errors incremented
	if atomic.LoadUint64(&filter.stats.ErrorsTotal) == 0 {
		t.Error("Expected ErrorsTotal to increment after panic")
	}

	// 7. Cancellation must stop DNS and HTTP before RunContext returns.
	cancel()

	select {
	case err := <-errCh:
		stopped = true
		if err != nil {
			t.Errorf("Run() exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DNS and metrics shutdown")
	}
	assertListenersClosed(t, filter.Config.ListenAddr, filter.Config.MetricsAddr)
}

func TestNewDNSFilter_ConfigurationErrors(t *testing.T) {
	// Test 1: No config file
	_, err := NewDNSFilter("", "")
	if err == nil {
		t.Error("Expected error for empty config path")
	}

	// Test 2: Invalid YAML
	tmpDir := t.TempDir()
	badConfig := filepath.Join(tmpDir, "bad.yml")
	os.WriteFile(badConfig, []byte("invalid_yaml: [ unclosed bracket"), 0644)

	_, err = NewDNSFilter(badConfig, "")
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}

	// Test 3: Missing file
	_, err = NewDNSFilter(filepath.Join(tmpDir, "missing.yml"), "")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestNewDNSFilterRejectsInvalidListener(t *testing.T) {
	configContent := `
listen_addr: "127.0.0.1:999999" 
resolver_unfiltered:
  addr: "1.1.1.1:53"
  name: "dummy"
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	_ = os.WriteFile(configFile, []byte(configContent), 0644)

	if _, err := NewDNSFilter(configFile, ""); err == nil {
		t.Error("Expected invalid listener to be rejected before starting")
	}
}

func TestRun_SignalShutdown(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ports := getFreeTestPorts(t, 2)
			dnsPort, metricsPort := ports[0], ports[1]
			filter := &DNSFilter{
				Config: &Config{ListenAddr: fmt.Sprintf("127.0.0.1:%d", dnsPort), MetricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort)},
				Cache:  NewDNSCache(10, 1), stats: &Stats{},
			}
			done := make(chan error, 1)
			go func() { done <- filter.Run() }()
			waitForHealth(t, filter.Config.MetricsAddr)
			proc, err := os.FindProcess(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			if err := proc.Signal(sig); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("signal did not stop all servers")
			}
			assertListenersClosed(t, filter.Config.ListenAddr, filter.Config.MetricsAddr)
		})
	}
}

func waitForHealth(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("health endpoint %s did not become ready", addr)
}

func assertListenersClosed(t *testing.T, dnsAddr, metricsAddr string) {
	t.Helper()
	udp, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		t.Fatalf("UDP port still occupied after shutdown: %v", err)
	}
	udp.Close()
	for _, addr := range []string{dnsAddr, metricsAddr} {
		tcp, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("TCP port %s still occupied after shutdown: %v", addr, err)
		}
		tcp.Close()
	}
}

func TestRunContextBindFailuresReleaseListeners(t *testing.T) {
	for _, blocked := range []string{"tcp", "udp", "metrics"} {
		t.Run(blocked, func(t *testing.T) {
			ports := getFreeTestPorts(t, 2)
			dnsPort, metricsPort := ports[0], ports[1]
			filter := &DNSFilter{
				Config: &Config{ListenAddr: fmt.Sprintf("127.0.0.1:%d", dnsPort), MetricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort)},
				Cache:  NewDNSCache(10, 1), stats: &Stats{},
			}
			var closeOccupied func() error
			if blocked == "udp" {
				conn, err := net.ListenPacket("udp", filter.Config.ListenAddr)
				if err != nil {
					t.Fatal(err)
				}
				closeOccupied = conn.Close
			} else {
				addr := filter.Config.ListenAddr
				if blocked == "metrics" {
					addr = filter.Config.MetricsAddr
				}
				listener, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				closeOccupied = listener.Close
			}
			defer closeOccupied()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- filter.RunContext(ctx) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected a bind error")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("bind failure left RunContext blocked")
			}
			closeOccupied()
			assertListenersClosed(t, filter.Config.ListenAddr, filter.Config.MetricsAddr)
		})
	}
}

func TestRunContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	filter := &DNSFilter{Config: &Config{ListenAddr: "invalid"}}
	if err := filter.RunContext(ctx); err != nil {
		t.Fatal(err)
	}
}
