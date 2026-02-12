package lib

import (
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

// GetFreePort asks the kernel for a free open port that is ready to use.
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestIntegration_RunAndResolve(t *testing.T) {
	// 1. Prepare Environment
	dnsPort, err := GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	metricsPort, err := GetFreePort()
	if err != nil {
		t.Fatal(err)
	}

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
	errCh := make(chan error, 1)
	go func() {
		errCh <- filter.Run()
	}()

	// Wait for startup (simple sleep usually sufficient for tests, or poll metrics port)
	time.Sleep(200 * time.Millisecond)

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

	// 5. Test Metrics Endpoint
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err != nil {
		t.Fatalf("Metrics check failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK from metrics, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 6. Test Panic Recovery
	// Inject a panic into the resolver logic
	filter.Config.Resolvers["resolver_unfiltered"].dnsClient = &mockDNSClient{
		Handler: func(m *dns.Msg) (*dns.Msg, error) {
			panic("forced panic")
		},
	}

	// Send request that should panic
	mPanic := new(dns.Msg)
	mPanic.SetQuestion("panic.com.", dns.TypeA)
	_, _, _ = c.Exchange(mPanic, fmt.Sprintf("127.0.0.1:%d", dnsPort))

	// Wait a moment for stats to update
	time.Sleep(50 * time.Millisecond)

	// Check if errors incremented
	if atomic.LoadUint64(&filter.stats.ErrorsTotal) == 0 {
		t.Error("Expected ErrorsTotal to increment after panic")
	}

	// 7. Cleanup is handled by test timeout or killing the process,
	// strictly speaking we should cancel the context of Run(),
	// but Run() waits for Signal. We can send a signal.
	proc, _ := os.FindProcess(os.Getpid())
	proc.Signal(os.Interrupt)

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() exited with error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// t.Log("Timeout waiting for server shutdown")
	}
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

func TestRun_StartupError(t *testing.T) {
	// Use an invalid port to trigger listener error
	configContent := `
listen_addr: "127.0.0.1:999999" 
resolver_unfiltered:
  addr: "1.1.1.1:53"
  name: "dummy"
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	_ = os.WriteFile(configFile, []byte(configContent), 0644)

	filter, _ := NewDNSFilter(configFile, "")

	err := filter.Run()
	if err == nil {
		t.Error("Expected error starting with invalid port")
	}
}

func TestRun_SignalShutdown(t *testing.T) {
	port, _ := GetFreePort()
	configContent := fmt.Sprintf(`
listen_addr: "127.0.0.1:%d"
resolver_unfiltered:
  addr: "1.1.1.1:53"
  name: "dummy"
`, port)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	_ = os.WriteFile(configFile, []byte(configContent), 0644)

	filter, _ := NewDNSFilter(configFile, "")

	errCh := make(chan error)
	go func() {
		errCh <- filter.Run()
	}()

	// Allow to start
	time.Sleep(100 * time.Millisecond)

	// Send SIGINT
	proc, _ := os.FindProcess(os.Getpid())
	proc.Signal(syscall.SIGINT)

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Expected nil error on graceful shutdown, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for shutdown")
	}
}
