package lib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
)

// Proxy is an interface that defines the behavior of the DNS filter service.
type Proxy interface {
	Run() error
}

// Ensure DNSFilter implements the Proxy interface.
var _ Proxy = (*DNSFilter)(nil)

type DNSFilter struct {
	Config *Config
	Cache  *DNSCache
	stats  *Stats
}

type Stats struct {
	RequestsTotal uint64 `json:"requests_total"`
	BlockedTotal  uint64 `json:"blocked_total"`
	ErrorsTotal   uint64 `json:"errors_total"`
	CacheHits     uint64 `json:"cache_hits"`
}

func NewDNSFilter(configFile, listenAddr string) (*DNSFilter, error) {
	if configFile == "" {
		return nil, errors.New("config file path is required")
	}

	config, err := ConfigFromFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not load config from file: %w", err)
	}

	// Override config if command line argument provided
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}

	// SMART FALLBACK:
	// If the configured IP (e.g., 10.99.0.1) does not exist on this host,
	// fallback to localhost (127.0.0.1) to ensure the service still starts
	// and remains manageable.
	config.ListenAddr = checkAndFallbackIP(config.ListenAddr, "udp")
	if config.MetricsAddr != "" {
		config.MetricsAddr = checkAndFallbackIP(config.MetricsAddr, "tcp")
	}

	if err = config.Validate(); err != nil {
		return nil, fmt.Errorf("could not validate config: %w", err)
	}

	cacheSize := config.CacheSize
	if cacheSize == 0 {
		cacheSize = 10000
	}

	return &DNSFilter{
		Config: config,
		// Defaulting minimum cache TTL to 10 seconds for production safety
		Cache: NewDNSCache(cacheSize, 10),
		stats: &Stats{},
	}, nil
}

// checkAndFallbackIP attempts to bind to the address. If the IP is not available
// (e.g. interface down or non-existent), it returns 127.0.0.1 with the original port.
func checkAndFallbackIP(addr string, network string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // Let later validation handle format errors
	}

	if host == "" || host == "0.0.0.0" || host == "::" {
		return addr // Wildcards are always valid
	}

	// Try to bind. If it fails specifically because the address isn't available, fallback.
	// We use ListenPacket for UDP and Listen for TCP.
	var ln interface{ Close() error }

	if network == "udp" {
		ln, err = net.ListenPacket("udp", addr)
	} else {
		ln, err = net.Listen("tcp", addr)
	}

	if err == nil {
		ln.Close()
		return addr // Address is valid and available
	}

	// Check for "bind: cannot assign requested address" or similar OS errors
	// This usually happens when the IP belongs to an interface that doesn't exist.
	if strings.Contains(err.Error(), "assign requested address") || strings.Contains(err.Error(), "can't assign requested address") {
		fallback := "127.0.0.1:" + port
		slog.Warn("configured address not available on this host, falling back to localhost",
			"configured", addr,
			"fallback", fallback,
			"error", err)
		return fallback
	}

	// For other errors (e.g., "permission denied" or "address in use"),
	// we return the original address and let the main Run() fail naturally
	// so the user sees the real error.
	return addr
}

func (p *DNSFilter) Run() error {
	slog.Info("dns_filter starting",
		"addr", p.Config.ListenAddr,
		"metrics", p.Config.MetricsAddr,
		"cache_size", p.Config.CacheSize,
		"whitelist_count", len(p.Config.Whitelist))

	readTimeout := p.Config.RequestTimeout
	if readTimeout == 0 {
		readTimeout = 5 * time.Second
	}

	// Servers setup
	udpServer := &dns.Server{
		Addr:         p.Config.ListenAddr,
		Net:          "udp",
		ReadTimeout:  readTimeout,
		WriteTimeout: readTimeout,
		Handler:      dns.HandlerFunc(p.Resolve),
	}

	tcpServer := &dns.Server{
		Addr:         p.Config.ListenAddr,
		Net:          "tcp",
		ReadTimeout:  readTimeout,
		WriteTimeout: readTimeout,
		Handler:      dns.HandlerFunc(p.Resolve),
	}

	g, ctx := errgroup.WithContext(context.Background())

	// 1. UDP Listener
	g.Go(func() error {
		slog.Info("listening on udp", "addr", p.Config.ListenAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			return fmt.Errorf("udp server failed: %w", err)
		}
		return nil
	})

	// 2. TCP Listener
	g.Go(func() error {
		slog.Info("listening on tcp", "addr", p.Config.ListenAddr)
		if err := tcpServer.ListenAndServe(); err != nil {
			return fmt.Errorf("tcp server failed: %w", err)
		}
		return nil
	})

	// 3. Metrics & Health Server
	if p.Config.MetricsAddr != "" {
		g.Go(func() error {
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})
			mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(p.stats)
			})

			server := &http.Server{
				Addr:    p.Config.MetricsAddr,
				Handler: mux,
			}
			slog.Info("listening metrics", "addr", p.Config.MetricsAddr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("metrics server failed: %w", err)
			}
			return nil
		})
	}

	// 4. Signal Monitor
	g.Go(func() error {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)

		select {
		case <-stop:
			slog.Info("signal received, shutting down")
		case <-ctx.Done():
			// Another goroutine failed, strictly shutdown
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := udpServer.ShutdownContext(shutdownCtx); err != nil {
			slog.Error("udp shutdown error", "err", err)
		}
		if err := tcpServer.ShutdownContext(shutdownCtx); err != nil {
			slog.Error("tcp shutdown error", "err", err)
		}
		return nil
	})

	return g.Wait()
}

func (p *DNSFilter) Resolve(w dns.ResponseWriter, r *dns.Msg) {
	// Panic Recovery Middleware
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&p.stats.ErrorsTotal, 1)
			slog.Error("panic recovered", "err", r)
		}
	}()

	atomic.AddUint64(&p.stats.RequestsTotal, 1)

	if len(r.Question) == 0 {
		return
	}

	timeout := p.Config.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	q := r.Question[0]

	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}

	reqLogger := slog.With(
		"id", r.Id,
		"domain", q.Name,
		"client_ip", clientIP,
		"proto", transport,
		"type", dns.TypeToString[q.Qtype],
	)

	// Check Cache
	cacheKey := p.Cache.GenerateKey(q)
	if cachedMsg := p.Cache.Get(cacheKey); cachedMsg != nil {
		reqLogger.Debug("cache hit")
		atomic.AddUint64(&p.stats.CacheHits, 1)
		cachedMsg.Id = r.Id // Restore ID to match request
		_ = w.WriteMsg(cachedMsg)
		return
	}

	resolvedMsg, err := p.ResolveDomain(ctx, q.Name, r.Id, reqLogger)
	if err != nil {
		atomic.AddUint64(&p.stats.ErrorsTotal, 1)
		reqLogger.Error("resolve_domain failed", "error", err)
		dnsErr := new(dns.Msg)
		dnsErr.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(dnsErr)
		return
	}

	// Cache successful responses
	if resolvedMsg.Rcode == dns.RcodeSuccess && len(resolvedMsg.Answer) > 0 {
		p.Cache.Set(cacheKey, resolvedMsg)
	} else if resolvedMsg.Rcode == dns.RcodeNameError {
		p.Cache.Set(cacheKey, resolvedMsg)
	}

	if err := w.WriteMsg(resolvedMsg); err != nil {
		reqLogger.Error("write_msg failed", "error", err)
	}
}

// ResolveDomain handles the core logic: whitelist checking, resolver selection, and concurrent lookups.
func (p *DNSFilter) ResolveDomain(ctx context.Context, domain string, originalMsgID uint16, logger *slog.Logger) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Id = originalMsgID

	if whitelistedMsg, ok := p.checkWhitelist(ctx, dns.Fqdn(domain), m, logger); ok {
		return whitelistedMsg, nil
	}

	firstResolver, err := p.getPrimaryResolver()
	if err != nil {
		return nil, err
	}

	return p.resolveConcurrently(ctx, m, firstResolver, logger)
}

func (p *DNSFilter) checkWhitelist(ctx context.Context, domain string, m *dns.Msg, logger *slog.Logger) (*dns.Msg, bool) {
	for _, whitelistedDomain := range p.Config.Whitelist {
		if domain == whitelistedDomain {
			unfilteredResolver, exists := p.Config.Resolvers["resolver_unfiltered"]
			if !exists {
				logger.Error("resolver_unfiltered not found for whitelisted domain")
				return nil, false
			}

			logger.Info("domain is whitelisted", "resolver", unfilteredResolver.Name)

			resp, _, err := unfilteredResolver.resolve(ctx, m, logger)
			if err != nil {
				logger.Error("failed to resolve whitelisted domain", "error", err)
				return nil, false
			}
			return resp, true
		}
	}
	return nil, false
}

func (p *DNSFilter) getPrimaryResolver() (*Resolver, error) {
	var resolver *Resolver
	var exists bool

	switch {
	case p.Config.FilterPorn:
		resolver, exists = p.Config.Resolvers["resolver_anti_porn"]
	case p.Config.FilterMalware:
		resolver, exists = p.Config.Resolvers["resolver_anti_malware"]
	default:
		resolver, exists = p.Config.Resolvers["resolver_unfiltered"]
	}

	if !exists {
		return nil, fmt.Errorf("configured primary resolver not found")
	}
	return resolver, nil
}

type resolveResult struct {
	msg         *dns.Msg
	gotFiltered bool
	err         error
}

func (p *DNSFilter) resolveConcurrently(ctx context.Context, m *dns.Msg, primary *Resolver, logger *slog.Logger) (*dns.Msg, error) {
	g, gctx := errgroup.WithContext(ctx)
	results := make([]resolveResult, 2)

	// Helper to safely execute resolver with panic recovery
	safeResolve := func(r *Resolver, idx int) error {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic in resolver goroutine", "resolver", r.Name, "err", rec)
				results[idx] = resolveResult{err: fmt.Errorf("panic in resolver: %v", rec)}
			}
		}()
		msg, filtered, err := r.resolve(gctx, m.Copy(), logger.With("resolver", r.Name))
		results[idx] = resolveResult{msg: msg, gotFiltered: filtered, err: err}
		return err
	}

	// 1. Primary Resolver
	g.Go(func() error {
		return safeResolve(primary, 0)
	})

	// 2. Ads Resolver (Optional)
	if p.Config.FilterAds {
		g.Go(func() error {
			adsResolver, exists := p.Config.Resolvers["resolver_anti_ads"]
			if !exists {
				return fmt.Errorf("resolver_anti_ads not found")
			}
			return safeResolve(adsResolver, 1)
		})
	}

	_ = g.Wait()

	rPrimary := results[0]
	rAds := results[1]

	if rPrimary.gotFiltered {
		atomic.AddUint64(&p.stats.BlockedTotal, 1)
		return rPrimary.msg, nil
	}
	if p.Config.FilterAds && rAds.gotFiltered {
		atomic.AddUint64(&p.stats.BlockedTotal, 1)
		return rAds.msg, nil
	}
	if rPrimary.msg != nil {
		return rPrimary.msg, rPrimary.err
	}
	if rPrimary.err != nil {
		return nil, rPrimary.err
	}
	if p.Config.FilterAds && rAds.err != nil {
		return nil, rAds.err
	}

	return nil, fmt.Errorf("resolution failed with no response")
}

// Config Definitions

type Config struct {
	ListenAddr     string        `yaml:"listen_addr"`
	MetricsAddr    string        `yaml:"metrics_addr"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
	CacheSize      int           `yaml:"cache_size"`

	FilterMalware bool `yaml:"filter_malware"`
	FilterPorn    bool `yaml:"filter_porn"`
	FilterAds     bool `yaml:"filter_ads"`

	Resolvers map[string]*Resolver `yaml:",inline"`
	Whitelist []string             `yaml:"whitelist"`
}

func ConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	c := &Config{}
	err = yaml.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}

	return c, nil
}

func (c *Config) Validate() error {
	for name, resolver := range c.Resolvers {
		if err := resolver.LoadAndValidate(false); err != nil {
			return fmt.Errorf("resolver %s failed validation: %w", name, err)
		}
	}
	// Normalize Whitelist to FQDNs
	for i, domain := range c.Whitelist {
		c.Whitelist[i] = dns.Fqdn(domain)
	}
	return nil
}
