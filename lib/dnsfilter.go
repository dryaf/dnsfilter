package lib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sync/errgroup"
)

// Proxy is an interface that defines the behavior of the DNS filter service.
type Proxy interface {
	RunContext(context.Context) error
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

func (s *Stats) snapshot() Stats {
	return Stats{
		RequestsTotal: atomic.LoadUint64(&s.RequestsTotal),
		BlockedTotal:  atomic.LoadUint64(&s.BlockedTotal),
		ErrorsTotal:   atomic.LoadUint64(&s.ErrorsTotal),
		CacheHits:     atomic.LoadUint64(&s.CacheHits),
	}
}

func (p *DNSFilter) metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.stats.snapshot())
	})
	return mux
}

// Keep UDP responses below the IPv6 minimum MTU after IP and UDP headers.
const maxUDPPayloadSize = 1232

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
	if err = config.Validate(); err != nil {
		return nil, fmt.Errorf("could not validate config: %w", err)
	}

	// SMART FALLBACK:
	// If the configured IP (e.g., 10.99.0.1) does not exist on this host,
	// fallback to localhost (127.0.0.1) to ensure the service still starts
	// and remains manageable.
	config.ListenAddr = checkAndFallbackIP(config.ListenAddr, "udp")
	if config.MetricsAddr != "" {
		config.MetricsAddr = checkAndFallbackIP(config.MetricsAddr, "tcp")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return p.RunContext(ctx)
}

// RunContext serves DNS until cancellation or a listener failure.
func (p *DNSFilter) RunContext(parent context.Context) error {
	if parent.Err() != nil {
		return nil
	}
	slog.Info("dns_filter starting", "addr", p.Config.ListenAddr, "metrics", p.Config.MetricsAddr)

	// Bind every listener before serving. A failed bind must not leave a
	// partially running DNS service or a healthy-looking metrics endpoint.
	var lc net.ListenConfig
	tcp, err := lc.Listen(parent, "tcp", p.Config.ListenAddr)
	if err != nil {
		return fmt.Errorf("tcp listener failed: %w", err)
	}
	defer tcp.Close()
	udpAddr := p.Config.ListenAddr
	host, port, _ := net.SplitHostPort(udpAddr)
	if port == "0" {
		_, port, _ = net.SplitHostPort(tcp.Addr().String())
		udpAddr = net.JoinHostPort(host, port)
	}
	udp, err := lc.ListenPacket(parent, "udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp listener failed: %w", err)
	}
	defer udp.Close()

	var metricsListener net.Listener
	var metricsServer *http.Server
	if p.Config.MetricsAddr != "" {
		metricsListener, err = lc.Listen(parent, "tcp", p.Config.MetricsAddr)
		if err != nil {
			return fmt.Errorf("metrics listener failed: %w", err)
		}
		defer metricsListener.Close()
		metricsServer = &http.Server{
			Handler:           p.metricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
	}

	g, ctx := errgroup.WithContext(parent)
	timeout := p.Config.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		p.resolveRequest(ctx, w, r)
	})
	listeners := []struct {
		name    string
		server  *dns.Server
		started chan struct{}
		done    chan struct{}
	}{
		{"udp", &dns.Server{PacketConn: udp, UDPSize: dns.DefaultMsgSize, ReadTimeout: timeout, WriteTimeout: timeout, Handler: handler}, make(chan struct{}), make(chan struct{})},
		{"tcp", &dns.Server{Listener: tcp, ReadTimeout: timeout, WriteTimeout: timeout, Handler: handler}, make(chan struct{}), make(chan struct{})},
	}
	for _, listener := range listeners {
		listener.server.NotifyStartedFunc = func() { close(listener.started) }
		g.Go(func() error {
			defer close(listener.done)
			if err := listener.server.ActivateAndServe(); err != nil {
				return fmt.Errorf("%s server failed: %w", listener.name, err)
			}
			return nil
		})
	}
	if metricsServer != nil {
		g.Go(func() error {
			// Health checks become available only after both DNS servers start.
			for _, listener := range listeners {
				select {
				case <-listener.started:
				case <-ctx.Done():
					return nil
				}
			}
			if err := metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("metrics server failed: %w", err)
			}
			return nil
		})
	}
	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var shutdownErrors []error
		if metricsServer != nil {
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				_ = metricsServer.Close()
				shutdownErrors = append(shutdownErrors, fmt.Errorf("metrics shutdown: %w", err))
			}
		}
		for _, listener := range listeners {
			// ShutdownContext must not race ahead of ActivateAndServe.
			select {
			case <-listener.started:
				if err := listener.server.ShutdownContext(shutdownCtx); err != nil {
					shutdownErrors = append(shutdownErrors, fmt.Errorf("%s shutdown: %w", listener.name, err))
				}
			case <-listener.done:
			}
		}
		return errors.Join(shutdownErrors...)
	})
	return g.Wait()
}

func (p *DNSFilter) Resolve(w dns.ResponseWriter, r *dns.Msg) {
	p.resolveRequest(context.Background(), w, r)
}

func (p *DNSFilter) resolveRequest(parent context.Context, w dns.ResponseWriter, r *dns.Msg) {
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
	// Apply access control before cache lookup or any upstream work. Loopback
	// is always available for the host's own resolver; other clients need an
	// explicit network grant in the configuration.
	if !p.Config.allowsClient(w.RemoteAddr()) {
		_ = writeDNSResponse(w, r, new(dns.Msg).SetRcode(r, dns.RcodeRefused))
		return
	}

	timeout := p.Config.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
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
	cacheKey := p.Cache.GenerateRequestKey(r)
	if cachedMsg := p.Cache.Get(cacheKey); cachedMsg != nil {
		reqLogger.Debug("cache hit")
		atomic.AddUint64(&p.stats.CacheHits, 1)
		cachedMsg.Id = r.Id // Restore ID to match request
		if err := writeDNSResponse(w, r, cachedMsg); err != nil {
			reqLogger.Error("write_msg failed", "error", err)
		}
		return
	}

	resolvedMsg, err := p.resolveQuery(ctx, r, reqLogger)
	if err != nil {
		atomic.AddUint64(&p.stats.ErrorsTotal, 1)
		reqLogger.Error("resolve_domain failed", "error", err)
		dnsErr := new(dns.Msg)
		dnsErr.SetRcode(r, dns.RcodeServerFailure)
		_ = writeDNSResponse(w, r, dnsErr)
		return
	}

	// The cache validates positive and SOA-backed negative responses.
	p.Cache.Set(cacheKey, resolvedMsg)

	if err := writeDNSResponse(w, r, resolvedMsg); err != nil {
		reqLogger.Error("write_msg failed", "error", err)
	}
}

// writeDNSResponse applies the current client's EDNS and transport limits to
// both fresh and cached answers. The cache owns a separate, complete copy.
func writeDNSResponse(w dns.ResponseWriter, request, response *dns.Msg) error {
	size := dns.MinMsgSize
	if opt := request.IsEdns0(); opt != nil {
		size = min(maxUDPPayloadSize, max(dns.MinMsgSize, int(opt.UDPSize())))
		if response.IsEdns0() == nil {
			response.SetEdns0(maxUDPPayloadSize, opt.Do())
		} else {
			response.IsEdns0().SetUDPSize(maxUDPPayloadSize)
		}
	} else {
		// An OPT record describes this exchange, not a previous upstream one.
		extra := response.Extra[:0]
		for _, rr := range response.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				extra = append(extra, rr)
			}
		}
		response.Extra = extra
		if response.Rcode > 0xf {
			response = new(dns.Msg).SetRcode(request, dns.RcodeServerFailure)
		}
	}
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		response.Truncate(size)
	}
	return w.WriteMsg(response)
}

// ResolveDomain is a convenience method for an IN A lookup.
func (p *DNSFilter) ResolveDomain(ctx context.Context, domain string, originalMsgID uint16, logger *slog.Logger) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Id = originalMsgID
	return p.resolveQuery(ctx, m, logger)
}

// resolveQuery preserves the client's question and flags throughout resolution.
func (p *DNSFilter) resolveQuery(ctx context.Context, request *dns.Msg, logger *slog.Logger) (*dns.Msg, error) {
	m := request.Copy()

	if whitelistedMsg, matched, err := p.checkWhitelist(ctx, m.Question[0].Name, m, logger); matched {
		return whitelistedMsg, err
	}
	// Ask filtering upstreams for EDE even for legacy clients. The downstream
	// writer removes OPT when the client did not request EDNS. Signed queries
	// cannot be altered without invalidating their authentication.
	if (p.Config.FilterAds || p.Config.FilterMalware || p.Config.FilterPorn) && m.IsEdns0() == nil && m.IsTsig() == nil {
		m.SetEdns0(maxUDPPayloadSize, false)
	}

	firstResolver, err := p.getPrimaryResolver()
	if err != nil {
		return nil, err
	}

	return p.resolveConcurrently(ctx, m, firstResolver, logger)
}

func (p *DNSFilter) checkWhitelist(ctx context.Context, domain string, m *dns.Msg, logger *slog.Logger) (*dns.Msg, bool, error) {
	domain = dns.CanonicalName(domain)
	for _, whitelistedDomain := range p.Config.Whitelist {
		if domain == dns.CanonicalName(whitelistedDomain) {
			unfilteredResolver := p.Config.Resolvers["resolver_unfiltered"]
			if unfilteredResolver == nil {
				return nil, true, errors.New("resolver_unfiltered not found for whitelisted domain")
			}

			logger.Info("domain is whitelisted", "resolver", unfilteredResolver.Name)

			result := resolveSafely(ctx, unfilteredResolver, m, logger)
			if result.err != nil {
				return nil, true, fmt.Errorf("failed to resolve whitelisted domain: %w", result.err)
			}
			return result.msg, true, nil
		}
	}
	return nil, false, nil
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

	if !exists || resolver == nil {
		return nil, fmt.Errorf("configured primary resolver not found")
	}
	return resolver, nil
}

type resolveResult struct {
	msg         *dns.Msg
	gotFiltered bool
	err         error
	receivedAt  time.Time
}

func ageResolveResults(results []resolveResult) {
	for i := range results {
		if results[i].msg != nil && results[i].msg.IsTsig() == nil {
			// Include time spent waiting for the other resolver in this TTL.
			results[i].msg = results[i].msg.Copy()
			ageResponseTTL(results[i].msg, uint64(max(0, time.Since(results[i].receivedAt)/time.Second)))
		}
	}
}

func resolveSafely(ctx context.Context, resolver *Resolver, m *dns.Msg, logger *slog.Logger) (result resolveResult) {
	if resolver == nil {
		return resolveResult{err: errors.New("resolver is missing")}
	}
	logger = logger.With("resolver", resolver.Name)
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("panic in resolver", "err", rec)
			result = resolveResult{err: fmt.Errorf("panic in resolver: %v", rec)}
		}
	}()
	result.msg, result.gotFiltered, result.err = resolver.resolve(ctx, m.Copy(), logger)
	result.receivedAt = time.Now()
	return result
}

func (p *DNSFilter) resolveConcurrently(ctx context.Context, m *dns.Msg, primary *Resolver, logger *slog.Logger) (*dns.Msg, error) {
	resolvers := []*Resolver{primary}
	if p.Config.FilterAds {
		ads := p.Config.Resolvers["resolver_anti_ads"]
		if ads == nil {
			return nil, errors.New("resolver_anti_ads not found")
		}
		resolvers = append(resolvers, ads)
	}

	// Each resolver shares the request deadline, but an individual error must
	// not cancel another resolver's verdict. Completion order is not policy.
	results := make([]resolveResult, len(resolvers))
	var wg sync.WaitGroup
	for i, resolver := range resolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = resolveSafely(ctx, resolver, m, logger)
		}()
	}
	wg.Wait()
	ageResolveResults(results)

	// A confirmed block is safe to return even when another upstream failed.
	for _, result := range results {
		if result.gotFiltered {
			atomic.AddUint64(&p.stats.BlockedTotal, 1)
			return result.msg, nil
		}
	}
	for i, result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("resolver %s failed: %w", resolvers[i].Name, result.err)
		}
	}
	primaryMsg := results[0].msg
	// Preserve negative/error RCODEs from the primary. An ads resolver's error
	// response, however, must never authorize a successful primary response.
	if primaryMsg.Rcode == dns.RcodeSuccess && p.Config.FilterAds {
		adsMsg := results[1].msg
		if adsMsg.Rcode != dns.RcodeSuccess || adsMsg.Truncated {
			return nil, fmt.Errorf("ads filter did not complete: rcode=%s truncated=%t", dns.RcodeToString[adsMsg.Rcode], adsMsg.Truncated)
		}
		if primaryMsg.IsTsig() != nil {
			return nil, errors.New("cannot combine a signed response with an ads filter verdict")
		}
		primaryTTL, _ := responseTTL(primaryMsg)
		adsTTL, _ := responseTTL(adsMsg)
		// A verdict without a cacheable lifetime authorizes only this lookup.
		limitResponseTTL(primaryMsg, min(primaryTTL, adsTTL))
	}
	return primaryMsg, nil
}

// Config Definitions

type Config struct {
	ListenAddr     string        `yaml:"listen_addr"`
	MetricsAddr    string        `yaml:"metrics_addr"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
	CacheSize      int           `yaml:"cache_size"`
	AllowedClients []string      `yaml:"allowed_clients"`
	clientNetworks []*net.IPNet

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
	if c == nil {
		return errors.New("config is required")
	}
	if err := validateListenAddress(c.ListenAddr); err != nil {
		return fmt.Errorf("invalid listen_addr: %w", err)
	}
	if c.MetricsAddr != "" {
		if err := validateListenAddress(c.MetricsAddr); err != nil {
			return fmt.Errorf("invalid metrics_addr: %w", err)
		}
	}
	if c.RequestTimeout < 0 {
		return errors.New("request_timeout must be positive or zero for the default")
	}
	if c.CacheSize < 0 {
		return errors.New("cache_size must be positive or zero for the default")
	}
	primary := "resolver_unfiltered"
	if c.FilterPorn {
		primary = "resolver_anti_porn"
	} else if c.FilterMalware {
		primary = "resolver_anti_malware"
	}
	required := []string{primary}
	if c.FilterAds {
		required = append(required, "resolver_anti_ads")
	}
	if len(c.Whitelist) != 0 {
		required = append(required, "resolver_unfiltered")
	}
	for _, name := range required {
		if c.Resolvers[name] == nil {
			return fmt.Errorf("required resolver %s is missing or null", name)
		}
	}
	var networks []*net.IPNet
	for _, cidr := range c.AllowedClients {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid allowed_clients network %q: %w", cidr, err)
		}
		networks = append(networks, network)
	}
	c.clientNetworks = networks
	for name, resolver := range c.Resolvers {
		if resolver == nil {
			return fmt.Errorf("resolver %s must not be null", name)
		}
		if err := resolver.LoadAndValidate(false); err != nil {
			return fmt.Errorf("resolver %s failed validation: %w", name, err)
		}
	}
	// DNS name comparisons are case-insensitive; keep the client's wire name
	// intact and canonicalize only the lookup keys.
	for i, domain := range c.Whitelist {
		if _, valid := dns.IsDomainName(domain); domain == "" || !valid {
			return fmt.Errorf("invalid whitelist domain %q", domain)
		}
		c.Whitelist[i] = dns.CanonicalName(domain)
	}
	return nil
}

func validateListenAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("listener host must be an IP address: %w", err)
		}
	}
	// Port zero is useful for callers requesting an ephemeral listener.
	_, err = strconv.ParseUint(port, 10, 16)
	return err
}

func (c *Config) allowsClient(addr net.Addr) bool {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ip = addr.IP
	case *net.TCPAddr:
		ip = addr.IP
	default:
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, network := range c.clientNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
