package lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
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

// dnsExchanger defines an interface for a DNS client, allowing for mocking in tests.
type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
}

// realDNSClient wraps a real *dns.Client to satisfy the dnsExchanger interface.
type realDNSClient struct {
	client *dns.Client
}

func (c *realDNSClient) ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error) {
	return c.client.ExchangeContext(ctx, m, a)
}

type DNSFilter struct {
	Config *Config
}

func NewDNSFilter(configFile, listenAddr string) (*DNSFilter, error) {
	if configFile == "" {
		return nil, errors.New("config file path is required")
	}

	config, err := ConfigFromFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("could not load config from file: %w", err)
	}

	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}

	if err = config.Validate(); err != nil {
		return nil, fmt.Errorf("could not validate config: %w", err)
	}

	return &DNSFilter{Config: config}, nil
}

func (p *DNSFilter) Run() error {
	slog.Info("dns_filter starting",
		"addr", p.Config.ListenAddr,
		"filter_ads", p.Config.FilterAds,
		"filter_malware", p.Config.FilterMalware,
		"filter_porn", p.Config.FilterPorn)

	// Set default timeouts if not configured
	readTimeout := p.Config.RequestTimeout
	if readTimeout == 0 {
		readTimeout = 5 * time.Second
	}

	server := &dns.Server{
		Addr:         p.Config.ListenAddr,
		Net:          "udp",
		ReadTimeout:  readTimeout,
		WriteTimeout: readTimeout,
	}
	dns.HandleFunc(".", p.Resolve)

	// Create a channel to receive OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := server.ListenAndServe(); err != nil {
			slog.Error("failed to serve", "error", err)
		}
	}()

	<-stop // Wait for SIGINT

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.ShutdownContext(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.Info("gracefully stopped server")
	return nil
}

func (p *DNSFilter) Resolve(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	// 1. Setup Context with Timeout
	timeout := p.Config.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 2. Setup Structured Logger
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	q := r.Question[0]
	reqLogger := slog.With(
		"id", r.Id,
		"domain", q.Name,
		"client_ip", clientIP,
		"type", dns.TypeToString[q.Qtype],
	)

	// 3. Resolve
	resolvedMsg, err := p.ResolveDomain(ctx, q.Name, r.Id, reqLogger)
	if err != nil {
		reqLogger.Error("resolve_domain failed", "error", err)
		dnsErr := new(dns.Msg)
		dnsErr.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(dnsErr)
		return
	}

	// 4. Write Response
	if err := w.WriteMsg(resolvedMsg); err != nil {
		reqLogger.Error("write_msg failed", "error", err)
	}
}

// ResolveDomain handles the core logic: whitelist checking, resolver selection, and concurrent lookups.
func (p *DNSFilter) ResolveDomain(ctx context.Context, domain string, originalMsgID uint16, logger *slog.Logger) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Id = originalMsgID

	// 1. Check Whitelist
	if whitelistedMsg, ok := p.checkWhitelist(ctx, domain, m, logger); ok {
		return whitelistedMsg, nil
	}

	// 2. Select Primary Resolver
	firstResolver, err := p.getPrimaryResolver()
	if err != nil {
		return nil, err
	}

	// 3. Execute Resolution (Primary + Ads concurrently)
	return p.resolveConcurrently(ctx, m, firstResolver, logger)
}

func (p *DNSFilter) checkWhitelist(ctx context.Context, domain string, m *dns.Msg, logger *slog.Logger) (*dns.Msg, bool) {
	for _, whitelistedDomain := range p.Config.Whitelist {
		if domain == whitelistedDomain {
			logger.Info("domain is whitelisted")
			unfilteredResolver, exists := p.Config.Resolvers["resolver_unfiltered"]
			if !exists {
				logger.Error("resolver_unfiltered not found for whitelisted domain")
				return nil, false
			}
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

// resultStruct helps gather concurrent results
type resolveResult struct {
	msg         *dns.Msg
	gotFiltered bool
	err         error
}

func (p *DNSFilter) resolveConcurrently(ctx context.Context, m *dns.Msg, primary *Resolver, logger *slog.Logger) (*dns.Msg, error) {
	g, gctx := errgroup.WithContext(ctx)

	// Channel to capture results. Buffered to avoid blocking goroutines.
	// Index 0: Primary, Index 1: Ads
	results := make([]resolveResult, 2)

	// 1. Primary Resolver
	g.Go(func() error {
		msg, filtered, err := primary.resolve(gctx, m.Copy(), logger.With("resolver", primary.Name))
		results[0] = resolveResult{msg: msg, gotFiltered: filtered, err: err}
		return err // If primary fails, we might want to cancel everything
	})

	// 2. Ads Resolver (Optional)
	if p.Config.FilterAds {
		g.Go(func() error {
			adsResolver, exists := p.Config.Resolvers["resolver_anti_ads"]
			if !exists {
				return fmt.Errorf("resolver_anti_ads not found")
			}
			msg, filtered, err := adsResolver.resolve(gctx, m.Copy(), logger.With("resolver", adsResolver.Name))
			results[1] = resolveResult{msg: msg, gotFiltered: filtered, err: err}
			return err
		})
	}

	// Wait for completion
	_ = g.Wait()
	// Note: We ignore the error from Wait() intentionally here to process partial results or specific logic below,
	// checking results[i].err individually.

	rPrimary := results[0]
	rAds := results[1]

	// Priority 1: Primary blocked content (Malware/Porn)
	if rPrimary.gotFiltered {
		return rPrimary.msg, nil
	}

	// Priority 2: Ads blocked content
	if p.Config.FilterAds && rAds.gotFiltered {
		return rAds.msg, nil
	}

	// Priority 3: Return Primary valid response
	if rPrimary.msg != nil {
		return rPrimary.msg, rPrimary.err
	}

	// Fallback/Error handling
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
	RequestTimeout time.Duration `yaml:"request_timeout"`

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
	return nil
}

// Resolver Definitions

type Resolver struct {
	dnsClient     dnsExchanger `yaml:"-"`
	httpsClient   *http.Client `yaml:"-"`
	Name          string       `yaml:"name"`
	Addr          string       `yaml:"addr"`
	URL           string       `yaml:"url"`
	TLSServerName string       `yaml:"tls_server_name"`
}

func (resolver *Resolver) LoadAndValidate(isTest bool) error {
	if err := validateAddrWithPort(resolver.Addr, isTest); err != nil {
		return err
	}

	if resolver.URL != "" {
		_, err := url.ParseRequestURI(resolver.URL)
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
		resolver.httpsClient = &http.Client{Timeout: 5 * time.Second}
	} else {
		// Initialize DNS client if not already mocked
		if resolver.dnsClient == nil {
			client := &dns.Client{
				Net:       "tcp-tls",
				Timeout:   5 * time.Second,
				TLSConfig: &tls.Config{ServerName: resolver.TLSServerName},
			}
			resolver.dnsClient = &realDNSClient{client: client}
		}
	}
	return nil
}

func (resolver *Resolver) resolve(ctx context.Context, m *dns.Msg, logger *slog.Logger) (*dns.Msg, bool, error) {
	var err error
	var resp *dns.Msg

	if resolver.URL != "" {
		m.SetEdns0(dns.DefaultMsgSize*2, false)
		resp, err = resolver.makeHttpsRequest(ctx, m, logger)
		if err != nil {
			logger.Error("doh_exchange failed", "error", err)
			return nil, false, fmt.Errorf("doh exchange failed: %w", err)
		}
	} else {
		m.SetEdns0(dns.DefaultMsgSize*2, false)
		resp, _, err = resolver.dnsClient.ExchangeContext(ctx, m, resolver.Addr)
		if err != nil {
			logger.Error("dns_exchange failed", "error", err)
			return nil, false, fmt.Errorf("dns exchange failed: %w", err)
		}
	}

	if resp == nil {
		return nil, false, errors.New("resolver returned nil response")
	}

	// Logic to determine if response is a block
	if resp.Rcode == dns.RcodeNameError {
		logger.Info("blocked", "reason", "NXDOMAIN")
		return resp, true, nil
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.A.String() == "0.0.0.0" {
				logger.Info("blocked", "reason", "0.0.0.0")
				return resp, true, nil
			}
		}
	}
	return resp, false, nil
}

func (rs *Resolver) makeHttpsRequest(ctx context.Context, reqMsg *dns.Msg, logger *slog.Logger) (*dns.Msg, error) {
	wire, err := reqMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rs.URL, bytes.NewBuffer(wire))
	if err != nil {
		return nil, fmt.Errorf("http request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-udpwireformat")

	resp, err := rs.httpsClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("unpack failed: %w", err)
	}
	respMsg.SetEdns0(dns.DefaultMsgSize*4, false)
	respMsg.SetReply(reqMsg)

	return respMsg, nil
}

func validateAddrWithPort(addr string, isTest bool) error {
	if addr == "" {
		return errors.New("addr must be set")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("could not parse address: %w", err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	if isTest {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("host '%s' is not a valid IP address", host)
	}
	return nil
}
