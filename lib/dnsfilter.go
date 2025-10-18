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
		panic("no config.yml")
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
	slog.Info("dns_filter",
		"addr", p.Config.ListenAddr,
		"filter_ads", p.Config.FilterAds,
		"filter_malware", p.Config.FilterMalware,
		"filter_porn", p.Config.FilterPorn)

	server := &dns.Server{Addr: p.Config.ListenAddr, Net: "udp"}
	dns.HandleFunc(".", p.Resolve)

	// Create a channel to receive OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := server.ListenAndServe(); err != nil {
			slog.Error(fmt.Sprintf("failed to serve: %s", err.Error()))
		}
	}()

	<-stop // Wait for SIGINT

	// Call server's Shutdown method with the context
	if err := server.Shutdown(); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.Info("gracefully stopped server")
	return nil
}

func (p *DNSFilter) Resolve(w dns.ResponseWriter, r *dns.Msg) {
	ctx := context.Background() // you should use a real context from your application
	resolvedMsg, err := p.ResolveDomain(ctx, r.Question[0].Name, r.Id)
	if err != nil {
		slog.Error("resolve_domain", err)
		dnsErr := new(dns.Msg)
		dnsErr.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(dnsErr)
		return
	}
	if err := w.WriteMsg(resolvedMsg); err != nil {
		slog.Error("write_msg", err)
	}
}

func (p *DNSFilter) ResolveDomain(ctx context.Context, domain string, originalMsgID uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Id = originalMsgID

	// Check if domain is whitelisted
	for _, whitelistedDomain := range p.Config.Whitelist {
		if domain == whitelistedDomain {
			// Domain is whitelisted, resolve it without filtering
			unfilteredResolver, exists := p.Config.Resolvers["resolver_unfiltered"]
			if !exists {
				return nil, fmt.Errorf("resolver_unfiltered not found")
			}
			m, _, err := unfilteredResolver.resolve(ctx, m, "")
			if err != nil {
				return nil, fmt.Errorf("failed to resolve '%s': %w", domain, err)
			}
			return m, nil
		}
	}

	var firstResolver *Resolver
	var exists bool

	switch {
	case p.Config.FilterPorn:
		firstResolver, exists = p.Config.Resolvers["resolver_anti_porn"]
	case p.Config.FilterMalware:
		firstResolver, exists = p.Config.Resolvers["resolver_anti_malware"]
	default:
		firstResolver, exists = p.Config.Resolvers["resolver_unfiltered"]
	}
	if !exists {
		return nil, fmt.Errorf("configured resolver not found")
	}

	g, gctx := errgroup.WithContext(ctx)

	var m1 *dns.Msg
	var m1_got_filtered bool
	var err1 error

	// Goroutine for the primary resolver (porn/malware/unfiltered)
	g.Go(func() error {
		m1, m1_got_filtered, err1 = firstResolver.resolve(gctx, m.Copy(), "")
		return err1
	})

	var m2 *dns.Msg
	var m2_got_filtered bool
	var err2 error

	// Goroutine for the ads resolver, if enabled
	if p.Config.FilterAds {
		g.Go(func() error {
			antiAdsResolver, exists := p.Config.Resolvers["resolver_anti_ads"]
			if !exists {
				return fmt.Errorf("resolver_anti_ads not found")
			}
			m2, m2_got_filtered, err2 = antiAdsResolver.resolve(gctx, m.Copy(), "")
			return err2
		})
	}

	_ = g.Wait()

	if m1_got_filtered {
		return m1, nil
	}
	if m2_got_filtered {
		return m2, nil
	}

	if p.Config.FilterAds && p.Config.Resolvers["resolver_anti_ads"] == nil {
		return nil, fmt.Errorf("resolver_anti_ads not found")
	}

	var combinedErr error
	if err1 != nil || err2 != nil {
		combinedErr = fmt.Errorf("errors while resolving: %v, %v", err1, err2)
	}

	if m1 == nil && m2 == nil {
		return nil, fmt.Errorf("failed to resolve '%s': domain not found", domain)
	}

	if m1 != nil {
		return m1, combinedErr
	}

	return m2, combinedErr
}

type ResolveError struct {
	Resolver string
	Err      error
}

func (re *ResolveError) Error() string {
	return fmt.Sprintf("resolver '%s' error: %v", re.Resolver, re.Err)
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`

	FilterMalware bool `yaml:"filter_malware"`
	FilterPorn    bool `yaml:"filter_porn"`
	FilterAds     bool `yaml:"filter_ads"`

	Resolvers map[string]*Resolver `yaml:",inline"`

	Whitelist []string `yaml:"whitelist"`
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

type Resolver struct {
	dnsClient     dnsExchanger `yaml:"-"` // Use the interface
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

		resolver.httpsClient = &http.Client{
			Timeout: time.Second * 5,
		}
	} else {
		// In tests, dnsClient will be replaced by a mock.
		if resolver.dnsClient == nil {
			client := &dns.Client{
				Net:     "tcp-tls",
				Timeout: time.Second * 5,
				TLSConfig: &tls.Config{
					ServerName: resolver.TLSServerName,
				},
			}
			resolver.dnsClient = &realDNSClient{client: client} // Wrap the real client
		}
	}

	return nil
}

func (resolver *Resolver) resolve(ctx context.Context, m *dns.Msg, requestingIP string) (*dns.Msg, bool, error) {
	var err error
	var resp *dns.Msg

	if resolver.URL != "" {
		m.SetEdns0(dns.DefaultMsgSize*2, false)
		resp, err = resolver.makeHttpsRequest(ctx, m)
		if err != nil {
			slog.Error(resolver.Name+"_dns_exchange", err, "resolver", resolver.Addr)
			return nil, false, fmt.Errorf("failed to exchange dns context: %w", err)
		}
	} else {
		m.SetEdns0(dns.DefaultMsgSize*2, false)
		resp, _, err = resolver.dnsClient.ExchangeContext(ctx, m, resolver.Addr)
		if err != nil {
			// Context errors are handled by errgroup, so we just check for other errors
			slog.Error(resolver.Name+"_dns_exchange", err, "resolver", resolver.Addr)
			return nil, false, fmt.Errorf("failed to exchange dns context: %w", err)
		}
	}

	if resp == nil {
		return nil, false, errors.New("resolver returned nil response")
	}

	clientValue, ok := ctx.Value("client").(string)
	if !ok {
		clientValue = "unknown"
	}

	if resp.Rcode == dns.RcodeNameError {
		slog.Info("blocked", "domain", m.Question[0].Name, "resolver", resolver.Addr, "client", clientValue, "reason", "NXDOMAIN")
		return resp, true, nil
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.A.String() == "0.0.0.0" {
				slog.Info("blocked", "domain", a.Hdr.Name, "resolver", resolver.Addr, "client", clientValue)
				return resp, true, nil
			}
		}
	}
	return resp, false, nil
}

func (rs *Resolver) makeHttpsRequest(ctx context.Context, reqMsg *dns.Msg) (respMsg *dns.Msg, err error) {
	// ... (implementation is unchanged)
	wire, err := reqMsg.Pack()
	if err != nil {
		slog.Error("dns msg pack", err, "msg", reqMsg)
		return nil, err
	}
	buff := bytes.NewBuffer(wire)
	resp, err := rs.httpsClient.Post(rs.URL, "application/dns-udpwireformat", buff)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		slog.Error("https post", err, "response")
		return nil, err
	}

	if resp.StatusCode != 200 {
		slog.Error("dns_https", err, "response", resp)
		return nil, errors.New("http status not 200")
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("ioutil", err, "body", respBody)
		return nil, err
	}

	respMsg = new(dns.Msg)
	err = respMsg.Unpack(respBody)
	if err != nil {
		slog.Error("respMsg.Unpack", err, "question", reqMsg.Question)
		return nil, err
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
		return nil // Looser validation for tests
	}

	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("host '%s' is not a valid IP address", host)
	}
	return nil
}
