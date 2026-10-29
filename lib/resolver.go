package lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// dnsExchanger defines an interface for a DNS client, allowing for mocking in tests.
type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
}

// realDNSClient wraps a real *dns.Client to satisfy the dnsExchanger interface.
type realDNSClient struct {
	client *dns.Client
}

func (c *realDNSClient) ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error) {
	r, rtt, err = c.client.ExchangeContext(ctx, m, a)
	if err == nil && r != nil && r.Truncated && c.client.Net == "udp" {
		// A UDP upstream may need TCP for a complete DNS response.
		tcp := *c.client
		tcp.Net = "tcp"
		var tcpRTT time.Duration
		r, tcpRTT, err = tcp.ExchangeContext(ctx, m, a)
		rtt += tcpRTT
	}
	return r, rtt, err
}

// Resolver Definitions

type Resolver struct {
	dnsClient     dnsExchanger `yaml:"-"`
	httpsClient   *http.Client `yaml:"-"`
	Name          string       `yaml:"name"`
	Addr          string       `yaml:"addr"`
	URL           string       `yaml:"url"`
	Protocol      string       `yaml:"protocol"`
	TLSServerName string       `yaml:"tls_server_name"`
}

func (resolver *Resolver) LoadAndValidate(isTest bool) error {
	if resolver == nil {
		return errors.New("resolver must not be null")
	}
	if err := validateAddrWithPort(resolver.Addr, isTest); err != nil {
		return err
	}
	protocol := resolver.Protocol
	if protocol == "" {
		// Preserve existing encrypted configurations. Plain DNS requires an
		// explicit choice, so an upgrade cannot silently downgrade transport.
		protocol = "tls"
		if resolver.URL != "" {
			protocol = "https"
		}
	}
	switch protocol {
	case "https":
		if resolver.URL == "" {
			return errors.New("protocol https requires a DoH URL")
		}
	case "udp", "tcp", "tls":
		if resolver.URL != "" {
			return fmt.Errorf("protocol %s must not specify a DoH URL", protocol)
		}
	default:
		return fmt.Errorf("unsupported resolver protocol %q (use udp, tcp, tls or https)", protocol)
	}
	resolver.Protocol = protocol

	if resolver.URL != "" {
		parsed, err := url.ParseRequestURI(resolver.URL)
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
		if parsed.Hostname() == "" || (parsed.Scheme != "https" && !(isTest && parsed.Scheme == "http")) {
			return errors.New("DoH URL must be an absolute HTTPS URL")
		}

		// LOOP PREVENTION & SECURITY:
		// We explicitly define the DialContext. This forces the HTTP client to connect
		// directly to the IP address specified in resolver.Addr (e.g., 1.1.1.1:443),
		// ignoring system DNS. This allows the server to use 127.0.0.1 (itself)
		// as the system resolver without creating an infinite loop.
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// addr here would normally be "dns.adguard-dns.com:443" derived from URL.
				// We overwrite it with resolver.Addr (e.g., "94.140.15.15:853").
				return dialer.DialContext(ctx, network, resolver.Addr)
			},
			TLSClientConfig: &tls.Config{
				// Ensure we verify the certificate against the Hostname in the URL, NOT the IP.
				ServerName: resolver.TLSServerName,
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		}

		resolver.httpsClient = &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" && !(isTest && req.URL.Scheme == "http") {
					return errors.New("DoH redirect must use HTTPS")
				}
				if len(via) >= 10 {
					return errors.New("too many DoH redirects")
				}
				return nil
			},
		}
	} else {
		if resolver.dnsClient == nil {
			network := protocol
			if protocol == "tls" {
				network = "tcp-tls"
			}
			client := &dns.Client{
				Net:       network,
				Timeout:   5 * time.Second,
				TLSConfig: &tls.Config{ServerName: resolver.TLSServerName},
			}
			resolver.dnsClient = &realDNSClient{client: client}
		}
	}
	return nil
}

func (resolver *Resolver) exchange(ctx context.Context, m *dns.Msg, logger *slog.Logger) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg

	if resolver.URL != "" {
		resp, err = resolver.makeHTTPSRequest(ctx, m, logger)
		if err != nil {
			logger.Error("doh_exchange failed", "error", err)
			return nil, fmt.Errorf("doh exchange failed: %w", err)
		}
	} else {
		resp, _, err = resolver.dnsClient.ExchangeContext(ctx, m, resolver.Addr)
		if err != nil {
			logger.Error("dns_exchange failed", "error", err)
			return nil, fmt.Errorf("dns exchange failed: %w", err)
		}
	}

	return resp, nil
}

func (resolver *Resolver) resolve(ctx context.Context, m *dns.Msg, logger *slog.Logger) (*dns.Msg, bool, error) {
	resp, err := resolver.exchangeWithCookies(ctx, m, logger)
	if err != nil {
		return nil, false, err
	}
	if resp == nil {
		return nil, false, errors.New("resolver returned nil response")
	}
	normalizeNegativeTTL(resp)

	if resp.Rcode == dns.RcodeNameError {
		logger.Info("blocked", "reason", "NXDOMAIN")
		return resp, true, nil
	}
	// Filtering resolvers can return NOERROR with an empty answer for TXT,
	// MX, HTTPS, etc. Their EDE policy signal is independent of the RCODE.
	if opt := resp.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if ede, ok := option.(*dns.EDNS0_EDE); ok {
				switch ede.InfoCode {
				case dns.ExtendedErrorCodeBlocked, dns.ExtendedErrorCodeCensored,
					dns.ExtendedErrorCodeFiltered, dns.ExtendedErrorCodeProhibited:
					logger.Info("blocked", "ede", ede.InfoCode, "reason", ede.ExtraText)
					return resp, true, nil
				}
			}
		}
	}

	for _, rr := range resp.Answer {
		var ip net.IP
		switch answer := rr.(type) {
		case *dns.A:
			ip = answer.A
		case *dns.AAAA:
			ip = answer.AAAA
		}
		if ip.IsUnspecified() {
			logger.Info("blocked", "reason", ip.String())
			return resp, true, nil
		}
	}
	return resp, false, nil
}

func (resolver *Resolver) makeHTTPSRequest(ctx context.Context, reqMsg *dns.Msg, logger *slog.Logger) (*dns.Msg, error) {
	wire, err := reqMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", resolver.URL, bytes.NewBuffer(wire))
	if err != nil {
		return nil, fmt.Errorf("http request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Host header is automatically set by NewRequest based on resolver.URL.

	resp, err := resolver.httpsClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	if resp.ContentLength > dns.MaxMsgSize {
		return nil, errors.New("DoH response exceeds maximum DNS message size")
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	if len(respBody) > dns.MaxMsgSize {
		return nil, errors.New("DoH response exceeds maximum DNS message size")
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("unpack failed: %w", err)
	}
	normalizeNegativeTTL(respMsg)
	// RFC 8484 section 5.1: HTTP cache residence counts against every DNS
	// record's remaining lifetime. OPT's TTL field contains protocol flags.
	if value := resp.Header.Get("Age"); value != "" {
		age, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP Age header: %w", err)
		}
		ageResponseTTL(respMsg, age)
	}
	// The upstream response already contains its status and flags. Only restore
	// the transaction ID, which a DoH server may replace with zero.
	respMsg.Id = reqMsg.Id

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
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	if portNumber == 0 {
		return errors.New("upstream port must not be zero")
	}
	if isTest {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("host '%s' is not a valid IP address", host)
	}
	return nil
}
