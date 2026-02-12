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
	"strconv"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
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
	return c.client.ExchangeContext(ctx, m, a)
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

		// LOOP PREVENTION & SECURITY:
		// We explicitly define the DialContext. This forces the HTTP client to connect
		// directly to the IP address specified in resolver.Addr (e.g., 1.1.1.1:443),
		// ignoring system DNS. This allows the server to use 127.0.0.1 (itself)
		// as the system resolver without creating an infinite loop.
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// addr here would normally be "dns.adguard-dns.com:443" derived from URL.
				// We overwrite it with resolver.Addr (e.g., "94.140.15.15:853").
				return net.Dial(network, resolver.Addr)
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
		}
	} else {
		// Standard DNS Client
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

	// Host header is automatically set by NewRequest based on rs.URL

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
