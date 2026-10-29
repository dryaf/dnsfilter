package lib

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// CheckDNS verifies that both local DNS transports can resolve the root NS set.
// It uses the same unavailable-address fallback as the service and binds the
// probe's source to loopback, which is always permitted by the client ACL.
func CheckDNS(ctx context.Context, address string) error {
	if err := validateListenAddress(address); err != nil {
		return err
	}
	address = checkAndFallbackIP(address, "udp")
	host, port, _ := net.SplitHostPort(address)
	if port == "0" {
		return fmt.Errorf("cannot probe an ephemeral DNS port")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	address = net.JoinHostPort(host, port)
	source := net.IPv4(127, 0, 0, 1)
	if net.ParseIP(host).To4() == nil {
		source = net.IPv6loopback
	}
	for _, network := range []string{"udp", "tcp"} {
		if err := probeDNSNetwork(ctx, network, address, source); err != nil {
			return err
		}
	}
	return nil
}

func probeDNSNetwork(ctx context.Context, network, address string, source net.IP) error {
	var local net.Addr = &net.UDPAddr{IP: source}
	if network == "tcp" {
		local = &net.TCPAddr{IP: source}
	}
	client := &dns.Client{Net: network, Timeout: 2 * time.Second, Dialer: &net.Dialer{LocalAddr: local}}
	query := new(dns.Msg).SetQuestion(".", dns.TypeNS)
	query.SetEdns0(maxUDPPayloadSize, false)
	reply, _, err := client.ExchangeContext(ctx, query, address)
	if err != nil {
		return fmt.Errorf("%s DNS probe failed: %w", network, err)
	}
	if reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Question) != 1 || reply.Question[0] != query.Question[0] {
		return fmt.Errorf("%s DNS probe did not receive a successful complete answer", network)
	}
	// Truncation is a valid UDP result. The caller still requires the following
	// TCP probe to return a complete answer, as an ordinary DNS client would.
	if network == "udp" && reply.Truncated {
		return nil
	}
	if reply.Truncated || len(reply.Answer) == 0 {
		return fmt.Errorf("%s DNS probe did not receive a complete answer", network)
	}
	return nil
}
