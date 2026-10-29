package lib

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"

	"github.com/miekg/dns"
)

func firstCookie(msg *dns.Msg) *dns.EDNS0_COOKIE {
	if msg == nil {
		return nil
	}
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
				return cookie
			}
		}
	}
	return nil
}

func decodeCookie(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || (len(decoded) != 8 && (len(decoded) < 16 || len(decoded) > 40)) {
		return nil, errors.New("invalid DNS cookie")
	}
	return decoded, nil
}

func responseCookie(msg *dns.Msg, clientCookie string) (string, error) {
	cookie := firstCookie(msg)
	if cookie == nil {
		return "", nil // Upstreams without cookie support remain usable.
	}
	decoded, err := decodeCookie(cookie.Cookie)
	if err != nil || len(decoded) < 16 || hex.EncodeToString(decoded[:8]) != clientCookie {
		return "", errors.New("upstream returned an invalid or mismatched DNS cookie")
	}
	return hex.EncodeToString(decoded), nil
}

// A downstream server cookie belongs to whichever upstream answered the last
// query. Start each independent upstream exchange with only the client cookie;
// any challenge is answered using that upstream's cookie, under the same deadline.
func (resolver *Resolver) exchangeWithCookies(ctx context.Context, request *dns.Msg, logger *slog.Logger) (*dns.Msg, error) {
	if firstCookie(request) == nil || request.IsTsig() != nil {
		return resolver.exchange(ctx, request, logger)
	}
	query := request.Copy()
	cookie := firstCookie(query)
	decoded, err := decodeCookie(cookie.Cookie)
	if err != nil {
		return nil, err
	}
	clientCookie := hex.EncodeToString(decoded[:8])
	cookie.Cookie = clientCookie
	// RFC 7873 considers only the first COOKIE option.
	options := query.IsEdns0().Option[:0]
	for _, option := range query.IsEdns0().Option {
		if other, ok := option.(*dns.EDNS0_COOKIE); !ok || other == cookie {
			options = append(options, option)
		}
	}
	query.IsEdns0().Option = options
	for attempt := 0; attempt < 2; attempt++ {
		reply, err := resolver.exchange(ctx, query, logger)
		if err != nil || reply == nil {
			return reply, err
		}
		serverCookie, err := responseCookie(reply, clientCookie)
		if err != nil {
			return nil, err
		}
		if reply.Rcode != dns.RcodeBadCookie {
			return reply, nil
		}
		if serverCookie == "" || reply.IsTsig() != nil {
			return nil, errors.New("upstream BADCOOKIE response has no usable cookie")
		}
		cookie.Cookie = serverCookie
	}
	return nil, errors.New("upstream rejected its own DNS cookie")
}
