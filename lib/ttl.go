package lib

import (
	"math"

	"github.com/miekg/dns"
)

// negativeResponse includes CNAME chains that do not end in the requested RRset.
func negativeResponse(msg *dns.Msg) bool {
	if msg.Rcode == dns.RcodeNameError || len(msg.Answer) == 0 {
		return true
	}
	if len(msg.Question) != 1 {
		return false
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == msg.Question[0].Qtype || msg.Question[0].Qtype == dns.TypeANY {
			return false
		}
	}
	return true
}

// responseTTL bounds a complete response by all of its records. Negative
// answers need a SOA; its MINIMUM also limits their lifetime (RFC 2308).
func responseTTL(msg *dns.Msg) (uint32, bool) {
	if msg == nil || msg.Truncated || msg.IsTsig() != nil || (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) {
		return 0, false
	}
	ttl := uint32(math.MaxUint32)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				ttl = min(ttl, rr.Header().Ttl)
			}
		}
	}
	if !negativeResponse(msg) {
		return ttl, true
	}
	foundSOA := false
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			foundSOA = true
			ttl = min(ttl, soa.Minttl)
		}
	}
	if !foundSOA {
		return 0, false
	}
	return ttl, true
}

func normalizeNegativeTTL(msg *dns.Msg) {
	if msg.IsTsig() != nil || !negativeResponse(msg) {
		return
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
}

func limitResponseTTL(msg *dns.Msg, ttl uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = min(rr.Header().Ttl, ttl)
			}
		}
	}
}

func ageResponseTTL(msg *dns.Msg, seconds uint64) {
	if seconds > math.MaxUint32 {
		limitResponseTTL(msg, 0)
		return
	}
	age := uint32(seconds)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				hdr := rr.Header()
				hdr.Ttl -= min(hdr.Ttl, age)
			}
		}
	}
}
