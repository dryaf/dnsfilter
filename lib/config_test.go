package lib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRejectsUnusableConfigurations(t *testing.T) {
	base := "listen_addr: 127.0.0.1:0\nresolver_unfiltered:\n  addr: 127.0.0.1:853\n"
	for name, config := range map[string]string{
		"no resolvers":                 "listen_addr: 127.0.0.1:0\n",
		"missing malware resolver":     base + "filter_malware: true\n",
		"missing porn resolver":        base + "filter_porn: true\n",
		"missing ads resolver":         base + "filter_ads: true\n",
		"whitelist without unfiltered": "listen_addr: 127.0.0.1:0\nfilter_malware: true\nwhitelist: [example.com]\nresolver_anti_malware:\n  addr: 127.0.0.1:853\n",
		"null primary":                 "listen_addr: 127.0.0.1:0\nresolver_unfiltered: null\n",
		"null unused resolver":         base + "resolver_unused: null\n",
		"negative timeout":             base + "request_timeout: -1s\n",
		"duplicate timeout":            base + "request_timeout: 1s\nrequest_timeout: 2s\n",
		"negative capacity":            base + "cache_size: -1\n",
		"invalid listener":             strings.Replace(base, "127.0.0.1:0", "127.0.0.1:99999", 1),
		"missing listener":             strings.TrimPrefix(base, "listen_addr: 127.0.0.1:0\n"),
		"invalid metrics":              base + "metrics_addr: 127.0.0.1:not-a-port\n",
		"invalid client network":       base + "allowed_clients: [10.0.0.0/33]\n",
		"empty whitelist domain":       base + "whitelist: ['']\n",
		"invalid whitelist domain":     base + "whitelist: ['example..com']\n",
		"plaintext DoH":                base + "  url: http://resolver.example/dns-query\n",
		"relative DoH URL":             base + "  url: /dns-query\n",
		"zero upstream port":           strings.Replace(base, "127.0.0.1:853", "127.0.0.1:0", 1),
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(file, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDNSFilter(file, ""); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestConfigAcceptsSupportedResolverSelections(t *testing.T) {
	for name, extra := range map[string]string{
		"unfiltered":            "resolver_unfiltered:\n  addr: 127.0.0.1:853\n",
		"malware only":          "filter_malware: true\nresolver_anti_malware:\n  addr: 127.0.0.1:853\n",
		"porn includes malware": "filter_porn: true\nfilter_malware: true\nresolver_anti_porn:\n  addr: 127.0.0.1:853\n",
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(file, []byte("listen_addr: 127.0.0.1:0\n"+extra), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDNSFilter(file, ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}
