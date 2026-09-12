package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfigForTest() Config {
	var cfg Config
	cfg.Server.Address = "127.0.0.1:5353"
	cfg.Server.CacheExpiration = "5m"
	cfg.Upstream.DNSServers = []string{"8.8.8.8:53"}
	return cfg
}

func TestValidateConfigRejectsInvalidRewriteRule(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{name: "unsupported type", rule: Rule{Type: "REGEX", Value: "example.com", Target: "192.0.2.10"}},
		{name: "empty value", rule: Rule{Type: "DOMAIN", Value: "", Target: "192.0.2.10"}},
		{name: "invalid target", rule: Rule{Type: "DOMAIN", Value: "example.com", Target: "not-an-ip"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfigForTest()
			cfg.Rewrite.Rules = []Rule{tc.rule}
			if err := validateConfig(&cfg); err == nil {
				t.Fatal("expected invalid rewrite rule to be rejected")
			}
		})
	}
}

func TestValidateConfigAcceptsSupportedRewriteRules(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Rewrite.Rules = []Rule{
		{Type: "DOMAIN", Value: "example.com", Target: "192.0.2.10"},
		{Type: "DOMAIN-SUFFIX", Value: "example.org", Target: "2001:db8::10"},
		{Type: "RULE-SET", Value: "rules/example.list", Target: "192.0.2.20"},
	}
	if err := validateConfig(&cfg); err != nil {
		t.Fatalf("expected config to be valid: %v", err)
	}
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `server:
  address: "127.0.0.1:5353"
  cache_expiration: 5m
  unknown_option: true
upstream:
  dns_servers:
    - "8.8.8.8:53"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfigFromFile(path)
	if err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown_option") {
		t.Fatalf("expected error to identify unknown field, got: %v", err)
	}
}
