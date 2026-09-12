package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseAllowedCIDRsDefaultsToLoopback(t *testing.T) {
	prefixes, err := parseAllowedCIDRs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isClientAllowed(netip.MustParseAddr("127.0.0.1"), prefixes) {
		t.Fatal("expected IPv4 loopback to be allowed by default")
	}
	if !isClientAllowed(netip.MustParseAddr("::1"), prefixes) {
		t.Fatal("expected IPv6 loopback to be allowed by default")
	}
	if isClientAllowed(netip.MustParseAddr("192.168.1.10"), prefixes) {
		t.Fatal("expected private LAN address to be denied by default")
	}
	if isClientAllowed(netip.MustParseAddr("8.8.8.8"), prefixes) {
		t.Fatal("expected public address to be denied by default")
	}
}

func TestParseAllowedCIDRsCustomNetworks(t *testing.T) {
	prefixes, err := parseAllowedCIDRs([]string{"192.168.0.0/16", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isClientAllowed(netip.MustParseAddr("192.168.100.6"), prefixes) {
		t.Fatal("expected configured IPv4 client to be allowed")
	}
	if !isClientAllowed(netip.MustParseAddr("2001:db8::1234"), prefixes) {
		t.Fatal("expected configured IPv6 client to be allowed")
	}
	if isClientAllowed(netip.MustParseAddr("10.0.0.1"), prefixes) {
		t.Fatal("expected address outside allowlist to be denied")
	}
}

func TestParseAllowedCIDRsRejectsInvalidValue(t *testing.T) {
	if _, err := parseAllowedCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR to fail")
	}
	if _, err := parseAllowedCIDRs([]string{""}); err == nil {
		t.Fatal("expected empty CIDR to fail")
	}
}

func TestParseAllowedCIDRsNormalizesIPv4MappedPrefix(t *testing.T) {
	prefixes, err := parseAllowedCIDRs([]string{"::ffff:192.0.2.0/120"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isClientAllowed(netip.MustParseAddr("192.0.2.25"), prefixes) {
		t.Fatal("expected IPv4-mapped prefix to match unmapped IPv4 client")
	}
}

func TestNormalizePrefixKeepsBroadIPv4MappedIPv6PrefixValid(t *testing.T) {
	prefix := netip.MustParsePrefix("::ffff:0:0/80")
	normalized := normalizePrefix(prefix)
	if !normalized.IsValid() {
		t.Fatal("expected broad IPv6 prefix to remain valid")
	}
	if normalized.Bits() != 80 {
		t.Fatalf("expected /80 prefix to remain IPv6 /80, got /%d", normalized.Bits())
	}
}

func TestClientIPFromAddr(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}
	got, err := clientIPFromAddr(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := netip.MustParseAddr("127.0.0.1"); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestQuerySlotAdmission(t *testing.T) {
	slots := make(chan struct{}, 1)
	if !tryAcquireQuerySlot(slots) {
		t.Fatal("expected first query to acquire slot")
	}
	if tryAcquireQuerySlot(slots) {
		t.Fatal("expected full query limit to reject additional query")
	}
	releaseQuerySlot(slots)
	if !tryAcquireQuerySlot(slots) {
		t.Fatal("expected slot to become available after release")
	}
	releaseQuerySlot(slots)
}

func TestBuildRuntimeUsesSafeAccessDefaults(t *testing.T) {
	var cfg Config
	cfg.Server.CacheExpiration = "1m"
	cfg.Upstream.DNSServers = []string{"8.8.8.8"}

	rt, err := buildRuntimeFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap(rt.querySlots) != 256 {
		t.Fatalf("expected default max concurrent queries 256, got %d", cap(rt.querySlots))
	}
	if !isClientAllowed(netip.MustParseAddr("127.0.0.1"), rt.allowCIDRs) {
		t.Fatal("expected runtime default allowlist to permit loopback")
	}
	if isClientAllowed(netip.MustParseAddr("192.168.1.1"), rt.allowCIDRs) {
		t.Fatal("expected runtime default allowlist to reject LAN clients")
	}
}

func TestValidateConfigRejectsNegativeConcurrencyLimit(t *testing.T) {
	var cfg Config
	cfg.Server.Address = "127.0.0.1:53"
	cfg.Server.CacheExpiration = "1m"
	cfg.Server.MaxConcurrentQueries = -1
	cfg.Upstream.DNSServers = []string{"8.8.8.8"}

	if err := validateConfig(&cfg); err == nil {
		t.Fatal("expected negative max_concurrent_queries to fail validation")
	}
}
