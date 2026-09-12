package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDetermineTTL(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("1.2.3.4")},
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("5.6.7.8")},
	}
	ttl := determineTTL(msg, 30*time.Second)
	if ttl != 120*time.Second {
		t.Fatalf("expected 120s, got %v", ttl)
	}
}

func TestDetermineTTLNegativeFallback(t *testing.T) {
	msg := &dns.Msg{}
	msg.MsgHdr.Rcode = dns.RcodeNameError
	ttl := determineTTL(msg, 45*time.Second)
	if ttl != 45*time.Second {
		t.Fatalf("expected 45s, got %v", ttl)
	}
}

func TestClampTTL(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
		min  time.Duration
		max  time.Duration
		want time.Duration
	}{
		{"below-min", 5 * time.Second, 10 * time.Second, 0, 10 * time.Second},
		{"above-max", 30 * time.Second, 0, 20 * time.Second, 20 * time.Second},
		{"in-range", 15 * time.Second, 10 * time.Second, 20 * time.Second, 15 * time.Second},
	}
	for _, c := range cases {
		if got := clampTTL(c.ttl, c.min, c.max); got != c.want {
			t.Fatalf("%s: expected %v got %v", c.name, c.want, got)
		}
	}
}

func TestParseUpstreamEndpoints(t *testing.T) {
	eps, err := parseUpstreamEndpoints(
		[]string{"8.8.8.8", "tcp://1.1.1.1:54", "tls://1.0.0.1@cloudflare-dns.com", "tls://cloudflare-dns.com"},
		"udp",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(eps) != 4 {
		t.Fatalf("expected 4 endpoints, got %d", len(eps))
	}
	if eps[0].Network != "udp" || eps[0].Address != "8.8.8.8:53" {
		t.Fatalf("unexpected endpoint %#v", eps[0])
	}
	if eps[1].Network != "tcp" || eps[1].Address != "1.1.1.1:54" {
		t.Fatalf("unexpected endpoint %#v", eps[1])
	}
	if eps[2].Network != "tcp-tls" || eps[2].ServerName != "cloudflare-dns.com" || eps[2].Address != "1.0.0.1:853" {
		t.Fatalf("unexpected tls endpoint %#v", eps[2])
	}
	if eps[3].Network != "tcp-tls" || eps[3].ServerName != "cloudflare-dns.com" || eps[3].Address != "cloudflare-dns.com:853" {
		t.Fatalf("unexpected hostname tls endpoint %#v", eps[3])
	}
}

func TestParseUpstreamEndpointsRejectsUnverifiableDoT(t *testing.T) {
	if _, err := parseUpstreamEndpoints([]string{"tls://1.1.1.1"}, "udp"); err == nil {
		t.Fatal("expected DoT IP without TLS server name to fail")
	}
	if _, err := parseUpstreamEndpoints([]string{"tls://1.1.1.1@"}, "udp"); err == nil {
		t.Fatal("expected empty TLS server name to fail")
	}
}

func TestMatchRule(t *testing.T) {
	rules := []Rule{
		{Type: "DOMAIN", Value: "a.example.com", Target: "1.1.1.1"},
		{Type: "DOMAIN-SUFFIX", Value: "example.com", Target: "2.2.2.2"},
		{Type: "DOMAIN-KEYWORD", Value: "google", Target: "3.3.3.3"},
	}
	matcher := buildRuleMatcher(rules)
	if got := matchRule("a.example.com.", matcher); got != "1.1.1.1" {
		t.Fatalf("expected domain exact match")
	}
	if got := matchRule("example.com.", matcher); got != "2.2.2.2" {
		t.Fatalf("expected suffix root match")
	}
	if got := matchRule("b.example.com.", matcher); got != "2.2.2.2" {
		t.Fatalf("expected suffix match")
	}
	if got := matchRule("a.b.example.com.", matcher); got != "2.2.2.2" {
		t.Fatalf("expected nested suffix match")
	}
	if got := matchRule("notexample.com.", matcher); got != "" {
		t.Fatalf("expected suffix boundary mismatch, got %q", got)
	}
	if got := matchRule("example.com.evil.", matcher); got != "" {
		t.Fatalf("expected non-suffix domain to remain unmatched, got %q", got)
	}
	if got := matchRule("images.googleusercontent.com.", matcher); got != "3.3.3.3" {
		t.Fatalf("expected keyword match")
	}
}

func TestBuildRewriteRecord(t *testing.T) {
	cases := []struct {
		name   string
		qtype  uint16
		ip     string
		ok     bool
		rrtype uint16
	}{
		{name: "A with IPv4", qtype: dns.TypeA, ip: "192.0.2.10", ok: true, rrtype: dns.TypeA},
		{name: "AAAA with IPv6", qtype: dns.TypeAAAA, ip: "2001:db8::10", ok: true, rrtype: dns.TypeAAAA},
		{name: "AAAA with IPv4", qtype: dns.TypeAAAA, ip: "192.0.2.10", ok: false},
		{name: "A with IPv6", qtype: dns.TypeA, ip: "2001:db8::10", ok: false},
		{name: "TXT with IPv4", qtype: dns.TypeTXT, ip: "192.0.2.10", ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := dns.Question{Name: "example.com.", Qtype: tc.qtype, Qclass: dns.ClassINET}
			rr, ok := buildRewriteRecord(q, net.ParseIP(tc.ip), 60)
			if ok != tc.ok {
				t.Fatalf("expected ok=%v, got %v", tc.ok, ok)
			}
			if !tc.ok {
				if rr != nil {
					t.Fatalf("expected nil record, got %T", rr)
				}
				return
			}
			if rr.Header().Rrtype != tc.rrtype {
				t.Fatalf("expected rrtype %d, got %d", tc.rrtype, rr.Header().Rrtype)
			}
			if rr.Header().Ttl != 60 {
				t.Fatalf("expected ttl 60, got %d", rr.Header().Ttl)
			}
		})
	}
}
