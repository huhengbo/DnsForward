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
		[]string{"8.8.8.8", "tcp://1.1.1.1:54", "tls://1.0.0.1@cloudflare-dns.com"},
		"udp",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
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
	if got := matchRule("b.example.com.", matcher); got != "2.2.2.2" {
		t.Fatalf("expected suffix match")
	}
	if got := matchRule("images.googleusercontent.com.", matcher); got != "3.3.3.3" {
		t.Fatalf("expected keyword match")
	}
}
