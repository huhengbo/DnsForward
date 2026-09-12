package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
)

func TestDetermineTTLUsesSOAForNXDOMAIN(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
			Minttl: 45,
		},
	}

	if got := determineTTL(msg, 30*time.Second); got != 30*time.Second {
		t.Fatalf("expected configured negative TTL cap 30s, got %v", got)
	}
	if got := determineTTL(msg, 0); got != 45*time.Second {
		t.Fatalf("expected RFC 2308 SOA TTL 45s, got %v", got)
	}
}

func TestDetermineTTLUsesSOAForNODATA(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 90},
			Minttl: 60,
		},
	}

	if !isNegativeResponse(msg) {
		t.Fatal("expected NOERROR/NODATA response with SOA to be treated as negative")
	}
	if got := determineTTL(msg, 2*time.Minute); got != 60*time.Second {
		t.Fatalf("expected SOA-derived TTL 60s, got %v", got)
	}
}

func TestDetermineTTLDoesNotCacheZeroSOANegativeResponse(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
			Minttl: 30,
		},
	}

	if got := determineTTL(msg, time.Minute); got != 0 {
		t.Fatalf("expected zero SOA TTL to disable negative caching, got %v", got)
	}
}

func TestCacheDurationDoesNotCacheExplicitZeroTTLAnswer(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.10")},
	}
	rt := &runtimeConfig{defaultCacheTTL: 5 * time.Minute, minCacheTTL: 10 * time.Second}

	if got := cacheDuration(msg, rt); got != 0 {
		t.Fatalf("expected explicit zero-TTL answer not to be cached, got %v", got)
	}
}

func TestCacheDurationMinTTLIsLocalRetentionPolicy(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP("192.0.2.10")},
	}
	rt := &runtimeConfig{minCacheTTL: 10 * time.Second}

	if got := cacheDuration(msg, rt); got != 10*time.Second {
		t.Fatalf("expected local retention to be clamped to 10s, got %v", got)
	}
	if got := msg.Answer[0].Header().Ttl; got != 5 {
		t.Fatalf("local cache policy must not rewrite downstream RR TTL, got %d", got)
	}
}

func TestAgeDNSMessageTTL(t *testing.T) {
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.10")},
	}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30}, Ns: "ns.example."},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("192.0.2.53")},
	}

	ageDNSMessageTTL(msg, 20*time.Second)

	if got := msg.Answer[0].Header().Ttl; got != 100 {
		t.Fatalf("answer TTL: expected 100, got %d", got)
	}
	if got := msg.Ns[0].Header().Ttl; got != 10 {
		t.Fatalf("authority TTL: expected 10, got %d", got)
	}
	if got := msg.Extra[0].Header().Ttl; got != 0 {
		t.Fatalf("additional TTL should saturate at zero, got %d", got)
	}
}

func TestGetCachedResponseAgesCopyWithoutMutatingStoredMessage(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	msg := &dns.Msg{}
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.10")},
	}

	rt := &runtimeConfig{dnsCache: cache.New(time.Minute, time.Minute)}
	rt.dnsCache.Set("key", dnsCacheEntry{msg: msg.Copy(), storedAt: t0}, time.Minute)

	first, found := getCachedResponse(rt, "key", t0.Add(15*time.Second))
	if !found {
		t.Fatal("expected cached response")
	}
	if got := first.Answer[0].Header().Ttl; got != 45 {
		t.Fatalf("expected aged TTL 45, got %d", got)
	}

	second, found := getCachedResponse(rt, "key", t0.Add(20*time.Second))
	if !found {
		t.Fatal("expected cached response")
	}
	if got := second.Answer[0].Header().Ttl; got != 40 {
		t.Fatalf("expected stored response to remain immutable; got TTL %d", got)
	}
}
