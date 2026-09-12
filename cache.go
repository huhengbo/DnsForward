package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type dnsCacheEntry struct {
	msg      *dns.Msg
	storedAt time.Time
}

func storeInCache(cacheKey string, msg *dns.Msg) {
	storeInCacheAt(cacheKey, msg, time.Now())
}

func storeInCacheAt(cacheKey string, msg *dns.Msg, now time.Time) {
	rt := currentRuntime()
	if rt == nil || rt.dnsCache == nil || msg == nil {
		return
	}

	msgCopy := msg.Copy()
	msgCopy.Id = 0
	ttl := cacheDuration(msgCopy, rt)
	if ttl <= 0 {
		return
	}

	rt.dnsCache.Set(cacheKey, dnsCacheEntry{msg: msgCopy, storedAt: now}, ttl)
	if len(msgCopy.Question) > 0 {
		serviceLogger(fmt.Sprintf("缓存写入：%s (TTL=%v)", strings.TrimSuffix(msgCopy.Question[0].Name, "."), ttl), 1, true)
	}
}

func cacheDuration(msg *dns.Msg, rt *runtimeConfig) time.Duration {
	if msg == nil || rt == nil {
		return 0
	}

	ttl := determineTTL(msg, rt.negativeCacheTTL)
	if ttl <= 0 {
		if isNegativeResponse(msg) || len(msg.Answer) > 0 {
			return 0
		}
		ttl = rt.defaultCacheTTL
	}
	return clampTTL(ttl, rt.minCacheTTL, rt.maxCacheTTL)
}

func getCachedResponse(rt *runtimeConfig, cacheKey string, now time.Time) (*dns.Msg, bool) {
	if rt == nil || rt.dnsCache == nil {
		return nil, false
	}

	cached, found := rt.dnsCache.Get(cacheKey)
	if !found {
		return nil, false
	}
	entry, ok := cached.(dnsCacheEntry)
	if !ok || entry.msg == nil {
		rt.dnsCache.Delete(cacheKey)
		return nil, false
	}

	resp := entry.msg.Copy()
	ageDNSMessageTTL(resp, now.Sub(entry.storedAt))
	return resp, true
}

func determineTTL(msg *dns.Msg, negativeTTL time.Duration) time.Duration {
	if msg == nil {
		return 0
	}

	if isNegativeResponse(msg) {
		if soaTTL, found := negativeSOATTL(msg); found {
			if soaTTL == 0 {
				return 0
			}
			ttl := time.Duration(soaTTL) * time.Second
			if negativeTTL > 0 && ttl > negativeTTL {
				ttl = negativeTTL
			}
			return ttl
		}
		if negativeTTL > 0 {
			return negativeTTL
		}
		return 0
	}

	var (
		found  bool
		minTTL uint32 = ^uint32(0)
	)
	for _, rr := range msg.Answer {
		ttl := rr.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(minTTL) * time.Second
}

func isNegativeResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode == dns.RcodeNameError {
		return true
	}
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) > 0 {
		return false
	}
	_, found := negativeSOATTL(msg)
	return found
}

func negativeSOATTL(msg *dns.Msg) (uint32, bool) {
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return ttl, true
	}
	return 0, false
}

func ageDNSMessageTTL(msg *dns.Msg, elapsed time.Duration) {
	if msg == nil || elapsed <= 0 {
		return
	}

	seconds := uint64(elapsed / time.Second)
	if seconds == 0 {
		return
	}
	age := func(records []dns.RR) {
		for _, rr := range records {
			header := rr.Header()
			if uint64(header.Ttl) <= seconds {
				header.Ttl = 0
				continue
			}
			header.Ttl -= uint32(seconds)
		}
	}
	age(msg.Answer)
	age(msg.Ns)
	age(msg.Extra)
}

func clampTTL(ttl time.Duration, minTTL, maxTTL time.Duration) time.Duration {
	if ttl <= 0 {
		return ttl
	}
	if minTTL > 0 && ttl < minTTL {
		ttl = minTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}
