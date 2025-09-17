package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func storeInCache(cacheKey string, msg *dns.Msg) {
	rt := currentRuntime()
	if rt == nil || rt.dnsCache == nil {
		return
	}
	msgCopy := msg.Copy()
	msgCopy.Id = 0
	ttl := determineTTL(msgCopy, rt.negativeCacheTTL)
	if ttl <= 0 {
		ttl = rt.defaultCacheTTL
	}
	ttl = clampTTL(ttl, rt.minCacheTTL, rt.maxCacheTTL)
	rt.dnsCache.Set(cacheKey, msgCopy, ttl)
	if len(msgCopy.Question) > 0 {
		serviceLogger(fmt.Sprintf("缓存写入：%s (TTL=%v)", strings.TrimSuffix(msgCopy.Question[0].Name, "."), ttl), 1, true)
	}
}

func determineTTL(msg *dns.Msg, negativeTTL time.Duration) time.Duration {
	var (
		found  bool
		minTTL uint32 = ^uint32(0)
	)
	update := func(ttl uint32) {
		if ttl == 0 {
			return
		}
		if ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	for _, rr := range msg.Answer {
		update(rr.Header().Ttl)
	}
	for _, rr := range msg.Ns {
		switch v := rr.(type) {
		case *dns.SOA:
			candidate := v.Hdr.Ttl
			if v.Minttl < candidate {
				candidate = v.Minttl
			}
			update(candidate)
		default:
			update(rr.Header().Ttl)
		}
	}
	if found {
		return time.Duration(minTTL) * time.Second
	}
	if msg.MsgHdr.Rcode == dns.RcodeNameError && negativeTTL > 0 {
		return negativeTTL
	}
	return 0
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
