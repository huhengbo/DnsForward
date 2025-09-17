package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true
	rt := currentRuntime()
	if rt == nil {
		dns.HandleFailed(w, r)
		return
	}

	if len(r.Question) > 0 {
		question := r.Question[0]
		domain := question.Name
		cacheKey := buildCacheKey(question)

		if cachedMsg, found := rt.dnsCache.Get(cacheKey); found {
			metricCacheHit.Inc()
			resp := cachedMsg.(*dns.Msg).Copy()
			resp.Id = r.Id
			serviceLogger(fmt.Sprintf("缓存命中！: %s -> %v", domain, extractRecords(resp.Answer)), 32, true)
			w.WriteMsg(resp)
			serviceLogger(fmt.Sprintf("DNS解析：%s%s", strings.TrimSuffix(domain, "."), extractRecords(resp.Answer)), 1, true)
			return
		}
		metricCacheMiss.Inc()

		handled := false
		if ip := matchRule(domain, rt.matcher); ip != "" {
			targetIP := net.ParseIP(ip)
			if targetIP == nil {
				serviceLogger(fmt.Sprintf("规则目标无效，无法解析为 IP: %s", ip), 31, false)
			} else if ipv4 := targetIP.To4(); ipv4 != nil {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rt.rewriteTTL}
				rr.A = ipv4
				msg.Answer = append(msg.Answer, rr)
				handled = true
			} else if ipv6 := targetIP.To16(); ipv6 != nil {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rt.rewriteTTL}
				rr.AAAA = ipv6
				msg.Answer = append(msg.Answer, rr)
				handled = true
			} else {
				serviceLogger(fmt.Sprintf("规则目标不是有效的 IPv4/IPv6: %s", ip), 31, false)
			}
			if handled {
				storeInCache(cacheKey, &msg)
				metricRewriteHit.Inc()
				serviceLogger(fmt.Sprintf("DNS重写：%s%s", strings.TrimSuffix(domain, "."), extractRecords(msg.Answer)), 1, true)
				w.WriteMsg(&msg)
				return
			}
		}

		metricUpstreamRequests.Inc()
		start := time.Now()
		resp := forwardToUpstreamParallel(rt, r)
		if resp != nil {
			serviceLogger(fmt.Sprintf("上游DNS解析！: %s -> %v", domain, extractRecords(resp.Answer)), 32, true)
			storeInCache(cacheKey, resp)
			metricUpstreamSuccess.Inc()
			metricUpstreamLatency.Observe(time.Since(start).Seconds())
			w.WriteMsg(resp)
		} else {
			dns.HandleFailed(w, r)
			metricUpstreamFailure.Inc()
		}
		return
	}

	w.WriteMsg(&msg)
}

func extractRecords(answers []dns.RR) []string {
	var records []string
	for _, ans := range answers {
		switch v := ans.(type) {
		case *dns.A:
			records = append(records, v.A.String())
		case *dns.AAAA:
			records = append(records, v.AAAA.String())
		case *dns.CNAME:
			records = append(records, v.Target)
		default:
			records = append(records, v.String())
		}
	}
	return records
}

func buildCacheKey(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}
