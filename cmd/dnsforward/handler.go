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

	clientIP, err := clientIPFromAddr(w.RemoteAddr())
	if err != nil || !isClientAllowed(clientIP, rt.allowCIDRs) {
		metricClientRejected.Inc()
		if err != nil {
			serviceLogger(fmt.Sprintf("拒绝无法识别来源的 DNS 请求: %v", err), 31, true)
		} else {
			serviceLogger(fmt.Sprintf("ACL 拒绝 DNS 请求: %s", clientIP), 31, true)
		}
		writeDNSRcode(w, r, dns.RcodeRefused)
		return
	}

	if !tryAcquireQuerySlot(rt.querySlots) {
		metricOverloadRejected.Inc()
		serviceLogger(fmt.Sprintf("并发查询已达上限，拒绝请求: %s", clientIP), 31, true)
		writeDNSRcode(w, r, dns.RcodeServerFailure)
		return
	}
	defer releaseQuerySlot(rt.querySlots)

	if len(r.Question) > 0 {
		question := r.Question[0]
		domain := question.Name
		cacheKey := buildCacheKey(question)

		if resp, found := getCachedResponse(rt, cacheKey, time.Now()); found {
			metricCacheHit.Inc()
			resp.Id = r.Id
			serviceLogger(fmt.Sprintf("缓存命中！: %s -> %v", domain, extractRecords(resp.Answer)), 32, true)
			w.WriteMsg(resp)
			serviceLogger(fmt.Sprintf("DNS解析：%s%s", strings.TrimSuffix(domain, "."), extractRecords(resp.Answer)), 1, true)
			return
		}
		metricCacheMiss.Inc()

		if ip := matchRule(domain, rt.matcher); ip != "" {
			targetIP := net.ParseIP(ip)
			if targetIP == nil {
				serviceLogger(fmt.Sprintf("规则目标无效，无法解析为 IP: %s", ip), 31, false)
			} else if rr, ok := buildRewriteRecord(question, targetIP, rt.rewriteTTL); ok {
				msg.Answer = append(msg.Answer, rr)
				storeInCache(cacheKey, &msg)
				metricRewriteHit.Inc()
				serviceLogger(fmt.Sprintf("DNS重写：%s%s", strings.TrimSuffix(domain, "."), extractRecords(msg.Answer)), 1, true)
				w.WriteMsg(&msg)
				return
			} else {
				serviceLogger(fmt.Sprintf("规则命中但 QTYPE/目标地址不匹配，转发上游: %s qtype=%d target=%s", domain, question.Qtype, ip), 0, true)
			}
		}

		resp := coalesceUpstreamLookup(rt, cacheKey, func() *dns.Msg {
			metricUpstreamRequests.Inc()
			start := time.Now()
			upstreamResp := forwardToUpstreamParallel(rt, r)
			if upstreamResp == nil {
				metricUpstreamFailure.Inc()
				return nil
			}

			serviceLogger(fmt.Sprintf("上游DNS解析！: %s -> %v", domain, extractRecords(upstreamResp.Answer)), 32, true)
			storeInCache(cacheKey, upstreamResp)
			metricUpstreamSuccess.Inc()
			metricUpstreamLatency.Observe(time.Since(start).Seconds())
			return upstreamResp
		})
		if resp != nil {
			resp.Id = r.Id
			w.WriteMsg(resp)
		} else {
			dns.HandleFailed(w, r)
		}
		return
	}

	w.WriteMsg(&msg)
}

func coalesceUpstreamLookup(rt *runtimeConfig, cacheKey string, lookup func() *dns.Msg) *dns.Msg {
	value, _, _ := rt.missGroup.Do(cacheKey, func() (any, error) {
		return lookup(), nil
	})
	resp, _ := value.(*dns.Msg)
	if resp == nil {
		return nil
	}
	return resp.Copy()
}

func buildRewriteRecord(question dns.Question, targetIP net.IP, ttl uint32) (dns.RR, bool) {
	switch question.Qtype {
	case dns.TypeA:
		ipv4 := targetIP.To4()
		if ipv4 == nil {
			return nil, false
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ipv4,
		}, true
	case dns.TypeAAAA:
		if targetIP.To4() != nil {
			return nil, false
		}
		ipv6 := targetIP.To16()
		if ipv6 == nil {
			return nil, false
		}
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ipv6,
		}, true
	default:
		return nil, false
	}
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
