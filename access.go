package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

var defaultAllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}

func parseAllowedCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		values = defaultAllowedCIDRs
	}

	prefixes := make([]netip.Prefix, 0, len(values))
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("server.allow_cidrs[%d] 不能为空", index)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("server.allow_cidrs[%d] 无法解析 %q: %w", index, value, err)
		}
		prefixes = append(prefixes, normalizePrefix(prefix))
	}
	return prefixes, nil
}

func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr().WithZone("")
	bits := prefix.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

func clientIPFromAddr(addr net.Addr) (netip.Addr, error) {
	if addr == nil {
		return netip.Addr{}, fmt.Errorf("客户端地址为空")
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("客户端地址无法解析 %q: %w", addr.String(), err)
	}
	return ip.WithZone("").Unmap(), nil
}

func isClientAllowed(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.WithZone("").Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func tryAcquireQuerySlot(slots chan struct{}) bool {
	if slots == nil {
		return true
	}
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseQuerySlot(slots chan struct{}) {
	if slots == nil {
		return
	}
	<-slots
}

func writeDNSRcode(w dns.ResponseWriter, request *dns.Msg, rcode int) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = rcode
	_ = w.WriteMsg(response)
}
