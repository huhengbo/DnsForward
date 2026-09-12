package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type upstreamEndpoint struct {
	Address    string
	Network    string
	ServerName string
}

func forwardToUpstreamParallel(rt *runtimeConfig, r *dns.Msg) *dns.Msg {
	var wg sync.WaitGroup
	respChan := make(chan *dns.Msg, 1)

	for _, endpoint := range rt.upstreamEndpoints {
		wg.Add(1)
		go func(ep upstreamEndpoint) {
			defer wg.Done()
			client := &dns.Client{Timeout: rt.upstreamTimeout, Net: ep.Network}
			if ep.Network == "tcp-tls" {
				client.TLSConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
					ServerName: ep.ServerName,
				}
			}
			query := r.Copy()
			resp, _, err := client.Exchange(query, ep.Address)
			if err == nil && resp != nil {
				if resp.Rcode == dns.RcodeServerFailure {
					return
				}
				select {
				case respChan <- resp:
					serviceLogger(fmt.Sprintf("上游响应成功: %s", ep.Address), 32, true)
				default:
				}
			}
		}(endpoint)
	}

	go func() {
		wg.Wait()
		close(respChan)
	}()

	select {
	case resp := <-respChan:
		return resp
	case <-time.After(rt.upstreamTimeout):
		serviceLogger("获取上游DNS响应超时", 31, false)
		return nil
	}
}

func normalizeProtocol(proto string) (network, defaultPort string, err error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "", "udp":
		return "udp", "53", nil
	case "tcp":
		return "tcp", "53", nil
	case "tls", "tcp-tls", "dot":
		return "tcp-tls", "853", nil
	default:
		return "", "", fmt.Errorf("不支持的上游协议: %s", proto)
	}
}

func parseUpstreamEndpoints(servers []string, defaultProto string) ([]upstreamEndpoint, error) {
	if len(servers) == 0 {
		return nil, errors.New("upstream.dns_servers 不能为空")
	}
	defaultNetwork, defaultPort, err := normalizeProtocol(defaultProto)
	if err != nil {
		return nil, err
	}
	var endpoints []upstreamEndpoint
	for _, raw := range servers {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		protoNetwork, protoPort := defaultNetwork, defaultPort
		target := entry
		if strings.Contains(entry, "://") {
			parts := strings.SplitN(entry, "://", 2)
			if len(parts) == 2 {
				protoNetwork, protoPort, err = normalizeProtocol(parts[0])
				if err != nil {
					return nil, err
				}
				target = parts[1]
			}
		}
		serverName := ""
		if strings.Contains(target, "@") {
			parts := strings.SplitN(target, "@", 2)
			target = strings.TrimSpace(parts[0])
			serverName = strings.TrimSpace(parts[1])
			if serverName == "" {
				return nil, fmt.Errorf("DoT 上游 %q 的 TLS 校验名称不能为空", entry)
			}
		}
		hostPort := target
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			hostPort = net.JoinHostPort(target, protoPort)
		}
		host, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return nil, fmt.Errorf("上游地址解析失败 %s: %w", target, err)
		}

		if protoNetwork == "tcp-tls" && serverName == "" {
			if net.ParseIP(host) != nil {
				return nil, fmt.Errorf("DoT 上游 %q 使用 IP 地址时必须通过 tls://IP@hostname 显式指定 TLS 校验名称", entry)
			}
			serverName = host
		}

		endpoints = append(endpoints, upstreamEndpoint{
			Address:    hostPort,
			Network:    protoNetwork,
			ServerName: serverName,
		})
	}
	if len(endpoints) == 0 {
		return nil, errors.New("未解析到有效上游 DNS")
	}
	return endpoints, nil
}
