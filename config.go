package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Server struct {
		Address          string `yaml:"address"`
		CacheExpiration  string `yaml:"cache_expiration"`
		NegativeCacheTTL string `yaml:"negative_cache_ttl"`
		MinTTL           string `yaml:"min_ttl"`
		MaxTTL           string `yaml:"max_ttl"`
		MetricsAddress   string `yaml:"metrics_address"`
	} `yaml:"server"`

	Upstream struct {
		DNSServers []string `yaml:"dns_servers"`
		Timeout    string   `yaml:"timeout"`
		Protocol   string   `yaml:"protocol"`
	} `yaml:"upstream"`

	Rewrite struct {
		Rules      []Rule `yaml:"rules"`
		DefaultTTL string `yaml:"default_ttl"`
	} `yaml:"rewrite"`

	Fetch struct {
		Timeout string `yaml:"timeout"`
		Retry   int    `yaml:"retry"`
	} `yaml:"fetch"`
}

func validateConfig(cfg *Config) error {
	if strings.TrimSpace(cfg.Server.Address) == "" {
		return errors.New("server.address 未配置")
	}
	if strings.TrimSpace(cfg.Server.CacheExpiration) == "" {
		return errors.New("server.cache_expiration 未配置")
	}
	if len(cfg.Upstream.DNSServers) == 0 {
		return errors.New("upstream.dns_servers 不能为空")
	}
	if cfg.Fetch.Retry < 0 {
		return errors.New("fetch.retry 不能为负数")
	}
	for idx, rule := range cfg.Rewrite.Rules {
		if strings.TrimSpace(rule.Target) == "" {
			return fmt.Errorf("rewrite.rules[%d] target 不能为空", idx)
		}
	}
	return nil
}

func loadConfigFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var newCfg Config
	if err := yaml.Unmarshal(data, &newCfg); err != nil {
		return Config{}, err
	}
	if err := validateConfig(&newCfg); err != nil {
		return Config{}, err
	}
	return newCfg, nil
}

func buildRuntimeFromConfig(newCfg Config) (*runtimeConfig, error) {
	cacheExpiration, err := time.ParseDuration(newCfg.Server.CacheExpiration)
	if err != nil {
		return nil, fmt.Errorf("server.cache_expiration 无法解析: %w", err)
	}
	if cacheExpiration <= 0 {
		return nil, errors.New("server.cache_expiration 需大于 0")
	}
	cleanupInterval := cacheExpiration
	if cleanupInterval < time.Second {
		cleanupInterval = time.Second
	}
	dnsCache := cache.New(cacheExpiration, cleanupInterval)

	defaultCacheTTL := cacheExpiration
	negativeTTL := time.Minute
	if strings.TrimSpace(newCfg.Server.NegativeCacheTTL) != "" {
		negativeTTL, err = time.ParseDuration(newCfg.Server.NegativeCacheTTL)
		if err != nil {
			return nil, fmt.Errorf("server.negative_cache_ttl 无法解析: %w", err)
		}
		if negativeTTL < 0 {
			return nil, errors.New("server.negative_cache_ttl 不能为负数")
		}
	}
	if negativeTTL > defaultCacheTTL {
		negativeTTL = defaultCacheTTL
	}
	var minTTL time.Duration
	if strings.TrimSpace(newCfg.Server.MinTTL) != "" {
		minTTL, err = time.ParseDuration(newCfg.Server.MinTTL)
		if err != nil {
			return nil, fmt.Errorf("server.min_ttl 无法解析: %w", err)
		}
		if minTTL < 0 {
			return nil, errors.New("server.min_ttl 不能为负数")
		}
	}
	var maxTTL time.Duration
	if strings.TrimSpace(newCfg.Server.MaxTTL) != "" {
		maxTTL, err = time.ParseDuration(newCfg.Server.MaxTTL)
		if err != nil {
			return nil, fmt.Errorf("server.max_ttl 无法解析: %w", err)
		}
		if maxTTL <= 0 {
			return nil, errors.New("server.max_ttl 需大于 0")
		}
	}
	if minTTL > 0 && maxTTL > 0 && minTTL > maxTTL {
		return nil, errors.New("server.min_ttl 不应大于 server.max_ttl")
	}
	rewriteTTL := uint32(600)
	if strings.TrimSpace(newCfg.Rewrite.DefaultTTL) != "" {
		rewriteDuration, err := time.ParseDuration(newCfg.Rewrite.DefaultTTL)
		if err != nil {
			return nil, fmt.Errorf("rewrite.default_ttl 无法解析: %w", err)
		}
		if rewriteDuration <= 0 {
			return nil, errors.New("rewrite.default_ttl 需大于 0")
		}
		rewriteTTL = uint32(rewriteDuration / time.Second)
		if rewriteTTL == 0 {
			rewriteTTL = 1
		}
	}
	upstreamTimeout := 2 * time.Second
	if strings.TrimSpace(newCfg.Upstream.Timeout) != "" {
		if upstreamTimeout, err = time.ParseDuration(newCfg.Upstream.Timeout); err != nil {
			return nil, fmt.Errorf("upstream.timeout 无法解析: %w", err)
		}
		if upstreamTimeout <= 0 {
			return nil, errors.New("upstream.timeout 需大于 0")
		}
	}
	endpoints, err := parseUpstreamEndpoints(newCfg.Upstream.DNSServers, newCfg.Upstream.Protocol)
	if err != nil {
		return nil, err
	}
	ruleFetchTimeout := 5 * time.Second
	if strings.TrimSpace(newCfg.Fetch.Timeout) != "" {
		if ruleFetchTimeout, err = time.ParseDuration(newCfg.Fetch.Timeout); err != nil {
			return nil, fmt.Errorf("fetch.timeout 无法解析: %w", err)
		}
		if ruleFetchTimeout <= 0 {
			return nil, errors.New("fetch.timeout 需大于 0")
		}
	}
	ruleFetchRetry := newCfg.Fetch.Retry
	if ruleFetchRetry <= 0 {
		ruleFetchRetry = 3
	}
	client := &http.Client{Timeout: ruleFetchTimeout}
	mergedRules := loadAndMergeRules(newCfg.Rewrite.Rules, client, ruleFetchRetry)
	matcher := buildRuleMatcher(mergedRules)

	rt := &runtimeConfig{
		upstreamEndpoints: endpoints,
		upstreamTimeout:   upstreamTimeout,
		ruleFetchClient:   client,
		ruleFetchRetry:    ruleFetchRetry,
		dnsCache:          dnsCache,
		defaultCacheTTL:   defaultCacheTTL,
		negativeCacheTTL:  negativeTTL,
		minCacheTTL:       minTTL,
		maxCacheTTL:       maxTTL,
		rewriteTTL:        rewriteTTL,
		matcher:           matcher,
	}
	return rt, nil
}

func applyRuntimeConfig(newCfg Config) error {
	rt, err := buildRuntimeFromConfig(newCfg)
	if err != nil {
		return err
	}
	if current := currentRuntime(); current != nil && current.dnsCache != nil {
		current.dnsCache.Flush()
	}
	runtimeCfg.Store(rt)
	cfg = newCfg
	totalRules := len(rt.matcher.domain) + len(rt.matcher.keyword)
	for _, rs := range rt.matcher.suffix {
		totalRules += len(rs)
	}
	serviceLogger(fmt.Sprintf("已加载配置，规则数量: %d", totalRules), 32, false)
	metricReloadCount.Inc()
	return nil
}
