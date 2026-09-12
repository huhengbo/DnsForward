package main

import (
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/singleflight"
)

type runtimeConfig struct {
	upstreamEndpoints []upstreamEndpoint
	upstreamTimeout   time.Duration
	ruleFetchClient   *http.Client
	ruleFetchRetry    int
	dnsCache          *cache.Cache
	defaultCacheTTL   time.Duration
	negativeCacheTTL  time.Duration
	minCacheTTL       time.Duration
	maxCacheTTL       time.Duration
	rewriteTTL        uint32
	matcher           ruleMatcher
	allowCIDRs        []netip.Prefix
	querySlots        chan struct{}
	missGroup         singleflight.Group
}

var runtimeCfg atomic.Value

func currentRuntime() *runtimeConfig {
	if cfg := runtimeCfg.Load(); cfg != nil {
		return cfg.(*runtimeConfig)
	}
	return nil
}
