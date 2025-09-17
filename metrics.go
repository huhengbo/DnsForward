package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsRegistry        = prometheus.NewRegistry()
	metricCacheHit         = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_cache_hits_total", Help: "缓存命中次数"})
	metricCacheMiss        = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_cache_misses_total", Help: "缓存未命中次数"})
	metricRewriteHit       = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_rewrite_hits_total", Help: "规则重写次数"})
	metricUpstreamRequests = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_upstream_requests_total", Help: "上游查询请求数"})
	metricUpstreamSuccess  = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_upstream_success_total", Help: "上游查询成功数"})
	metricUpstreamFailure  = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_upstream_failure_total", Help: "上游查询失败数"})
	metricUpstreamLatency  = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "dnsforward_upstream_duration_seconds", Help: "上游查询耗时", Buckets: prometheus.DefBuckets})
	metricReloadCount      = prometheus.NewCounter(prometheus.CounterOpts{Name: "dnsforward_reload_total", Help: "配置热加载次数"})
	metricsOnce            sync.Once
)

func ensureMetricsRegistered() {
	metricsOnce.Do(func() {
		metricsRegistry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
		metricsRegistry.MustRegister(prometheus.NewGoCollector())
		metricsRegistry.MustRegister(
			metricCacheHit,
			metricCacheMiss,
			metricRewriteHit,
			metricUpstreamRequests,
			metricUpstreamSuccess,
			metricUpstreamFailure,
			metricUpstreamLatency,
			metricReloadCount,
		)
	})
}

func startMetricsServer(addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		serviceLogger(fmt.Sprintf("指标服务监听: %s", addr), 0, false)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serviceLogger(fmt.Sprintf("指标服务启动失败: %v", err), 31, false)
		}
	}()
}
