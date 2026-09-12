package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const webTestConfig = `server:
  address: "127.0.0.1:5353"
  web_address: "127.0.0.1:8080"
  cache_expiration: 5m
upstream:
  dns_servers:
    - "8.8.8.8:53"
  timeout: 2s
  protocol: udp
fetch:
  timeout: 5s
  retry: 1
rewrite:
  default_ttl: 10m
  rules: []
`

func TestWebConfigValidateHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader(webTestConfig))
	rr := httptest.NewRecorder()
	webConfigValidateHandler(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestWebConfigValidateRejectsUnknownField(t *testing.T) {
	body := strings.Replace(webTestConfig, "  cache_expiration: 5m", "  cache_expiration: 5m\n  unknown: true", 1)
	req := httptest.NewRequest(http.MethodPost, "/api/config/validate", strings.NewReader(body))
	rr := httptest.NewRecorder()
	webConfigValidateHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestWebConfigGetAndPut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(webTestConfig), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath := ConfigFilePath
	oldCfg := cfg
	ConfigFilePath = path
	t.Cleanup(func() {
		ConfigFilePath = oldPath
		cfg = oldCfg
	})

	getReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	getRR := httptest.NewRecorder()
	webConfigHandler(getRR, getReq)
	if getRR.Code != http.StatusOK || !strings.Contains(getRR.Body.String(), "web_address") {
		t.Fatalf("unexpected GET response: %d %s", getRR.Code, getRR.Body.String())
	}

	updated := strings.Replace(webTestConfig, "127.0.0.1:8080", "127.0.0.1:8081", 1)
	putReq := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(updated))
	putRR := httptest.NewRecorder()
	webConfigHandler(putRR, putReq)
	if putRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putRR.Code, putRR.Body.String())
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored), "127.0.0.1:8081") {
		t.Fatalf("updated config not written: %s", stored)
	}
}

func TestRecentLogs(t *testing.T) {
	recentMu.Lock()
	recentLog = nil
	recentMu.Unlock()
	serviceLogger("web-log-test", 0, false)
	lines := recentLogLines()
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], "web-log-test") {
		t.Fatalf("recent log missing: %#v", lines)
	}
}
