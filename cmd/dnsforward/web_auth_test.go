package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := makePasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPasswordHash(hash, "correct horse battery staple") {
		t.Fatal("expected password to verify")
	}
	if verifyPasswordHash(hash, "wrong password") {
		t.Fatal("wrong password unexpectedly verified")
	}
	if _, _, _, err := parsePasswordHash(hash); err != nil {
		t.Fatalf("generated hash should parse: %v", err)
	}
}

func TestRequireWebAuthRejectsUnauthenticatedAPI(t *testing.T) {
	oldCfg := cfg
	hash, err := makePasswordHash("secret")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.WebPasswordHash = hash
	resetWebSessions()
	t.Cleanup(func() {
		cfg = oldCfg
		resetWebSessions()
	})

	handler := requireWebAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestWebLoginAndAuthenticatedRequest(t *testing.T) {
	oldCfg := cfg
	hash, err := makePasswordHash("secret")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.WebPasswordHash = hash
	resetWebSessions()
	t.Cleanup(func() {
		cfg = oldCfg
		resetWebSessions()
	})

	form := url.Values{"password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	webLoginHandler(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected login redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("login did not issue session cookie")
	}
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie flags: %#v", sessionCookie)
	}

	handler := requireWebAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	authReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	authReq.AddCookie(sessionCookie)
	authRR := httptest.NewRecorder()
	handler.ServeHTTP(authRR, authReq)
	if authRR.Code != http.StatusNoContent {
		t.Fatalf("expected authenticated request to pass, got %d", authRR.Code)
	}
}

func TestInvalidPasswordHashRejected(t *testing.T) {
	var c Config
	c.Server.Address = "127.0.0.1:5353"
	c.Server.CacheExpiration = "5m"
	c.Server.WebAddress = "127.0.0.1:8080"
	c.Server.WebPasswordHash = "not-a-valid-hash"
	c.Upstream.DNSServers = []string{"8.8.8.8:53"}
	if err := validateConfig(&c); err == nil {
		t.Fatal("expected invalid web_password_hash to be rejected")
	}
}
