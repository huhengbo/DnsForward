package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	passwordHashPrefix = "pbkdf2-sha256"
	passwordIterations = 200000
	sessionCookieName  = "dnsforward_session"
	sessionTTL         = 12 * time.Hour
)

var webSessions = struct {
	sync.Mutex
	items map[string]time.Time
}{items: make(map[string]time.Time)}

func makePasswordHash(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := derivePasswordKey([]byte(password), salt, passwordIterations)
	return strings.Join([]string{
		passwordHashPrefix,
		strconv.Itoa(passwordIterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	}, "$"), nil
}

func verifyPasswordHash(encoded, password string) bool {
	iterations, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return false
	}
	actual := derivePasswordKey([]byte(password), salt, iterations)
	if len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func parsePasswordHash(encoded string) (int, []byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 4 || parts[0] != passwordHashPrefix {
		return 0, nil, nil, fmt.Errorf("web_password_hash 格式无效")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100000 || iterations > 1000000 {
		return 0, nil, nil, fmt.Errorf("web_password_hash 迭代次数无效")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return 0, nil, nil, fmt.Errorf("web_password_hash salt 无效")
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(digest) != sha256.Size {
		return 0, nil, nil, fmt.Errorf("web_password_hash digest 无效")
	}
	return iterations, salt, digest, nil
}

func derivePasswordKey(password, salt []byte, iterations int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	binary.BigEndian.PutUint32(block[len(salt):], 1)

	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(block)
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func printPasswordHashFromStdin() error {
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	hash, err := makePasswordHash(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}

func webAuthEnabled() bool {
	return strings.TrimSpace(cfg.Server.WebPasswordHash) != ""
}

func resetWebSessions() {
	webSessions.Lock()
	webSessions.items = make(map[string]time.Time)
	webSessions.Unlock()
}

func createWebSession() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	webSessions.Lock()
	webSessions.items[token] = time.Now().Add(sessionTTL)
	webSessions.Unlock()
	return token, nil
}

func deleteWebSession(token string) {
	webSessions.Lock()
	delete(webSessions.items, token)
	webSessions.Unlock()
}

func validWebSession(r *http.Request) bool {
	if !webAuthEnabled() {
		return true
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	webSessions.Lock()
	expires, ok := webSessions.items[cookie.Value]
	if ok && time.Now().After(expires) {
		delete(webSessions.items, cookie.Value)
		ok = false
	}
	webSessions.Unlock()
	return ok
}

func setWebSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func clearWebSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func requireWebAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if validWebSession(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}
