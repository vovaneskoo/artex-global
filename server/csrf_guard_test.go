package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// guardTestHandler reports that the request survived the guard by answering 202.
func guardTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
}

var guardTestOrigins = map[string]bool{"http://localhost:5173": true, "http://127.0.0.1:5173": true}

// callGuard runs one POST through the guard, mirroring the default dev allowlist.
func callGuard(method, target, origin, contentType, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(`{}`))
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	guardAPIWith(guardTestOrigins, guardTestHandler()).ServeHTTP(rec, r)
	return rec
}

// TestGuardRejectsForeignOriginMutations: a browser always sends Origin on a
// cross-origin mutation. Anything that is neither the request's own origin nor
// allowlisted must be rejected BEFORE the handler runs — CORS alone only hides
// the response; the mutation (MCP save → stdio discovery) would still execute.
// This is the localhost-port CSRF: localhost:5174 is a different origin but the
// same site as localhost:8787, so SameSite cookies never protected it.
func TestGuardRejectsForeignOriginMutations(t *testing.T) {
	for _, origin := range []string{
		"http://localhost:5174",            // другой порт того же хоста (same-site, cross-origin)
		"http://127.0.0.1:9999",            // другой loopback-порт
		"https://evil.example",             // внешний origin
		"http://localhost:8787.evil.example",
		"null", // sandboxed iframe
	} {
		if rec := callGuard(http.MethodPost, "/api/mcp", origin, "application/json", "localhost:8787"); rec.Code != http.StatusForbidden {
			t.Fatalf("Origin %s: статус = %d, ожидается 403 (до вызова handler)", origin, rec.Code)
		}
		if rec := callGuard(http.MethodDelete, "/api/tasks/1", origin, "", "localhost:8787"); rec.Code != http.StatusForbidden {
			t.Fatalf("Origin %s DELETE: статус = %d, ожидается 403", origin, rec.Code)
		}
	}
}

// TestGuardAllowsLegitMutations: no Origin (curl/скрипты), allowlisted dev
// origins and the request's own origin (embedded UI, reverse proxy preserving
// Host or sending X-Forwarded-Host) all reach the handler.
func TestGuardAllowsLegitMutations(t *testing.T) {
	cases := []struct {
		name        string
		origin      string
		host        string
		fwdHost     string
		contentType string
	}{
		{"curl без Origin", "", "localhost:8787", "", "application/json"},
		{"next dev allowlist", "http://localhost:5173", "localhost:8787", "", "application/json"},
		{"127.0.0.1 dev allowlist", "http://127.0.0.1:5173", "localhost:8787", "", "application/json"},
		{"тот же origin (embedded UI)", "http://ops.box:8787", "ops.box:8787", "", "application/json"},
		{"reverse proxy X-Forwarded-Host", "https://ui.corp", "127.0.0.1:8787", "ui.corp", "application/json"},
		{"charset параметр", "", "localhost:8787", "", "application/json; charset=utf-8"},
		{"multipart upload", "", "localhost:8787", "", "multipart/form-data; boundary=x"},
		{"DELETE без Content-Type", "", "localhost:8787", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(`{}`))
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.fwdHost != "" {
				r.Header.Set("X-Forwarded-Host", c.fwdHost)
			}
			if c.contentType != "" {
				r.Header.Set("Content-Type", c.contentType)
			}
			rec := httptest.NewRecorder()
			guardAPIWith(guardTestOrigins, guardTestHandler()).ServeHTTP(rec, r)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("origin=%q host=%q fwd=%q ct=%q: статус = %d, ожидается 202 (guard пропустил)",
					c.origin, c.host, c.fwdHost, c.contentType, rec.Code)
			}
		})
	}
}

// TestGuardGETNeverBlocked: mutations only — GET/HEAD/OPTIONS carry no guard
// regardless of Origin/Content-Type (SSE, downloads, plain reads).
func TestGuardGETNeverBlocked(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if rec := callGuard(m, "/api/logs/stream", "https://evil.example", "text/plain", "localhost:8787"); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: статус = %d, ожидается 202", m, rec.Code)
		}
	}
}

// TestGuardRejectsNonJSONMediaType: a "simple request" (text/plain form POST,
// no-cors fetch) skips the CORS preflight entirely while still delivering a
// JSON body the handlers would decode. The guard answers 415 before any
// handler state changes. application/x-www-form-urlencoded is equally rejected
// (nothing in the API reads it).
func TestGuardRejectsNonJSONMediaType(t *testing.T) {
	for _, ct := range []string{"text/plain", "text/plain; charset=utf-8", "application/x-www-form-urlencoded", "application/xml", "garbage////"} {
		if rec := callGuard(http.MethodPost, "/api/mcp", "", ct, "localhost:8787"); rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: статус = %d, ожидается 415", ct, rec.Code)
		}
	}
}

// TestGuardMediaCheckRunsBeforeHandler: the 415 fires even when the request is
// perfectly authenticated — rejection happens before any write.
func TestGuardMediaCheckRunsBeforeHandler(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	h := s.Handler()

	r := httptest.NewRequest(http.MethodPost, "/api/task-categories", strings.NewReader(`{"name":"csrf-probe"}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain mutation: статус = %d, ожидается 415 (до записи); body=%s", rec.Code, rec.Body.String())
	}
}

// TestCookieNoLongerAuthenticates: the artex_token cookie used to carry the
// 7-day JWT and authenticate every /api request — the ambient credential a
// same-host cross-origin page could ride (cookies ignore ports). extractToken
// must ignore it entirely.
func TestCookieNoLongerAuthenticates(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	r.AddCookie(&http.Cookie{Name: "artex_token", Value: "forged-or-real-jwt"})
	if got := extractToken(r); got != "" {
		t.Fatalf("cookie не должна аутентифицировать: extractToken = %q", got)
	}

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()

	r2 := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	r2.AddCookie(&http.Cookie{Name: "artex_token", Value: "anything"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r2)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie-only запрос: статус = %d, ожидается 401", rec.Code)
	}
}

// TestAuthSSEToken: POST /api/auth/sse-token exchanges a Bearer session for a
// short-lived ticket that authenticates an SSE ?ticket= handshake — the web
// client no longer puts the long-lived JWT in URLs.
func TestAuthSSEToken(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	// без Bearer — 401
	r := httptest.NewRequest(http.MethodPost, "/api/auth/sse-token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("без токена: статус = %d, ожидается 401", rec.Code)
	}

	// с Bearer — короткоживущий ticket (10 минут)
	r2 := httptest.NewRequest(http.MethodPost, "/api/auth/sse-token", nil)
	r2.Header.Set("Authorization", "Bearer "+tok)
	r2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("sse-token: статус = %d (%s), ожидается 200", rec2.Code, rec2.Body.String())
	}
	if body := rec2.Body.String(); !strings.Contains(body, `"token"`) || !strings.Contains(body, `"expires_in":600`) {
		t.Fatalf("sse-token ответ не содержит ticket/expires_in: %s", body)
	}

	// ticket аутентифицирует requireAuth-защищённый GET (?ticket= как в SSE):
	// без DB защищённый handler ответит не-401 — значит аутентификация прошла.
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &parsed); err != nil || parsed.Token == "" {
		t.Fatalf("не удалось извлечь ticket из %s: %v", rec2.Body.String(), err)
	}
	r3 := httptest.NewRequest(http.MethodGet, "/api/stats?ticket="+parsed.Token, nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, r3)
	if rec3.Code == http.StatusUnauthorized {
		t.Fatal("ticket в ?ticket= не принят (401)")
	}

	// просроченный ticket отклоняется
	hash, _ := s.cachedPassHash()
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).SignedString(s.signingKey(hash))
	if err != nil {
		t.Fatalf("sign expired: %v", err)
	}
	r4 := httptest.NewRequest(http.MethodGet, "/api/stats?ticket="+expired, nil)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, r4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("просроченный ticket: статус = %d, ожидается 401", rec4.Code)
	}
}

// TestForeignOriginCannotCreateMCP: e2e через реальный mux — disallowed Origin
// не создаёт MCP и не запускает discovery-процесс (guard падает до handler'а).
// Требует PostgreSQL (disposable), иначе skip.
func TestForeignOriginCannotCreateMCP(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil || m.pg == nil {
		t.Skip("postgres unavailable — skipping MCP origin e2e")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	tok, _ := signJWT(s.jwtKey)

	marker := filepath.Join(t.TempDir(), "pwned")
	body := `{"name":"csrf-probe-mcp","transport":"stdio","command":"touch","args":["` + marker + `"],"enabled":true}`
	t.Cleanup(func() { m.pg.Exec(`DELETE FROM mcp_servers WHERE name = 'csrf-probe-mcp'`) })
	m.pg.Exec(`DELETE FROM mcp_servers WHERE name = 'csrf-probe-mcp'`)

	r := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://localhost:5174") // другой localhost-порт
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("MCP create с чужим Origin: статус = %d, ожидается 403", rec.Code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("discovery-процесс запустился несмотря на 403")
	}
	list, err := m.pg.ListMCP()
	if err != nil {
		t.Fatalf("list mcp: %v", err)
	}
	for _, srv := range list {
		if srv.Name == "csrf-probe-mcp" {
			t.Fatal("MCP создан несмотря на 403")
		}
	}
}
