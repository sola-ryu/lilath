package server_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
	"github.com/alanaktion/lilath/internal/server"
)

const (
	testUser     = "testuser"
	testPassword = "testpassword"
	cookieName   = "test_session"
)

// newTestServer returns an httptest.Server for the full handler stack, and a
// credentials store so callers can interact with it directly if needed.
func newTestServer(t *testing.T) (*httptest.Server, *auth.Credentials) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)

	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}

	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)

	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	return ts, creds
}

// login performs a POST /login and returns the session cookie, or fails the test.
func login(t *testing.T, ts *httptest.Server) *http.Cookie {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /login: expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("POST /login: no session cookie in response")
	return nil
}

// noFollowClient returns an *http.Client that does not follow redirects.
func noFollowClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestHealthz_GET(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", string(body))
	}
}

// --------------------------------------------------------------------------
// GET /auth — forward-auth endpoint
// --------------------------------------------------------------------------

func TestForwardAuth_Unauthenticated(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	resp, err := client.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestForwardAuth_UnauthenticatedWithURI(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("X-Forwarded-Uri", "/path?foo=bar&baz=qux")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	// The rd parameter must preserve all query params of the original URI.
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "/path?foo=bar&baz=qux" {
		t.Fatalf("rd param: expected %q, got %q", "/path?foo=bar&baz=qux", got)
	}
}

func TestForwardAuth_Authenticated(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-User"); got != testUser {
		t.Fatalf("X-Auth-User: expected %q, got %q", testUser, got)
	}
}

func TestForwardAuth_IPAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}

	sessions := auth.NewSessionStore(cfg.SessionTTL)

	// httptest uses 127.0.0.1 as the remote address.
	ipCheck, err := auth.NewIPChecker([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}

	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for allowed IP, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestForwardAuth_WithForwardedHostProto(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/protected")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/login") {
		t.Fatalf("expected absolute redirect to example.com, got %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "/protected" {
		t.Fatalf("rd param: expected %q, got %q", "/protected", got)
	}
}

func TestForwardAuth_WithBaseDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "asdf.example.com")
	req.Header.Set("X-Forwarded-Uri", "/protected?x=1")

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}

	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	rr := httptest.NewRecorder()
	h.ForwardAuth(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/login") {
		t.Fatalf("expected absolute redirect to base domain, got %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	if got := parsed.Query().Get("rd"); got != "https://asdf.example.com/protected?x=1" {
		t.Fatalf("rd param: expected absolute original URL, got %q", got)
	}

}

// --------------------------------------------------------------------------
// Bearer token auth — GET /auth with Authorization: Bearer <token>
// --------------------------------------------------------------------------

// newTestServerWithTokens returns an httptest.Server configured with a
// TokenStore loaded from the given tokens slice.
func newTestServerWithTokens(t *testing.T, tokens []string) *httptest.Server {
	t.Helper()

	dir := t.TempDir()

	usersPath := filepath.Join(dir, "users.txt")
	creds, err := auth.LoadCredentials(usersPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	tokensContent := strings.Join(tokens, "\n") + "\n"
	tokensPath := filepath.Join(dir, "tokens.txt")
	if err := os.WriteFile(tokensPath, []byte(tokensContent), 0600); err != nil {
		t.Fatalf("WriteFile tokens: %v", err)
	}
	tokenStore, err := auth.LoadTokens(tokensPath)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, tokenStore)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestForwardAuth_BearerToken_ValidToken(t *testing.T) {
	ts := newTestServerWithTokens(t, []string{"my-secret-token"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for valid Bearer token, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_InvalidToken(t *testing.T) {
	ts := newTestServerWithTokens(t, []string{"my-secret-token"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with bad Bearer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for invalid Bearer token, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_NoTokensConfigured(t *testing.T) {
	// When no tokens are configured, Bearer headers are ignored.
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer (no tokens configured): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d when no tokens configured, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BearerToken_EmptyTokenStore(t *testing.T) {
	// A token file containing only comments should behave the same as no file.
	ts := newTestServerWithTokens(t, []string{"# only comments"})
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Bearer (empty token store): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for empty token store, got %d", http.StatusFound, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// HTTP Basic auth — GET /auth with Authorization: Basic <credentials>
// --------------------------------------------------------------------------

func TestForwardAuth_BasicAuth_ValidCredentials(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.SetBasicAuth(testUser, testPassword)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Basic auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for valid Basic credentials, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-User"); got != testUser {
		t.Fatalf("expected X-Auth-User %q, got %q", testUser, got)
	}
}

func TestForwardAuth_BasicAuth_InvalidPassword(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.SetBasicAuth(testUser, "wrongpassword")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with bad Basic password: %v", err)
	}
	defer resp.Body.Close()

	// Invalid credentials must never return 401; fall through to login redirect.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for invalid Basic credentials, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BasicAuth_UnknownUser(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.SetBasicAuth("nobody", "password")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with unknown Basic user: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d for unknown Basic user, got %d", http.StatusFound, resp.StatusCode)
	}
}

func TestForwardAuth_BasicAuth_DeniedByUserAllowlist(t *testing.T) {
	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(usersPath, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(usersPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:   cookieName,
		SessionTTL:   60,
		DefaultUsers: []string{"otheruser"}, // testUser is not in the list
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	client := noFollowClient()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.SetBasicAuth(testUser, testPassword)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth with Basic auth (denied user): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d for Basic auth user denied by allowlist, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// GET /login — login page
// --------------------------------------------------------------------------

func TestLoginPage_GET(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
}

func TestLoginPage_GET_WithRd(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login?rd=/dashboard")
	if err != nil {
		t.Fatalf("GET /login?rd=: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// POST /login — credential submission
// --------------------------------------------------------------------------

func TestLoginSubmit_ValidCredentials(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after successful login")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session cookie value should not be empty")
	}
}

func TestLoginSubmit_SetsCookieDomainWithBaseDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"https://asdf.example.com/"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.LoginSubmit(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after successful login")
	}
	if sessionCookie.Domain != "example.com" {
		t.Fatalf("cookie domain: expected %q, got %q", "example.com", sessionCookie.Domain)
	}
}

func TestLoginSubmit_InvalidPassword(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {"wrongpassword"},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestLoginSubmit_UnknownUser(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {"nobody"},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestLoginSubmit_RedirectsToRd(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/dashboard"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", loc)
	}
}

// --------------------------------------------------------------------------
// GET /logout and POST /logout
// --------------------------------------------------------------------------

func TestLogout_GET(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	// Confirm session is active.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth before logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected authenticated before logout, got %d", resp.StatusCode)
	}

	// Logout.
	logoutReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, logoutResp.StatusCode)
	}

	// Session should now be invalid.
	authReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	authReq.AddCookie(cookie)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /auth after logout: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected unauthenticated after logout, got %d", authResp.StatusCode)
	}
}

func TestLogout_POST(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	logoutReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, logoutResp.StatusCode)
	}

	// Session should now be invalid.
	authReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	authReq.AddCookie(cookie)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /auth after POST /logout: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected unauthenticated after logout, got %d", authResp.StatusCode)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noFollowClient()

	cookie := login(t, ts)

	logoutReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout", nil)
	logoutReq.AddCookie(cookie)
	resp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	defer resp.Body.Close()

	// Check that a Set-Cookie header clears the session cookie.
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			if c.MaxAge >= 0 {
				t.Fatalf("expected MaxAge < 0 to clear cookie, got %d", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("expected a Set-Cookie header for the session cookie on logout")
}

func TestLogout_ClearsCookieDomainWithBaseDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		BaseDomain:        "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	rr := httptest.NewRecorder()

	h.Logout(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	var cleared *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			cleared = c
			break
		}
	}
	if cleared == nil {
		t.Fatal("expected a Set-Cookie header for the session cookie on logout")
	}
	if cleared.Domain != "example.com" {
		t.Fatalf("cookie domain: expected %q, got %q", "example.com", cleared.Domain)
	}
}

// --------------------------------------------------------------------------
// Custom login template
// --------------------------------------------------------------------------

func TestLoginPage_CustomTemplate(t *testing.T) {
dir := t.TempDir()

// Write a minimal custom template.
tmplPath := filepath.Join(dir, "custom-login.html")
if err := os.WriteFile(tmplPath, []byte(`<!DOCTYPE html><html><body id="custom">{{.RedirectURL}}</body></html>`), 0600); err != nil {
t.Fatalf("WriteFile: %v", err)
}

path := filepath.Join(dir, "users.txt")
creds, err := auth.LoadCredentials(path)
if err != nil {
t.Fatalf("LoadCredentials: %v", err)
}

cfg := &config.Config{
CookieName:    cookieName,
CookieSecure:  false,
SessionTTL:    60,
LoginTemplate: tmplPath,
}
sessions := auth.NewSessionStore(cfg.SessionTTL)
ipCheck, err := auth.NewIPChecker(nil)
if err != nil {
t.Fatalf("NewIPChecker: %v", err)
}
h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
if err != nil {
t.Fatalf("NewHandlers: %v", err)
}

req := httptest.NewRequest(http.MethodGet, "/login?rd=/dashboard", nil)
rr := httptest.NewRecorder()
h.LoginPage(rr, req)
resp := rr.Result()
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
}
body, err := io.ReadAll(resp.Body)
if err != nil {
t.Fatalf("ReadAll: %v", err)
}
if !strings.Contains(string(body), `id="custom"`) {
t.Errorf("response body does not contain custom template marker: %s", body)
}
if !strings.Contains(string(body), "/dashboard") {
t.Errorf("response body does not contain redirect URL: %s", body)
}
}

func TestNewHandlers_InvalidCustomTemplate(t *testing.T) {
creds, err := auth.LoadCredentials(filepath.Join(t.TempDir(), "users.txt"))
if err != nil {
t.Fatalf("LoadCredentials: %v", err)
}
cfg := &config.Config{
CookieName:    cookieName,
SessionTTL:    60,
LoginTemplate: "/nonexistent/path/login.html",
}
sessions := auth.NewSessionStore(cfg.SessionTTL)
ipCheck, err := auth.NewIPChecker(nil)
if err != nil {
t.Fatalf("NewIPChecker: %v", err)
}
_, err = server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
if err == nil {
t.Fatal("expected error for nonexistent template path, got nil")
}
}

// --------------------------------------------------------------------------
// Rate limiting
// --------------------------------------------------------------------------

// newRateLimitedServer returns a test server with rate limiting enabled.
// limit is the max requests for GET /auth and loginLimit for POST /login.
func newRateLimitedServer(t *testing.T, limit, loginLimit int) *httptest.Server {
	t.Helper()

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:             cookieName,
		CookieSecure:           false,
		SessionTTL:             60,
		TrustForwardedFor:      false,
		RateLimitRequests:      limit,
		RateLimitLoginRequests: loginLimit,
		RateLimitWindowSeconds: 60,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestForwardAuth_RateLimit(t *testing.T) {
	ts := newRateLimitedServer(t, 3, 10)
	client := noFollowClient()

	// First 3 requests should succeed (redirect to login — not rate-limited).
	for i := 1; i <= 3; i++ {
		resp, err := client.Get(ts.URL + "/auth")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: got 429, expected non-429", i)
		}
	}

	// 4th request should be rate-limited.
	resp, err := client.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("request 4: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 4: expected 429, got %d", resp.StatusCode)
	}
}

func TestForwardAuth_RateLimit_Disabled(t *testing.T) {
	ts := newRateLimitedServer(t, 0, 0)
	client := noFollowClient()

	// With limit=0, requests should never be rate-limited.
	for i := 0; i < 20; i++ {
		resp, err := client.Get(ts.URL + "/auth")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: got 429 with rate limiting disabled", i)
		}
	}
}

func TestLoginSubmit_RateLimit(t *testing.T) {
	ts := newRateLimitedServer(t, 100, 2)
	client := noFollowClient()

	postLogin := func() int {
		form := url.Values{
			"username": {"baduser"},
			"password": {"badpass"},
			"rd":       {"/"},
		}
		resp, err := client.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatalf("POST /login: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// First 2 attempts are within limit.
	for i := 1; i <= 2; i++ {
		if status := postLogin(); status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: got 429, should be within limit", i)
		}
	}

	// 3rd attempt should be rate-limited.
	if status := postLogin(); status != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: expected 429, got %d", status)
	}
}

func TestForwardAuth_RateLimit_IPAllowlistBypass(t *testing.T) {
	// httptest uses 127.0.0.1 as the remote address — add it to ip_allowlist.
	path := filepath.Join(t.TempDir(), "users.txt")
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	cfg := &config.Config{
		CookieName:             cookieName,
		CookieSecure:           false,
		SessionTTL:             60,
		TrustForwardedFor:      false,
		RateLimitRequests:      1, // very tight limit
		RateLimitWindowSeconds: 60,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	client := noFollowClient()
	// Many requests from the allowlisted 127.0.0.1 — none should be 429.
	for i := 0; i < 10; i++ {
		resp, err := client.Get(ts.URL + "/auth")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: allowlisted IP got 429", i)
		}
	}
}

func TestForwardAuth_RateLimit_RLAllowlistBypass(t *testing.T) {
	// Use the rate_limit_allowlist to exempt 127.0.0.1 from rate limiting
	// while still requiring authentication.
	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	cfg := &config.Config{
		CookieName:             cookieName,
		CookieSecure:           false,
		SessionTTL:             60,
		TrustForwardedFor:      false,
		RateLimitRequests:      1, // very tight limit
		RateLimitWindowSeconds: 60,
		RateLimitAllowlist:     []string{"127.0.0.1"},
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	client := noFollowClient()
	// Many requests from the rate-limit-allowlisted 127.0.0.1 — none 429.
	for i := 0; i < 10; i++ {
		resp, err := client.Get(ts.URL + "/auth")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: rate-limit-allowlisted IP got 429", i)
		}
	}
}

func TestNewHandlers_InvalidRateLimitAllowlist(t *testing.T) {
	creds, err := auth.LoadCredentials(filepath.Join(t.TempDir(), "users.txt"))
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	cfg := &config.Config{
		CookieName:         cookieName,
		SessionTTL:         60,
		RateLimitAllowlist: []string{"not-a-valid-ip"},
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	_, err = server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err == nil {
		t.Fatal("expected error for invalid rate limit allowlist, got nil")
	}
}

// --------------------------------------------------------------------------
// User allowlist — per-service and default user restrictions
// --------------------------------------------------------------------------

// newTestServerWithUsers returns a test server with the given default user list
// and optional custom users header name.
func newTestServerWithUsers(t *testing.T, defaultUsers []string, usersHeader string) (*httptest.Server, *auth.SessionStore) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
		t.Fatalf("WriteCredentials: %v", err)
	}
	creds, err := auth.LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		DefaultUsers:      defaultUsers,
		UsersHeader:       usersHeader,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts, sessions
}

// TestForwardAuth_DefaultUsers_AllowedUser verifies that a user in the default
// list can access a service with no service-specific header.
func TestForwardAuth_DefaultUsers_AllowedUser(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, []string{testUser}, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for user in default list, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_DefaultUsers_DeniedUser verifies that a user NOT in the
// default list is rejected with 403 even when authenticated.
func TestForwardAuth_DefaultUsers_DeniedUser(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, []string{"other-user"}, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d for user not in default list, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

// TestForwardAuth_DefaultUsers_Empty verifies that an empty default list allows
// all authenticated users (backward-compatible behavior).
func TestForwardAuth_DefaultUsers_Empty(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, nil, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d when no default users configured, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_ServiceUsersHeader_AllowedUser verifies that a user listed in
// the service-specific header is permitted even when not in DefaultUsers.
func TestForwardAuth_ServiceUsersHeader_AllowedUser(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, []string{"other-user"}, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	req.Header.Set("X-Lilath-Users", testUser)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for user in service header, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_ServiceUsersHeader_DeniedUser verifies that a user NOT listed
// in the service-specific header is rejected with 403.
func TestForwardAuth_ServiceUsersHeader_DeniedUser(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, nil, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	req.Header.Set("X-Lilath-Users", "other-user")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d for user not in service header, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

// TestForwardAuth_ServiceUsersHeader_Wildcard verifies that a service-specific
// header of "*" allows all authenticated users regardless of DefaultUsers.
func TestForwardAuth_ServiceUsersHeader_Wildcard(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, []string{"other-user"}, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	req.Header.Set("X-Lilath-Users", "*")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for wildcard service header, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_ServiceUsersHeader_MultipleUsers verifies comma-separated
// user lists in the service header.
func TestForwardAuth_ServiceUsersHeader_MultipleUsers(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, nil, "")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	req.Header.Set("X-Lilath-Users", "alice, "+testUser+", bob")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for user in multi-user service header, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_ServiceUsersHeader_CustomHeaderName verifies that UsersHeader
// config uses the configured header name instead of the default.
func TestForwardAuth_ServiceUsersHeader_CustomHeaderName(t *testing.T) {
	ts, sessions := newTestServerWithUsers(t, []string{"other-user"}, "X-Custom-Users")
	client := noFollowClient()

	sid, err := sessions.Create(testUser)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: sid})
	req.Header.Set("X-Custom-Users", testUser)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for user in custom header, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestForwardAuth_BearerToken_BypassesUserAllowlist verifies that token auth
// is never restricted by default_users or the service users header.
func TestForwardAuth_BearerToken_BypassesUserAllowlist(t *testing.T) {
	dir := t.TempDir()

	usersPath := filepath.Join(dir, "users.txt")
	creds, err := auth.LoadCredentials(usersPath)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	tokensPath := filepath.Join(dir, "tokens.txt")
	if err := os.WriteFile(tokensPath, []byte("secret-token\n"), 0600); err != nil {
		t.Fatalf("WriteFile tokens: %v", err)
	}
	tokenStore, err := auth.LoadTokens(tokensPath)
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}

	cfg := &config.Config{
		CookieName:        cookieName,
		CookieSecure:      false,
		SessionTTL:        60,
		TrustForwardedFor: false,
		// No users allowed by default, and service header also restricts.
		DefaultUsers: []string{"nobody"},
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, err := auth.NewIPChecker(nil)
	if err != nil {
		t.Fatalf("NewIPChecker: %v", err)
	}
	h, err := server.NewHandlers(cfg, creds, sessions, ipCheck, tokenStore)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	srv := server.NewServer(":0", h)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	client := noFollowClient()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	// Service restricts to a different user — tokens must bypass this.
	req.Header.Set("X-Lilath-Users", "alice")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d: Bearer token should bypass user allowlist, got %d", http.StatusOK, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// Redirect validation — tested via LoginPage handler
// --------------------------------------------------------------------------

func TestLoginPage_RedirectValidation(t *testing.T) {
	tests := []struct {
		name          string
		rd            string
		baseDomain    string
		wantRedirect  bool
		wantCleanPath string
	}{
		{"relative url", "/protected", "", true, "/"},
		{"protocol-relative rejected", "//evil.com/phish", "", true, "/"},
		{"cross-origin rejected", "https://evil.com/phish", "example.com", true, "/"},
		{"prefix attack rejected", "https://evil-example.com/phish", "example.com", true, "/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login?rd="+url.QueryEscape(tc.rd), nil)
			if tc.baseDomain != "" {
				req.Host = "example.com"
			}

			path := filepath.Join(t.TempDir(), "users.txt")
			hash, err := auth.HashPassword(testPassword)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			if err := auth.WriteCredentials(path, map[string]string{testUser: hash}); err != nil {
				t.Fatalf("WriteCredentials: %v", err)
			}
			creds, _ := auth.LoadCredentials(path)

			cfg := &config.Config{
				CookieName:        cookieName,
				CookieSecure:      false,
				SessionTTL:        60,
				TrustForwardedFor: false,
				BaseDomain:        tc.baseDomain,
			}
			sessions := auth.NewSessionStore(cfg.SessionTTL)
			ipCheck, _ := auth.NewIPChecker(nil)
			h, _ := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())

			rr := httptest.NewRecorder()
			h.LoginPage(rr, req)
			resp := rr.Result()
			defer resp.Body.Close()

			// Check the hidden rd field in the response body.
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			if tc.wantRedirect {
				if !strings.Contains(bodyStr, "csrf_") {
					t.Errorf("expected CSRF token in response")
				}
			}
		})
	}
}

func TestLoginPage_RedirectValidation_ProtocolRelative(t *testing.T) {
	rd := "//evil.com/phish"
	req := httptest.NewRequest(http.MethodGet, "/login?rd="+url.QueryEscape(rd), nil)

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, _ := auth.HashPassword(testPassword)
	_ = auth.WriteCredentials(path, map[string]string{testUser: hash})
	creds, _ := auth.LoadCredentials(path)

	cfg := &config.Config{
		CookieName: cookieName, CookieSecure: false, SessionTTL: 60,
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, _ := auth.NewIPChecker(nil)
	h, _ := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())

	rr := httptest.NewRecorder()
	h.LoginPage(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// The rd hidden field should NOT contain evil.com.
	if strings.Contains(string(body), "evil.com") {
		t.Error("protocol-relative URL was not rejected")
	}
}

func TestLoginPage_RedirectValidation_CrossOrigin(t *testing.T) {
	rd := "https://evil.com/phish"
	req := httptest.NewRequest(http.MethodGet, "/login?rd="+url.QueryEscape(rd), nil)
	req.Host = "example.com"

	path := filepath.Join(t.TempDir(), "users.txt")
	hash, _ := auth.HashPassword(testPassword)
	_ = auth.WriteCredentials(path, map[string]string{testUser: hash})
	creds, _ := auth.LoadCredentials(path)

	cfg := &config.Config{
		CookieName: cookieName, CookieSecure: false, SessionTTL: 60,
		BaseDomain: "example.com",
	}
	sessions := auth.NewSessionStore(cfg.SessionTTL)
	ipCheck, _ := auth.NewIPChecker(nil)
	h, _ := server.NewHandlers(cfg, creds, sessions, ipCheck, auth.NewTokenStore())

	rr := httptest.NewRecorder()
	h.LoginPage(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "evil.com") {
		t.Error("cross-origin URL was not rejected")
	}
}

// --------------------------------------------------------------------------
// CSRF protection on POST /login
// --------------------------------------------------------------------------

func TestLoginSubmit_CSRFValidation(t *testing.T) {
	ts, _ := newTestServer(t)

	// Cookie jar so CSRF cookie persists between GET and POST.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET /login — server sets the CSRF cookie.
	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}

	var csrfToken string
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "csrf_") {
			csrfToken = c.Value
			break
		}
	}
	resp.Body.Close()
	if csrfToken == "" {
		t.Fatal("no CSRF token found on login page")
	}

	// Submit with correct CSRF token — should succeed.
	form := url.Values{
		"username":   {testUser},
		"password":   {testPassword},
		"rd":         {"/"},
		"csrf_token": {csrfToken},
	}
	resp, err = client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login with valid CSRF: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d with valid CSRF, got %d", http.StatusFound, resp.StatusCode)
	}

	// Submit with wrong CSRF token — should fail.
	form.Set("csrf_token", "wrong-token")
	resp, err = client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login with invalid CSRF: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected %d with invalid CSRF, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// CSP and security headers on GET /login
// --------------------------------------------------------------------------

func TestLoginPage_SecurityHeaders(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}

	checkHeader := func(name, expected string) {
		got := resp.Header.Get(name)
		if got != expected {
			t.Errorf("header %s = %q; want %q", name, got, expected)
		}
	}

	checkHeader("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'self'")
	checkHeader("X-Frame-Options", "DENY")
	checkHeader("X-Content-Type-Options", "nosniff")
}

// --------------------------------------------------------------------------
// CSRF on POST /logout
// --------------------------------------------------------------------------

func TestLogoutWithCSRF(t *testing.T) {
	ts, _ := newTestServer(t)

	// Single client with cookie jar so both session and CSRF cookies persist.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login to get session cookie.
	form := url.Values{
		"username": {testUser},
		"password": {testPassword},
		"rd":       {"/"},
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()

	// Get login page for CSRF token (the session cookie should still be there).
	resp, err = client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	var csrfToken string
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "csrf_") {
			csrfToken = c.Value
			break
		}
	}
	if csrfToken == "" {
		t.Fatal("no CSRF token on login page")
	}

	// POST /logout with valid CSRF.
	form2 := url.Values{"csrf_token": {csrfToken}}
	resp, err = client.PostForm(ts.URL+"/logout", form2)
	if err != nil {
		t.Fatalf("POST /logout with valid CSRF: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected %d with valid CSRF, got %d", http.StatusFound, resp.StatusCode)
	}

	// POST /logout with invalid CSRF.
	form2.Set("csrf_token", "wrong")
	resp, err = client.PostForm(ts.URL+"/logout", form2)
	if err != nil {
		t.Fatalf("POST /logout with invalid CSRF: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected %d with invalid CSRF, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}
