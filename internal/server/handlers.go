package server

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alanaktion/lilath/internal/auth"
	"github.com/alanaktion/lilath/internal/config"
)

//go:embed templates
var templateFS embed.FS

var defaultLoginTmpl = template.Must(
	template.ParseFS(templateFS, "templates/login.html"),
)

// Handlers bundles all HTTP handler state.
type Handlers struct {
	cfg              *config.Config
	creds            *auth.Credentials
	sessions         *auth.SessionStore
	ipCheck          *auth.IPChecker
	tokens           *auth.TokenStore
	loginTmpl        *template.Template
	rateLimiter      *auth.RateLimiter
	loginRateLimiter *auth.RateLimiter
	rlAllowlist      *auth.IPChecker
}

func NewHandlers(
	cfg *config.Config,
	creds *auth.Credentials,
	sessions *auth.SessionStore,
	ipCheck *auth.IPChecker,
	tokens *auth.TokenStore,
) (*Handlers, error) {
	tmpl := defaultLoginTmpl
	if cfg.LoginTemplate != "" {
		t, err := template.ParseFiles(cfg.LoginTemplate)
		if err != nil {
			return nil, fmt.Errorf("loading login template %q: %w", cfg.LoginTemplate, err)
		}
		tmpl = t
	}

	rlAllowlist, err := auth.NewIPChecker(cfg.RateLimitAllowlist)
	if err != nil {
		return nil, fmt.Errorf("parsing rate limit allowlist: %w", err)
	}

	window := time.Duration(cfg.RateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Minute
	}

	return &Handlers{
		cfg:              cfg,
		creds:            creds,
		sessions:         sessions,
		ipCheck:          ipCheck,
		tokens:           tokens,
		loginTmpl:        tmpl,
		rateLimiter:      auth.NewRateLimiter(cfg.RateLimitRequests, window),
		loginRateLimiter: auth.NewRateLimiter(cfg.RateLimitLoginRequests, window),
		rlAllowlist:      rlAllowlist,
	}, nil
}

// ForwardAuth is the Traefik forwardAuth endpoint.
// Returns 200 when the request is authenticated, 302 to /login otherwise.
func (h *Handlers) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	clientIP := auth.ClientIP(r, h.cfg.TrustForwardedFor)

	// 1. Check IP allowlist — trusted IPs bypass auth and rate limiting.
	if !h.ipCheck.IsEmpty() {
		if clientIP != nil && h.ipCheck.Allow(clientIP) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// 2. Apply rate limiting (skip for IPs in the rate-limit allowlist).
	if clientIP != nil && !h.rlAllowlist.Allow(clientIP) {
		if !h.rateLimiter.AllowIP(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	// 3. Check Bearer token in Authorization header.
	if !h.tokens.IsEmpty() {
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if h.tokens.Allow(token) {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	// 4. Check HTTP Basic auth credentials. Never return 401 — if credentials
	// are absent or invalid, fall through to the session/login flow.
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Basic ") {
		if username, password, ok := r.BasicAuth(); ok && h.creds.Verify(username, password) {
			if !h.isUserAllowed(username, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("X-Auth-User", username)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// 5. Check session cookie.
	cookie, err := r.Cookie(h.cfg.CookieName)
	if err == nil && cookie.Value != "" {
		sess := h.sessions.Get(cookie.Value)
		if sess != nil {
			if !h.isUserAllowed(sess.Username, r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h.sessions.Refresh(cookie.Value)
			w.Header().Set("X-Auth-User", sess.Username)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Not authenticated — redirect to login, encoding the original URI.
	originalURI := r.Header.Get("X-Forwarded-Uri")
	if originalURI == "" {
		originalURI = "/"
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")

	var loginURL string
	if h.cfg.BaseDomain != "" {
		rd := originalURI
		if host != "" && strings.HasPrefix(originalURI, "/") {
			rd = proto + "://" + host + originalURI
		}
		loginURL = proto + "://" + normalizeBaseDomain(h.cfg.BaseDomain) + "/login?rd=" + url.QueryEscape(rd)
	} else if host != "" {
		// Use the forwarded host/proto for the redirect when available.
		loginURL = proto + "://" + host + "/login?rd=" + url.QueryEscape(originalURI)
	} else {
		// Fall back to a relative redirect when no forwarded host is available.
		loginURL = "/login?rd=" + url.QueryEscape(originalURI)
	}

	http.Redirect(w, r, loginURL, http.StatusFound)
}

type loginData struct {
	Error      string
	RedirectURL string
	CSRFToken  string
}

// LoginPage renders the login form.
func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = "/"
	}

	// Validate redirect URL: allow relative paths and same-domain / subdomain URLs.
	if !isValidRedirect(rd, h.cfg.BaseDomain, r.Host) {
		rd = "/"
	}

	// Generate CSRF token and store it in a dedicated cookie.
	csrfToken := generateCSRFToken()
	if csrfToken == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName(h.cfg.BaseDomain),
		Value:    csrfToken,
		Path:     "/",
		Domain:   cookieDomain(h.cfg.BaseDomain),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := h.loginTmpl.Execute(w, loginData{Error: "", RedirectURL: rd, CSRFToken: csrfToken}); err != nil {
		log.Printf("template error: %v", err)
	}
}

// LoginSubmit handles credential submission.
func (h *Handlers) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	// Apply login rate limiting. Skip for IPs in the auth allowlist or
	// rate-limit allowlist.
	clientIP := auth.ClientIP(r, h.cfg.TrustForwardedFor)
	if clientIP != nil && !h.ipCheck.Allow(clientIP) && !h.rlAllowlist.Allow(clientIP) {
		if !h.loginRateLimiter.AllowIP(clientIP) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	rd := r.FormValue("rd")
	if rd == "" {
		rd = "/"
	}

	// Validate CSRF token — must be present and matching.
	csrfCookie, csrfErr := r.Cookie(csrfCookieName(h.cfg.BaseDomain))
	csrfForm := r.FormValue("csrf_token")
	if csrfErr != nil || csrfCookie.Value == "" || csrfForm == "" {
		csrfToken := generateCSRFToken()
		if csrfToken == "" {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName(h.cfg.BaseDomain),
			Value:    csrfToken,
			Path:     "/",
			Domain:   cookieDomain(h.cfg.BaseDomain),
			HttpOnly: true,
			Secure:   h.cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		if err := h.loginTmpl.Execute(w, loginData{Error: "CSRF token missing or invalid.", RedirectURL: rd, CSRFToken: csrfToken}); err != nil {
			log.Printf("template error: %v", err)
		}
		return
	}
	if !constantTimeEqual([]byte(csrfCookie.Value), []byte(csrfForm)) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		if err := h.loginTmpl.Execute(w, loginData{Error: "Invalid or expired CSRF token.", RedirectURL: rd, CSRFToken: csrfCookie.Value}); err != nil {
			log.Printf("template error: %v", err)
		}
		return
	}

	// Validate redirect URL before using it.
	if !isValidRedirect(rd, h.cfg.BaseDomain, r.Host) {
		rd = "/"
	}

	if !h.creds.Verify(username, password) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if err := h.loginTmpl.Execute(w, loginData{Error: "Invalid username or password.", RedirectURL: rd}); err != nil {
			log.Printf("template error: %v", err)
		}
		return
	}

	sessionID, err := h.sessions.Create(username)
	if err != nil {
		log.Printf("failed to create session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   cookieDomain(h.cfg.BaseDomain),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, rd, http.StatusFound)
}

// Logout deletes the session and clears the cookie.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(h.cfg.CookieName); err == nil {
		h.sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(h.cfg.BaseDomain),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// LogoutWithCSRF validates the CSRF token before clearing the session.
// Requires successful form parse and matching cookie+form tokens; returns 400 otherwise.
func (h *Handlers) LogoutWithCSRF(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	csrfCookie, cookieErr := r.Cookie(csrfCookieName(h.cfg.BaseDomain))
	csrfForm := r.FormValue("csrf_token")
	if cookieErr != nil || csrfCookie.Value == "" || csrfForm == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !constantTimeEqual([]byte(csrfCookie.Value), []byte(csrfForm)) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.Logout(w, r)
}

// isValidRedirect reports whether rd is a safe redirect target.
// It allows:
//   - Relative paths (/path, ./relative, ../parent)
//   - Absolute http(s) URLs to same-host or subdomains of BaseDomain
// It rejects protocol-relative URLs (//evil.com), non-http(s) schemes,
// and cross-origin absolute URLs.
func isValidRedirect(rd, baseDomain, requestHost string) bool {
	if rd == "" {
		return false
	}
	// Reject protocol-relative URLs — they bypass the origin check entirely.
	if strings.HasPrefix(rd, "//") {
		return false
	}
	// Allow relative paths (/, ./, ../).
	switch {
	case rd == "/", rd == ".", rd == "..":
		return true
	case strings.HasPrefix(rd, "/"),
		strings.HasPrefix(rd, "./"),
		strings.HasPrefix(rd, "../"):
		return true
	}
	// Parse as absolute URL and validate the scheme/host.
	parsed, err := url.Parse(rd)
	if err != nil {
		return false
	}
	// Only allow http/https schemes.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	// Normalize requestHost for comparison (strip port and brackets, then lower-case).
	normalizedHost := strings.TrimSpace(requestHost)
	if strings.HasPrefix(normalizedHost, "[") {
		if end := strings.Index(normalizedHost, "]"); end != -1 {
			normalizedHost = normalizedHost[1:end]
		}
	} else if i := strings.LastIndex(normalizedHost, ":"); i != -1 {
		normalizedHost = normalizedHost[:i]
	}
	normalizedHost = strings.ToLower(normalizeBaseDomain(normalizedHost))
	if normalizedHost == "" {
		normalizedHost = strings.ToLower(requestHost)
	}
	// Allow same-host redirects.
	if host == normalizedHost {
		return true
	}
	// Allow subdomains of the configured base domain (cookie scope).
	if bd := strings.ToLower(normalizeBaseDomain(baseDomain)); bd != "" {
		// Exact match on base domain.
		if host == bd {
			return true
		}
		// Subdomain: host must end with .$bd (with dot to prevent prefix matches).
		if strings.HasSuffix(host, "."+bd) {
			return true
		}
	}
	return false
}

// generateCSRFToken generates a cryptographically random CSRF token.
// Returns empty string and logs an error if the system RNG fails.
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("CSRF token generation failed: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

// csrfCookieName returns the name used for the CSRF cookie.
func csrfCookieName(baseDomain string) string {
	domain := normalizeBaseDomain(baseDomain)
	if domain == "" {
		return "csrf_token"
	}
	return "csrf_" + strings.ReplaceAll(domain, ".", "_")
}

// isUserAllowed reports whether username is permitted to access the service
// indicated by the current request. It first checks for a service-specific
// user list carried in the configured header (set by a Traefik headers
// middleware and forwarded via authRequestHeaders). If that header is absent,
// it falls back to cfg.DefaultUsers. An empty DefaultUsers list means all
// authenticated users are allowed. The special value "*" in the header means
// all users are allowed regardless of DefaultUsers.
func (h *Handlers) isUserAllowed(username string, r *http.Request) bool {
	headerName := h.cfg.UsersHeader
	if headerName == "" {
		headerName = "X-Lilath-Users"
	}

	if headerVal := strings.TrimSpace(r.Header.Get(headerName)); headerVal != "" {
		if headerVal == "*" {
			return true
		}
		for _, u := range splitUsers(headerVal) {
			if u == username {
				return true
			}
		}
		return false
	}

	// No service-specific header — apply the default user list.
	if len(h.cfg.DefaultUsers) == 0 {
		return true
	}
	for _, u := range h.cfg.DefaultUsers {
		if u == username {
			return true
		}
	}
	return false
}

// splitUsers splits a comma-separated list of usernames, trimming whitespace.
func splitUsers(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if u := strings.TrimSpace(p); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func normalizeBaseDomain(base string) string {
	return strings.TrimPrefix(strings.TrimSpace(base), ".")
}

func cookieDomain(base string) string {
	return normalizeBaseDomain(base)
}

// constantTimeEqual compares two strings in constant time.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
