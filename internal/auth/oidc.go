// Package auth handles user authentication via OIDC (Google, Okta, Azure, etc),
// LDAP, or built-in username/password. It also issues enrollment tokens that
// the device presents during MS-WSTEP certificate enrollment.
package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"golang.org/x/oauth2"
)

const (
	// enrollmentTokenExpiry is how long an enrollment token is valid.
	// Short because it's only used during the enrollment flow (minutes).
	enrollmentTokenExpiry = 20 * time.Minute

	// sessionTokenExpiry is how long a dashboard session lasts.
	sessionTokenExpiry = 12 * time.Hour

	sessionCookieName = "pane_session"
)

// nowFunc returns the current time; overridable in tests for deterministic
// token issuance/expiry.
var nowFunc = time.Now

// Provider handles OIDC authentication for both the admin dashboard
// and the device enrollment flow.
type Provider struct {
	oidcProvider *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	jwtSecret    []byte
	db           *sql.DB

	// allowedDomains restricts login to specific email domains.
	// Empty = any authenticated account can log in.
	allowedDomains []string

	// baseURL is our public server URL, used for the OAuth2 redirect URI.
	baseURL string
}

// Claims are embedded in both enrollment tokens and session tokens.
type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
	// TokenType distinguishes enrollment tokens from session tokens
	TokenType string `json:"tt"`
}

// New creates an OIDC auth provider.
// The jwtSecret is used to sign enrollment tokens and session JWTs.
func New(ctx context.Context, db *sql.DB, issuer, clientID, clientSecret, baseURL string, allowedDomains []string, jwtSecret []byte) (*Provider, error) {
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("jwtSecret must be at least 32 bytes")
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("connecting to OIDC provider %q: %w", issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	oauth2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  baseURL + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return &Provider{
		oidcProvider:   provider,
		oauth2Config:   oauth2Cfg,
		verifier:       verifier,
		jwtSecret:      jwtSecret,
		db:             db,
		allowedDomains: allowedDomains,
		baseURL:        baseURL,
	}, nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// HandleLogin starts the OIDC login flow by redirecting to the identity provider.
// This URL is opened in a webview by Windows during device enrollment,
// or visited directly by admins accessing the dashboard.
// GET /auth/login
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// State encodes whether this is an enrollment flow or dashboard login, plus appru if any
	flowType := r.URL.Query().Get("flow") // "enroll" or "dashboard"
	if flowType == "" {
		flowType = "dashboard"
	}

	appru := r.URL.Query().Get("appru")
	loginHint := r.URL.Query().Get("login_hint")

	// State encodes: uuid : flowType : appru (b64) : loginHint (b64)
	state := uuid.New().String() + ":" + flowType + ":" +
		base64.RawURLEncoding.EncodeToString([]byte(appru)) + ":" +
		base64.RawURLEncoding.EncodeToString([]byte(loginHint))

	// Store state in a short-lived cookie for CSRF protection
	http.SetCookie(w, &http.Cookie{
		Name:     "pane_oauth_state",
		Value:    state,
		Path:     "/auth",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}

	// If the client provided a login hint (like entering an email in the Windows dialog),
	// pass it to the IdP. Also, for device enrollment, we usually want to force an account
	// selection prompt so it doesn't silently authenticate the wrong active session.
	if loginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	if flowType == "enroll" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
	}

	authURL := p.oauth2Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback is the OAuth2 redirect target after the user authenticates.
// For enrollment flow: issues an enrollment token and renders a page that
// passes the token back to the Windows enrollment agent.
// For dashboard flow: issues a session cookie and redirects to the dashboard.
// GET /auth/callback
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state (CSRF check)
	stateCookie, err := r.Cookie("pane_oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		slog.Warn("auth: invalid OAuth2 state", "remote", r.RemoteAddr)
		http.Error(w, "invalid state — please try logging in again", http.StatusBadRequest)
		return
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "pane_oauth_state",
		Value:  "",
		MaxAge: -1,
		Path:   "/auth",
	})

	// Parse state to determine flow type, appru, and login_hint
	parts := strings.SplitN(stateCookie.Value, ":", 4)
	flowType := "dashboard"
	appru := ""
	loginHint := ""

	if len(parts) >= 2 {
		flowType = parts[1]
	}
	if len(parts) >= 3 {
		decodedAppru, _ := base64.RawURLEncoding.DecodeString(parts[2])
		appru = string(decodedAppru)
	}
	if len(parts) >= 4 {
		decodedHint, _ := base64.RawURLEncoding.DecodeString(parts[3])
		loginHint = string(decodedHint)
	}

	// Exchange the auth code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	oauth2Token, err := p.oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		slog.Error("auth: exchanging auth code", "err", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	// Verify the ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := p.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		slog.Error("auth: verifying ID token", "err", err)
		http.Error(w, "invalid ID token", http.StatusUnauthorized)
		return
	}

	// Extract user claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("auth: extracting claims", "err", err)
		http.Error(w, "failed to read user info", http.StatusInternalServerError)
		return
	}

	if !claims.EmailVerified {
		http.Error(w, "email address not verified with identity provider", http.StatusForbidden)
		return
	}

	// Enforce that the authenticated user matches the originally intended login_hint
	if loginHint != "" && !strings.EqualFold(claims.Email, loginHint) {
		slog.Warn("auth: email mismatch during enrollment", "expected", loginHint, "got", claims.Email)

		msg := fmt.Sprintf("Account mismatch: You entered %s in Windows, but authenticated as %s. Please restart enrollment.", loginHint, claims.Email)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Return 200 OK so the Windows Web Authentication Broker renders the HTML error
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>Enrollment Failed</title></head><body style=\"font-family:sans-serif;padding:20px;\"><h2 style=\"color:#d32f2f;\">Enrollment Failed</h2><p>%s</p></body></html>", msg)
		return
	}

	// Domain restriction check
	if !p.isEmailAllowed(claims.Email) {
		slog.Warn("auth: login rejected — domain not allowed",
			"email", claims.Email,
			"allowed_domains", p.allowedDomains,
		)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Return 200 OK so the Windows Web Authentication Broker renders the HTML error
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(accessDeniedPage(claims.Email)))
		return
	}

	// Find or create user in our DB
	role, err := p.upsertUser(r.Context(), claims.Email, claims.Name)
	if err != nil {
		slog.Error("auth: upserting user", "err", err, "email", claims.Email)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("user authenticated", "email", claims.Email, "role", role, "flow", flowType)

	switch flowType {
	case "enroll":
		// Issue a short-lived enrollment token and pass it back to the Windows
		// enrollment agent via a Form POST to the appru URL.
		p.handleEnrollmentCallback(w, r, claims.Email, appru)

	default:
		// Issue a session cookie and redirect to the dashboard.
		p.handleDashboardCallback(w, r, claims.Email, role)
	}
}

// HandleLogout clears the session cookie.
// POST /auth/logout
func (p *Provider) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Token issuance ────────────────────────────────────────────────────────────

// handleEnrollmentCallback issues a short-lived enrollment token and renders
// an auto-submitting form that posts the token back to the Windows MDM client.
func (p *Provider) handleEnrollmentCallback(w http.ResponseWriter, r *http.Request, email, appru string) {
	token, err := p.issueEnrollmentToken(email)
	if err != nil {
		slog.Error("auth: issuing enrollment token", "err", err)
		http.Error(w, "failed to issue enrollment token", http.StatusInternalServerError)
		return
	}

	// If no appru was provided, fallback to the legacy window.external.notify method
	if appru == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, enrollmentCallbackPageLegacy, email, token)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, enrollmentCallbackPageAppru, email, appru, token)
}

// handleDashboardCallback issues a session JWT as an HTTP-only cookie.
func (p *Provider) handleDashboardCallback(w http.ResponseWriter, r *http.Request, email, role string) {
	sessionToken, err := p.issueSessionToken(email, role)
	if err != nil {
		slog.Error("auth: issuing session token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(sessionTokenExpiry.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// issueEnrollmentToken creates a short-lived JWT used as the WS-Trust security token.
func (p *Provider) issueEnrollmentToken(email string) (string, error) {
	now := nowFunc()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(enrollmentTokenExpiry)),
			ID:        uuid.New().String(),
		},
		Email:     email,
		TokenType: "enroll",
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString(p.jwtSecret)
}

// issueSessionToken creates a JWT for dashboard sessions stored as a cookie.
func (p *Provider) issueSessionToken(email, role string) (string, error) {
	now := nowFunc()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTokenExpiry)),
			ID:        uuid.New().String(),
		},
		Email:     email,
		Role:      role,
		TokenType: "session",
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString(p.jwtSecret)
}

// ValidateEnrollmentToken validates the JWT presented by a device during WSTEP.
// Returns the user email if valid.
func (p *Provider) ValidateEnrollmentToken(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.jwtSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token claims")
	}

	if claims.TokenType != "enroll" {
		return "", errors.New("not an enrollment token")
	}

	return claims.Email, nil
}

// ValidateSessionToken validates a dashboard session cookie JWT.
// Returns (email, role) if valid.
func (p *Provider) ValidateSessionToken(tokenStr string) (email, role string, err error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return p.jwtSecret, nil
	})
	if err != nil {
		return "", "", fmt.Errorf("parsing session token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid session")
	}

	if claims.TokenType != "session" {
		return "", "", errors.New("not a session token")
	}

	return claims.Email, claims.Role, nil
}

// SessionFromRequest extracts and validates the session token from the cookie.
func (p *Provider) SessionFromRequest(r *http.Request) (email, role string, err error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", "", errors.New("no session cookie")
	}
	return p.ValidateSessionToken(cookie.Value)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// isEmailAllowed checks the email against the configured domain allowlist.
func (p *Provider) isEmailAllowed(email string) bool {
	if len(p.allowedDomains) == 0 {
		return true // no restriction
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])
	for _, allowed := range p.allowedDomains {
		if strings.ToLower(allowed) == domain {
			return true
		}
	}
	return false
}

// upsertUser ensures the user exists in the database.
// On first login, creates the user with 'user' role.
// If this is the very first user ever, grants 'super_admin' (bootstrap).
func (p *Provider) upsertUser(ctx context.Context, email, displayName string) (role string, err error) {
	// Check if any users exist (bootstrap detection)
	var count int
	_ = p.db.QueryRowContext(ctx, dbpkg.Rebind(`SELECT COUNT(*) FROM users`)).Scan(&count)

	defaultRole := "user"
	if count == 0 {
		defaultRole = "super_admin"
		slog.Info("bootstrap: first user login — granting super_admin", "email", email)
	}

	_, err = p.db.ExecContext(ctx, dbpkg.Rebind(`
		INSERT INTO users (id, email, display_name, role, auth_provider, last_login)
		VALUES (?, ?, ?, ?, 'oidc', CURRENT_TIMESTAMP)
		ON CONFLICT(email) DO UPDATE SET
			display_name = excluded.display_name,
			last_login = CURRENT_TIMESTAMP
	`), uuid.New().String(), email, displayName, defaultRole)
	if err != nil {
		return "", fmt.Errorf("upserting user: %w", err)
	}

	// Fetch the actual role (may differ from default if user already exists)
	err = p.db.QueryRowContext(ctx, dbpkg.Rebind(`SELECT role FROM users WHERE email = ?`), email).Scan(&role)
	if err != nil {
		return "", fmt.Errorf("fetching user role: %w", err)
	}

	return role, nil
}

// ── HTML pages ────────────────────────────────────────────────────────────────

// enrollmentCallbackPageLegacy is the fallback if appru is missing.
const enrollmentCallbackPageLegacy = `<!DOCTYPE html>
<html>
<head><title>Latchz MDM — Enrolling...</title></head>
<body>
<p>Enrolling device for <strong>%s</strong>...</p>
<script>
  try {
    if (window.external && typeof window.external.notify === 'function') {
      window.external.notify('%s');
    }
  } catch(e) {
    document.body.innerHTML = '<p>Enrollment token issued. You may close this window.</p>';
  }
</script>
</body>
</html>`

// enrollmentCallbackPageAppru POSTs the token back to the Windows MDM client.
const enrollmentCallbackPageAppru = `<!DOCTYPE html>
<html>
<head><title>Latchz MDM — Authenticated</title></head>
<body onload="document.forms[0].submit()">
<p>Authentication successful for <strong>%s</strong>. Returning to Windows...</p>
<form method="POST" action="%s">
  <!-- Windows MDM client expects 'wresult' to contain the opaque token string -->
  <input type="hidden" name="wresult" value="%s">
  <noscript><input type="submit" value="Continue"></noscript>
</form>
</body>
</html>`

// accessDeniedPage is shown when a user's email domain is not on the allowlist.
func accessDeniedPage(email string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Access Denied — Latchz MDM</title></head>
<body>
<h1>Access Denied</h1>
<p>The account <strong>%s</strong> is not authorised to access this server.</p>
<p>Contact your administrator to be invited.</p>
</body>
</html>`, email)
}
