package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/vault"
	"golang.org/x/crypto/argon2"
)

// BuiltinProvider implements username/password authentication backed by the
// users table (argon2id password hashes). It satisfies the same authenticator
// contract as the OIDC provider.
type BuiltinProvider struct {
	db             *sql.DB
	jwtSecret      []byte
	baseURL        string
	bootstrapAdmin string
	vault          *vault.Vault
}

// SetVault attaches the AES-256-GCM secret vault used to decrypt enrolled TOTP 2FA secrets.
func (p *BuiltinProvider) SetVault(v *vault.Vault) {
	p.vault = v
}

// NewBuiltin creates a builtin auth provider and ensures the bootstrap admin
// account exists (its password must be set via `latchz admin -password`).
func NewBuiltin(db *sql.DB, jwtSecret []byte, baseURL, bootstrapAdmin string) (*BuiltinProvider, error) {
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("jwtSecret must be at least 32 bytes")
	}
	if bootstrapAdmin != "" {
		_, err := db.Exec(dbpkg.Rebind(`
			INSERT INTO users (id, email, role, auth_provider)
			VALUES (?, ?, 'super_admin', 'builtin')
			ON CONFLICT(email) DO NOTHING
		`), uuid.New().String(), strings.ToLower(bootstrapAdmin))
		if err != nil {
			return nil, fmt.Errorf("ensuring bootstrap admin: %w", err)
		}
	}
	return &BuiltinProvider{db: db, jwtSecret: jwtSecret, baseURL: baseURL, bootstrapAdmin: strings.ToLower(bootstrapAdmin)}, nil
}

func (p *BuiltinProvider) MountRoutes(r chi.Router) {
	r.Get("/auth/login", p.handleLoginForm)
	r.Post("/auth/login", p.handleLoginSubmit)
	r.Post("/auth/logout", p.handleLogout)
}

func (p *BuiltinProvider) SessionFromRequest(r *http.Request) (email, role string, err error) {
	return sessionFromRequest(p.jwtSecret, r)
}

func (p *BuiltinProvider) ValidateEnrollmentToken(tokenStr string) (string, error) {
	return validateEnrollmentToken(p.jwtSecret, p.db, tokenStr)
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

const csrfCookieName = "latchz_csrf"

type builtinLoginData struct {
	Flow, Appru, Email, Error, CSRF string
	NeedTOTP                        bool
}

func (p *BuiltinProvider) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	p.renderLoginForm(w, r, http.StatusOK, builtinLoginData{
		Flow:  r.URL.Query().Get("flow"),
		Appru: r.URL.Query().Get("appru"),
		Email: r.URL.Query().Get("login_hint"),
	})
}

// renderLoginForm renders the login form with a CSRF double-submit token. It
// REUSES the existing CSRF cookie when present (so concurrent tabs / re-renders
// share one valid token) and only mints+sets a new one when absent.
func (p *BuiltinProvider) renderLoginForm(w http.ResponseWriter, r *http.Request, status int, data builtinLoginData) {
	csrf := ""
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		csrf = c.Value
	}
	if csrf == "" {
		csrf = randomToken()
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    csrf,
			Path:     "/auth",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	data.CSRF = csrf
	writeHTML(w, status, tmplBuiltinLogin, data)
}

func (p *BuiltinProvider) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// CSRF: the form-field token must match the SameSite=Strict cookie. A
	// cross-site POST cannot read the cookie nor set a matching field (and the
	// Strict cookie isn't even sent cross-site), so login CSRF is blocked.
	if !validCSRFToken(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.PostForm.Get("email")))
	password := r.PostForm.Get("password")
	flow := r.PostForm.Get("flow")
	appru := r.PostForm.Get("appru")

	if flow == "enroll" && strings.HasPrefix(strings.TrimSpace(password), BulkTokenPrefix) {
		rawBulk := strings.TrimSpace(password)
		ownerEmail, err := VerifyBulkEnrollmentTokenUnconsumed(p.db, rawBulk)
		if err != nil {
			p.renderLoginForm(w, r, http.StatusUnauthorized, builtinLoginData{
				Flow: flow, Appru: appru, Email: email, Error: err.Error(),
			})
			return
		}
		if appru == "" {
			writeHTML(w, http.StatusOK, tmplEnrollLegacy, struct{ Email, Token string }{ownerEmail, rawBulk})
			return
		}
		safe, ok := appruAllowed(appru, p.baseURL)
		if !ok {
			slog.Warn("auth: rejected enrollment return URL (appru)", "appru", appru, "email", ownerEmail)
			writeHTML(w, http.StatusBadRequest, tmplEnrollRejected, nil)
			return
		}
		writeHTML(w, http.StatusOK, tmplEnrollAppru, struct {
			Email, Token string
			Appru        template.URL
		}{ownerEmail, rawBulk, safe})
		return
	}

	role, ok := p.authenticate(r.Context(), email, password)
	if !ok {
		p.renderLoginForm(w, r, http.StatusUnauthorized, builtinLoginData{
			Flow: flow, Appru: appru, Email: email, Error: "Invalid email or password.",
		})
		return
	}

	var totpEnabled int
	_ = p.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT COALESCE(totp_enabled, 0) FROM users WHERE email = ?`), email).Scan(&totpEnabled)
	if totpEnabled != 0 {
		totpCode := strings.TrimSpace(r.PostForm.Get("totp_code"))
		if totpCode == "" {
			p.renderLoginForm(w, r, http.StatusUnauthorized, builtinLoginData{
				Flow: flow, Appru: appru, Email: email, NeedTOTP: true,
				Error: "Two-factor authentication enabled — enter your 6-digit TOTP or recovery code.",
			})
			return
		}
		mfaOK, err := VerifyUserSecondFactor(p.db, p.vault, email, totpCode, nowFunc())
		if err != nil || !mfaOK {
			p.renderLoginForm(w, r, http.StatusUnauthorized, builtinLoginData{
				Flow: flow, Appru: appru, Email: email, NeedTOTP: true,
				Error: "Invalid 2FA authenticator or recovery code.",
			})
			return
		}
	}

	_, _ = p.db.ExecContext(r.Context(), dbpkg.Rebind(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = ?`), email)

	if flow == "enroll" {
		token, err := signClaims(p.jwtSecret, newEnrollmentClaims(email, nowFunc()))
		if err != nil {
			http.Error(w, "failed to issue enrollment token", http.StatusInternalServerError)
			return
		}
		if appru == "" {
			writeHTML(w, http.StatusOK, tmplEnrollLegacy, struct{ Email, Token string }{email, token})
			return
		}
		safe, ok := appruAllowed(appru, p.baseURL)
		if !ok {
			slog.Warn("auth: rejected enrollment return URL (appru)", "appru", appru, "email", email)
			writeHTML(w, http.StatusBadRequest, tmplEnrollRejected, nil)
			return
		}
		writeHTML(w, http.StatusOK, tmplEnrollAppru, struct {
			Email, Token string
			Appru        template.URL
		}{email, token, safe})
		return
	}

	sessionToken, err := signClaims(p.jwtSecret, newSessionClaims(email, role, nowFunc()))
	if err != nil {
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

func (p *BuiltinProvider) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

// randomToken returns a URL-safe random token (used for CSRF).
func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// validCSRFToken checks the double-submit CSRF token: the form field must match
// the SameSite=Strict cookie (constant-time).
func validCSRFToken(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.PostForm.Get("csrf"))) == 1
}

// authenticate verifies a builtin user's password and returns their role.
func (p *BuiltinProvider) authenticate(ctx context.Context, email, password string) (role string, ok bool) {
	var hash string
	err := p.db.QueryRowContext(ctx, dbpkg.Rebind(
		`SELECT COALESCE(password_hash, ''), role FROM users WHERE email = ? AND auth_provider = 'builtin'`,
	), email).Scan(&hash, &role)
	if err != nil || hash == "" {
		return "", false
	}
	if !VerifyPassword(password, hash) {
		return "", false
	}
	return role, true
}

// ── Password hashing (argon2id) ───────────────────────────────────────────────

const (
	pwTime    = 2
	pwMemory  = 64 * 1024
	pwThreads = 4
	pwKeyLen  = 32
	pwSaltLen = 16
)

// HashPassword returns an argon2id PHC-ish encoding: "argon2id$<salt>$<hash>".
func HashPassword(password string) (string, error) {
	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, pwTime, pwMemory, pwThreads, pwKeyLen)
	return fmt.Sprintf("argon2id$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a HashPassword encoding in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, pwTime, pwMemory, pwThreads, pwKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

var tmplBuiltinLogin = template.Must(template.New("builtinLogin").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latchz MDM — Sign In</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background-color: #0F0F12;
    background-image:
      radial-gradient(circle at 80% 0%, rgba(208, 188, 255, 0.12), transparent 45%),
      radial-gradient(circle at 20% 100%, rgba(79, 55, 139, 0.16), transparent 45%);
    color: #E6E1E5;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    color-scheme: dark;
  }
  .card {
    width: 100%;
    max-width: 400px;
    padding: 40px 36px;
    background: rgba(28, 27, 31, 0.85);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 24px;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.55);
  }
  .badge {
    width: 52px;
    height: 52px;
    border-radius: 16px;
    background: #4F378B;
    color: #EADDFF;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 1.35rem;
    margin-bottom: 20px;
  }
  h1 { font-size: 1.65rem; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 6px; }
  .sub { font-size: 0.9rem; color: #CAC4D0; margin-bottom: 28px; }
  .error {
    background: rgba(242, 184, 181, 0.12);
    border: 1px solid rgba(242, 184, 181, 0.35);
    color: #F2B8B5;
    padding: 12px 14px;
    border-radius: 10px;
    font-size: 0.85rem;
    margin-bottom: 20px;
  }
  label { display: block; font-size: 0.8rem; font-weight: 600; color: #CAC4D0; margin-bottom: 6px; }
  .field { margin-bottom: 16px; }
  input[type="email"], input[type="password"] {
    width: 100%;
    padding: 12px 14px;
    background: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px;
    color: #FFFFFF;
    font-size: 0.95rem;
    outline: none;
    transition: border-color 0.15s ease;
  }
  input:focus { border-color: #D0BCFF; }
  button {
    width: 100%;
    margin-top: 8px;
    padding: 13px 20px;
    border: none;
    border-radius: 12px;
    background: #D0BCFF;
    color: #381E72;
    font-size: 0.95rem;
    font-weight: 700;
    cursor: pointer;
    transition: filter 0.15s ease;
  }
  button:hover { filter: brightness(1.06); }
</style>
</head>
<body>
<div class="card">
  <div class="badge">L</div>
  <h1>Latchz MDM</h1>
  <p class="sub">{{if eq .Flow "enroll"}}Sign in to enroll this Windows device{{else}}Sign in to manage your Windows fleet{{end}}</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST" action="/auth/login">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="flow" value="{{.Flow}}">
    <input type="hidden" name="appru" value="{{.Appru}}">
    <div class="field">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" placeholder="admin@lab.local" value="{{.Email}}" autocomplete="username" autofocus required>
    </div>
    <div class="field">
      <label for="password">{{if eq .Flow "enroll"}}Password or Bulk Token (lzbt_…){{else}}Password{{end}}</label>
      <input id="password" name="password" type="password" placeholder="••••••••" autocomplete="current-password" required>
    </div>
    <div class="field">
      <label for="totp_code">2FA Code {{if not .NeedTOTP}}(if enabled){{end}}</label>
      <input id="totp_code" name="totp_code" type="password" placeholder="6-digit TOTP or XXXX-XXXX" autocomplete="one-time-code" {{if .NeedTOTP}}required{{end}}>
    </div>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`))
