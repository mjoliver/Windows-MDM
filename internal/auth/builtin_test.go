package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	idb "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestPasswordHashRoundtrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password must not verify")
	}
	if VerifyPassword("x", "not-a-valid-hash") {
		t.Fatal("malformed hash must not verify")
	}
}

func TestBuiltin_LoginFlow(t *testing.T) {
	database := testutil.DB(t)
	secret := []byte("0123456789012345678901234567890123")
	p, err := NewBuiltin(database.DB, secret, "https://mdm.example.com", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Bootstrap admin exists but has no password yet → cannot authenticate.
	if _, ok := p.authenticate(context.Background(), "admin@example.com", "pw"); ok {
		t.Fatal("login should fail before a password is set")
	}

	// Set a password (as the admin CLI would).
	hash, _ := HashPassword("pw")
	if _, err := database.Exec(idb.Rebind(`UPDATE users SET password_hash = ? WHERE email = ?`), hash, "admin@example.com"); err != nil {
		t.Fatal(err)
	}

	role, ok := p.authenticate(context.Background(), "admin@example.com", "pw")
	if !ok || role != "super_admin" {
		t.Fatalf("authenticate = (%q,%v), want super_admin,true", role, ok)
	}

	// A POST without a matching CSRF token is rejected.
	noCSRF := httptest.NewRequest("POST", "/auth/login",
		strings.NewReader(url.Values{"email": {"admin@example.com"}, "password": {"pw"}}.Encode()))
	noCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wNoCSRF := httptest.NewRecorder()
	p.handleLoginSubmit(wNoCSRF, noCSRF)
	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", wNoCSRF.Code)
	}

	// Full login POST (with matching CSRF double-submit) issues a session cookie.
	const csrf = "test-csrf-token-value"
	form := url.Values{"email": {"admin@example.com"}, "password": {"pw"}, "csrf": {csrf}}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	w := httptest.NewRecorder()
	p.handleLoginSubmit(w, req)
	if w.Code != 302 {
		t.Fatalf("expected redirect after login, got %d", w.Code)
	}
	res := w.Result()
	var sessionCookie string
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("no session cookie set")
	}

	req2 := httptest.NewRequest("GET", "/api/me", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	email, gotRole, err := p.SessionFromRequest(req2)
	if err != nil || email != "admin@example.com" || gotRole != "super_admin" {
		t.Fatalf("SessionFromRequest = (%q,%q,%v)", email, gotRole, err)
	}
}
