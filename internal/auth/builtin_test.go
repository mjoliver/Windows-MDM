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

	// Full login POST issues a session cookie that SessionFromRequest accepts.
	form := url.Values{"email": {"admin@example.com"}, "password": {"pw"}}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
