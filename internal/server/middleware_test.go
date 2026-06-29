package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	if !rl.allow("ip1") || !rl.allow("ip1") {
		t.Fatal("first 2 requests should be allowed")
	}
	if rl.allow("ip1") {
		t.Fatal("3rd request from same client should be blocked")
	}
	if !rl.allow("ip2") {
		t.Fatal("a different client should not be affected")
	}
}

// stubAuth implements the authenticator interface for middleware tests.
type stubAuth struct {
	email, role string
	err         error
}

func (stubAuth) MountRoutes(chi.Router) {}
func (s stubAuth) SessionFromRequest(*http.Request) (string, string, error) {
	return s.email, s.role, s.err
}
func (stubAuth) ValidateEnrollmentToken(string) (string, error) { return "", nil }

func runMW(mw func(http.Handler) http.Handler, req *http.Request) (*httptest.ResponseRecorder, bool) {
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, called
}

func TestRequireAuth_FailsClosedWithoutProvider(t *testing.T) {
	// Regression: a nil auth provider previously allowed all requests through.
	s := &Server{}
	rec, called := runMW(s.requireAuth, httptest.NewRequest("GET", "/api/devices", nil))
	if called {
		t.Fatal("handler ran with no auth provider configured")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestRequireAuth_RejectsUnauthenticated(t *testing.T) {
	s := &Server{auth: stubAuth{err: errors.New("no session")}}
	rec, called := runMW(s.requireAuth, httptest.NewRequest("GET", "/api/devices", nil))
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 and no handler call, got code=%d called=%v", rec.Code, called)
	}
}

func TestRequireAuth_PassesIdentityToContext(t *testing.T) {
	s := &Server{auth: stubAuth{email: "a@b.com", role: "admin"}}
	var gotEmail, gotRole string
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEmail = emailFromContext(r.Context())
		gotRole = roleFromContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/me", nil))
	if gotEmail != "a@b.com" || gotRole != "admin" {
		t.Fatalf("identity not propagated: email=%q role=%q", gotEmail, gotRole)
	}
}

func TestRequireRole(t *testing.T) {
	s := &Server{}
	admin := s.requireRole("admin", "super_admin")

	req := func(role string) *http.Request {
		return httptest.NewRequest("POST", "/api/devices/x/wipe", nil).
			WithContext(contextWithRole(context.Background(), role))
	}

	if rec, called := runMW(admin, req("user")); called || rec.Code != http.StatusForbidden {
		t.Fatalf("user role should be forbidden, got code=%d called=%v", rec.Code, called)
	}
	if rec, called := runMW(admin, req("admin")); !called || rec.Code != http.StatusOK {
		t.Fatalf("admin role should pass, got code=%d called=%v", rec.Code, called)
	}
	if rec, called := runMW(admin, req("super_admin")); !called || rec.Code != http.StatusOK {
		t.Fatalf("super_admin role should pass, got code=%d called=%v", rec.Code, called)
	}
}
