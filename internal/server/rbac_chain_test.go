package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/config"
)

func TestBehindProxy(t *testing.T) {
	cases := []struct {
		name              string
		mode              string
		trustCert, trustP bool
		want              bool
	}{
		{"tls none (terminated upstream)", "none", false, false, true},
		{"explicit trusted_proxy", "manual", false, true, true},
		{"trust_proxy_client_cert implies proxy", "manual", true, false, true},
		{"direct manual TLS", "manual", false, false, false},
		{"direct auto TLS", "auto", false, false, false},
		{"direct self-signed", "self-signed", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{cfg: &config.Config{}}
			s.cfg.TLS.Mode = c.mode
			s.cfg.TLS.TrustProxyClientCert = c.trustCert
			s.cfg.Server.TrustedProxy = c.trustP
			if got := s.behindProxy(); got != c.want {
				t.Fatalf("behindProxy() = %v, want %v", got, c.want)
			}
		})
	}
}

// Confirms the real chi composition: group Use(requireAuth) runs BEFORE the
// route's With(requireRole), so requireRole sees the role requireAuth set.
func TestRBACChain_Integration(t *testing.T) {
	s := &Server{auth: stubAuth{email: "u@x", role: "user"}}
	admin := s.requireRole("admin", "super_admin")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.With(admin).Post("/wipe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	})

	// user role → 403 (requireAuth set role, requireRole rejected)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/wipe", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user role: want 403, got %d", rec.Code)
	}

	// admin role → 200
	s2 := &Server{auth: stubAuth{email: "a@x", role: "admin"}}
	r2 := chi.NewRouter()
	r2.Group(func(r chi.Router) {
		r.Use(s2.requireAuth)
		r.With(s2.requireRole("admin")).Post("/wipe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	})
	rec2 := httptest.NewRecorder()
	r2.ServeHTTP(rec2, httptest.NewRequest("POST", "/wipe", nil))
	if rec2.Code != 200 {
		t.Fatalf("admin role: want 200, got %d", rec2.Code)
	}
}
