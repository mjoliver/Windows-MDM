// Package server sets up the HTTPS server with all routes for Pane.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchzmdm/latchz/internal/api"
	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/config"
	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/enrollment"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/pki"
)

// authenticator is the auth-provider contract the server depends on. Concrete
// implementations (OIDC, builtin) mount their own login endpoints and validate
// sessions + enrollment tokens. Keeping this an interface lets the server fail
// closed when no provider is configured rather than wiring a permissive bypass.
type authenticator interface {
	// MountRoutes registers the provider's login/callback/logout endpoints.
	MountRoutes(r chi.Router)
	// SessionFromRequest validates the session cookie and returns the identity.
	SessionFromRequest(r *http.Request) (email, role string, err error)
	// ValidateEnrollmentToken validates a device enrollment token and returns
	// the authenticated user's email.
	ValidateEnrollmentToken(token string) (email string, err error)
}

// Server is the Pane HTTPS server.
type Server struct {
	cfg        *config.Config
	db         *db.DB
	ca         *pki.CA
	auth       authenticator
	enrollment *enrollment.Handler
	mdm        *mdm.Handler
	api        *api.Handler
	mux        *chi.Mux
}

// New creates and configures the server and all its routes.
func New(cfg *config.Config, database *db.DB, ca *pki.CA) (*Server, error) {
	// JWT secret signs session + enrollment tokens. Prefer a stable, operator-
	// supplied secret (auth.jwt_secret / LATCHZ_AUTH_JWT_SECRET) so sessions
	// survive restarts and are valid across horizontally-scaled instances.
	// Only fall back to a random per-process secret in dev, with a loud warning.
	var jwtSecret []byte
	if s := cfg.Auth.JWTSecret; s != "" {
		jwtSecret = []byte(s)
	} else {
		jwtSecret = make([]byte, 64)
		if _, err := rand.Read(jwtSecret); err != nil {
			return nil, fmt.Errorf("generating jwt secret: %w", err)
		}
		slog.Warn("auth.jwt_secret is not set — using a random per-process secret. " +
			"Sessions will be invalidated on restart and will not work across multiple instances. " +
			"Set LATCHZ_AUTH_JWT_SECRET to a stable 32+ byte value in production.")
	}

	authProvider, err := buildAuthenticator(cfg, database.DB, jwtSecret)
	if err != nil {
		return nil, err
	}

	// Trusted-proxy client-cert header (only honoured when explicitly enabled,
	// for tls.mode=none behind a terminating mTLS proxy).
	proxyCertHeader := ""
	if cfg.TLS.TrustProxyClientCert {
		proxyCertHeader = cfg.TLS.ClientCertHeader
	}

	enrollHandler := enrollment.NewHandler(cfg.Server.Domain, cfg.Server.EnrollmentDomain)
	mdmHandler := mdm.NewHandler(database.DB, ca.TLSPool(), cfg.Server.Domain, proxyCertHeader)
	apiHandler := api.NewHandler(database.DB)

	s := &Server{
		cfg:        cfg,
		db:         database,
		ca:         ca,
		auth:       authProvider,
		enrollment: enrollHandler,
		mdm:        mdmHandler,
		api:        apiHandler,
		mux:        chi.NewRouter(),
	}
	s.routes()
	return s, nil
}

// buildAuthenticator constructs the configured auth provider. It fails closed:
// an unset or unimplemented provider returns an error rather than a no-auth
// server. Config validation already rejects these, but this is defence in depth.
func buildAuthenticator(cfg *config.Config, database *sql.DB, jwtSecret []byte) (authenticator, error) {
	base := "https://" + cfg.Server.Domain
	switch cfg.Auth.Provider {
	case "oidc":
		p, err := auth.New(
			context.Background(),
			database,
			cfg.Auth.OIDC.Issuer,
			cfg.Auth.OIDC.ClientID,
			cfg.Auth.OIDC.ClientSecret,
			base,
			cfg.Auth.OIDC.AllowedDomains,
			jwtSecret,
			cfg.Auth.BootstrapAdmin,
		)
		if err != nil {
			return nil, fmt.Errorf("initialising OIDC provider: %w", err)
		}
		slog.Info("OIDC auth provider initialised",
			"issuer", cfg.Auth.OIDC.Issuer,
			"allowed_domains", cfg.Auth.OIDC.AllowedDomains,
		)
		return p, nil
	// case "builtin": wired in a later change (builtin username/password auth).
	default:
		return nil, fmt.Errorf("no usable auth provider configured (provider=%q) — refusing to start", cfg.Auth.Provider)
	}
}

// Handler exposes the configured router so tests can drive the full route
// table with httptest without standing up a TLS listener.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// routes registers all HTTP handlers.
func (s *Server) routes() {
	r := s.mux

	// Standard middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.loggingMiddleware)
	r.Use(middleware.Recoverer)

	// ── MDM Enrollment endpoints ──────────────────────────────────────────
	// These are hit by the Windows MDM client during enrollment (MS-MDE2)
	r.Route("/EnterpriseEnrollment", func(r chi.Router) {
		// Discovery service: Windows looks here first
		r.Post("/Enrollment.svc", s.enrollment.HandleDiscovery)
		// Generic discovery (some Windows versions use this path)
		r.Get("/Enrollment.svc", s.enrollment.HandleDiscovery)
	})

	// Legacy / Alternate default autodiscovery path
	r.Route("/EnrollmentServer", func(r chi.Router) {
		r.Post("/Discovery.svc", s.enrollment.HandleDiscovery)
		r.Get("/Discovery.svc", s.enrollment.HandleDiscovery)
	})

	// Auth provider login/callback/logout endpoints (the page Windows opens for
	// user auth, and the dashboard login). The provider is always configured —
	// the server refuses to start otherwise.
	s.auth.MountRoutes(r)

	// MS-XCEP: certificate enrollment policy
	r.Post("/xcep", s.enrollment.HandleXCEP(s.ca))

	// Root CA download (so admins can install the CA cert on trusted devices)
	r.Get("/pki/ca.pem", s.enrollment.HandleCADownload(s.ca))

	// MS-WSTEP: certificate enrollment (device gets its client cert here). The
	// enrollment token is always validated by the real auth provider — there is
	// no accept-any-token bypass.
	r.Post("/wstep", s.enrollment.HandleWSTEP(s.ca, s.db.DB, s.auth.ValidateEnrollmentToken))

	// ── OMA-DM endpoint ─────────────────────────────────────────────────────
	// Enrolled devices check in here periodically (SyncML over HTTPS + mTLS)
	r.Post("/omadm", s.mdm.HandleOMADM)

	// ── REST API (dashboard backend) ──────────────────────────────────────
	r.Route("/api", func(r chi.Router) {
		// Public config — no auth required (safe values only)
		r.Get("/config", func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"support_url": s.cfg.Server.SupportURL,
			})
		})

		// All other API routes require authentication. Read endpoints are open to
		// any authenticated user; mutating/destructive endpoints additionally
		// require an admin role (RBAC).
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)

			// admin gates state-changing and destructive operations.
			admin := s.requireRole("admin", "super_admin")

			r.Get("/me", s.api.HandleMe)

			// Devices
			r.Get("/devices", s.api.HandleListDevices)
			r.Get("/devices/{id}", s.api.HandleGetDevice)
			r.With(admin).Delete("/devices/{id}", s.api.HandleUnenrollDevice)
			r.With(admin).Post("/devices/{id}/lock", s.api.HandleLockDevice)
			r.With(admin).Post("/devices/{id}/wipe", s.api.HandleWipeDevice)
			r.With(admin).Post("/devices/{id}/sync", s.api.HandleSyncDevice)
			r.Get("/devices/{id}/commands", s.api.HandleGetDeviceCommands)

			// Policy catalog (order matters: specific before param)
			r.Get("/catalog/csps", s.api.HandleListCSPs)
			r.Get("/catalog", s.api.HandleListCatalog)
			r.Get("/catalog/{id}", s.api.HandleGetCatalogEntry)

			// Configuration profiles
			r.Get("/profiles", s.api.HandleListProfiles)
			r.With(admin).Post("/profiles", s.api.HandleCreateProfile)
			r.Get("/profiles/{id}", s.api.HandleGetProfile)
			r.With(admin).Put("/profiles/{id}", s.api.HandleUpdateProfile)
			r.With(admin).Delete("/profiles/{id}", s.api.HandleDeleteProfile)

			// Device groups
			r.Get("/groups", s.api.HandleListGroups)
			r.With(admin).Post("/groups", s.api.HandleCreateGroup)
			r.With(admin).Put("/groups/{id}", s.api.HandleUpdateGroup)
			r.With(admin).Delete("/groups/{id}", s.api.HandleDeleteGroup)
			r.With(admin).Put("/groups/{id}/devices", s.api.HandleAssignDeviceToGroup)
			r.With(admin).Put("/groups/{id}/profiles", s.api.HandleAssignProfileToGroup)

			// Compliance
			r.Get("/compliance", s.api.HandleFleetCompliance)
			r.Get("/compliance/{deviceId}", s.api.HandleDeviceCompliance)

			// System
			r.Get("/system/health", s.handleHealth)
		})
	})

	// Emergency access (rescue for lockouts)
	r.Get("/emergency", s.handleEmergencyAccess)

	// ── Admin dashboard (React SPA) ───────────────────────────────────────
	// TODO Phase 4: embed React build and serve here
	r.Get("/*", s.handleDashboard)
}

// Run starts the server and blocks until shutdown.
// It selects the appropriate listener based on tls.mode:
//   - "auto"        → Let's Encrypt: binds :80 (ACME) + :443 (HTTPS)
//   - "manual"      → HTTPS on cfg.Server.Listen with provided cert/key
//   - "self-signed" → HTTPS on cfg.Server.Listen with generated cert
//   - "none"        → plain HTTP on cfg.Server.Listen (Cloud Run / reverse proxy)
func (s *Server) Run(ctx context.Context) error {
	// Let's Encrypt needs its own dual-listener setup
	if s.cfg.TLS.Mode == "auto" {
		tlsCfg, acmeHandler, err := buildAutoTLSConfig(
			s.cfg.Server.Domain,
			s.cfg.TLS.CacheDir,
			s.ca.TLSPool(),
		)
		if err != nil {
			return fmt.Errorf("building auto-TLS config: %w", err)
		}
		return s.runAutoTLS(ctx, tlsCfg, acmeHandler)
	}

	// Plain HTTP mode (Cloud Run, behind nginx/Caddy, etc.)
	if s.cfg.TLS.Mode == "none" {
		srv := &http.Server{
			Addr:         s.cfg.Server.Listen,
			Handler:      s.mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		slog.Info("Latchz MDM starting (plain HTTP — TLS terminated upstream)",
			"listen", s.cfg.Server.Listen,
			"domain", s.cfg.Server.Domain,
		)
		return s.runHTTP(ctx, srv)
	}

	// TLS modes: self-signed or manual
	tlsCfg, err := s.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("building TLS config: %w", err)
	}

	httpSrv := &http.Server{
		Addr:         s.cfg.Server.Listen,
		Handler:      s.mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("Latchz MDM starting",
		"listen", s.cfg.Server.Listen,
		"domain", s.cfg.Server.Domain,
		"tls_mode", s.cfg.TLS.Mode,
	)
	return s.runHTTPS(ctx, httpSrv)
}

// runHTTPS runs a TLS server and handles graceful shutdown.
func (s *Server) runHTTPS(ctx context.Context, srv *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-quit:
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// runHTTP runs a plain HTTP server (no TLS) with graceful shutdown.
func (s *Server) runHTTP(ctx context.Context, srv *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-quit:
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// buildTLSConfig creates a TLS config based on the configured mode.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	switch s.cfg.TLS.Mode {
	case "self-signed":
		cert, err := generateSelfSignedCert(s.cfg.Server.Domain)
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		slog.Warn("using self-signed TLS certificate (not suitable for production)",
			"domain", s.cfg.Server.Domain)
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			ClientCAs:    s.ca.TLSPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		}, nil

	case "manual":
		if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
			return nil, fmt.Errorf("tls.mode=manual requires tls.cert_file and tls.key_file")
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert/key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			ClientCAs:    s.ca.TLSPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		}, nil

	case "auto":
		// Handled in Run() via runAutoTLS — should not reach here
		return nil, fmt.Errorf("internal error: auto-TLS should be handled in Run()")

	case "none":
		// Handled in Run() via runHTTP — should not reach here
		return nil, fmt.Errorf("internal error: none mode should be handled in Run()")

	default:
		return nil, fmt.Errorf("unknown tls.mode %q — valid options: auto, manual, self-signed, none", s.cfg.TLS.Mode)
	}
}

// ── Middleware ────────────────────────────────────────────────────────────────

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail closed: if no auth provider is wired, reject rather than allow.
		// (The server refuses to start without one; this is defence in depth.)
		if s.auth == nil {
			respondJSON(w, http.StatusServiceUnavailable, `{"error":"authentication not configured"}`)
			return
		}
		email, role, err := s.auth.SessionFromRequest(r)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, `{"error":"unauthenticated"}`)
			return
		}
		// Attach email + role to request context for downstream handlers
		ctx := r.Context()
		ctx = contextWithEmail(ctx, email)
		ctx = contextWithRole(ctx, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireRole wraps requireAuth and additionally enforces that the session
// carries one of the allowed roles. Use on destructive/privileged endpoints.
func (s *Server) requireRole(allowed ...string) func(http.Handler) http.Handler {
	allow := make(map[string]bool, len(allowed))
	for _, r := range allowed {
		allow[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := roleFromContext(r.Context())
			if !allow[role] {
				respondJSON(w, http.StatusForbidden, `{"error":"forbidden: insufficient role"}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func respondJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// ── Remaining handlers ────────────────────────────────────────────────────────

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	webHandler().ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","version":"dev"}`))
}

func (s *Server) handleEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || token != s.cfg.Server.EmergencyToken {
		http.Error(w, "invalid or missing emergency token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"emergency access granted"}`))
}

func (s *Server) notImpl(w http.ResponseWriter) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
}

// ── Context keys ──────────────────────────────────────────────────────────────

func contextWithEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, api.CtxKeyEmail, email)
}

func contextWithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, api.CtxKeyRole, role)
}

func emailFromContext(ctx context.Context) string {
	v, _ := ctx.Value(api.CtxKeyEmail).(string)
	return v
}

func roleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(api.CtxKeyRole).(string)
	return v
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func (s *Server) sqlDB() *sql.DB {
	return s.db.DB
}
