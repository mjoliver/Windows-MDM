package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// buildAutoTLSConfig creates a Let's Encrypt TLS config that automatically
// obtains and renews certificates via the ACME HTTP-01 challenge.
//
// Requirements for auto-TLS to work:
//   - The server domain must have DNS pointing to this machine
//   - Port 80 must be accessible from the internet (for ACME challenges)
//   - The cache directory must be writable
//
// Pane will start an HTTP-01 challenge server on :80 alongside the main HTTPS server.
func buildAutoTLSConfig(domain, cacheDir string, clientCAs *x509.CertPool) (*tls.Config, http.Handler, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("server.domain is required for tls.mode=auto")
	}

	// Ensure the cache dir exists
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("creating TLS cache dir %q: %w", cacheDir, err)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}

	tlsCfg := manager.TLSConfig()
	// Require TLS 1.2+ — Let's Encrypt certs work fine with this
	tlsCfg.MinVersion = tls.VersionTLS12
	// Accept (and verify) a device client certificate when offered, so the
	// OMA-DM endpoint can authenticate enrolled devices via direct mTLS.
	tlsCfg.ClientCAs = clientCAs
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven

	slog.Info("auto-TLS: Let's Encrypt autocert configured",
		"domain", domain,
		"cache_dir", cacheDir,
	)

	// The ACME HTTP-01 challenge handler must be served on port 80.
	// Return it so the caller can start a :80 listener.
	return tlsCfg, manager.HTTPHandler(nil), nil
}

// runAutoTLS starts both the :80 ACME challenge server and the :443 HTTPS server.
// It blocks until both return.
func (s *Server) runAutoTLS(ctx context.Context, tlsCfg *tls.Config, acmeHandler http.Handler) error {
	// :80 — ACME challenge responder + HTTP→HTTPS redirect
	http80 := &http.Server{
		Addr:    ":80",
		Handler: acmeHandler,
	}

	// :443 — main HTTPS server. Timeouts bound slow-client (Slowloris) attacks.
	https443 := &http.Server{
		Addr:              ":443",
		Handler:           s.mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	slog.Info("Latchz MDM starting",
		"domain", s.cfg.Server.Domain,
		"tls_mode", "auto (Let's Encrypt)",
	)

	errCh := make(chan error, 2)

	go func() {
		slog.Info("ACME challenge server listening on :80")
		if err := http80.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf(":80 server error: %w", err)
		}
	}()

	go func() {
		slog.Info("HTTPS server listening on :443")
		// Empty cert/key args — autocert provides them via GetCertificate
		if err := https443.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			errCh <- fmt.Errorf(":443 server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("pane: shutting down")
		_ = http80.Shutdown(context.Background())
		_ = https443.Shutdown(context.Background())
		return nil
	}
}
