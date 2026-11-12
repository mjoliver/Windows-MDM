package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
func buildAutoTLSConfig(domain, mdmDomain, cacheDir string, clientCAs *x509.CertPool, verifyPeer func([][]byte, [][]*x509.Certificate) error) (*tls.Config, http.Handler, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("server.domain is required for tls.mode=auto")
	}

	// Ensure the cache dir exists
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("creating TLS cache dir %q: %w", cacheDir, err)
	}

	hosts := []string{domain}
	if mdmDomain != "" && !strings.EqualFold(mdmDomain, domain) {
		hosts = append(hosts, mdmDomain)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      autocert.DirCache(cacheDir),
	}

	tlsCfg := manager.TLSConfig()
	// Require TLS 1.2+ — Let's Encrypt certs work fine with this
	tlsCfg.MinVersion = tls.VersionTLS12
	// Do NOT request client certificates on the enrollment domain: Windows
	// WinHTTP (DeviceEnroller.exe) aborts the TLS handshake immediately with
	// ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED if the server sends a TLS
	// CertificateRequest before a client cert exists. When mdmDomain is set,
	// request client certificates via SNI only on mdmDomain.
	tlsCfg.ClientAuth = tls.NoClientCert
	if mdmDomain != "" {
		baseGetCert := tlsCfg.GetCertificate
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello != nil && strings.EqualFold(hello.ServerName, mdmDomain) {
				mtls := tlsCfg.Clone()
				mtls.GetConfigForClient = nil
				mtls.GetCertificate = baseGetCert
				mtls.ClientCAs = clientCAs
				mtls.ClientAuth = tls.VerifyClientCertIfGiven
				mtls.VerifyPeerCertificate = verifyPeer
				return mtls, nil
			}
			return nil, nil
		}
	}

	slog.Info("auto-TLS: Let's Encrypt autocert configured",
		"domain", domain,
		"mdm_domain", mdmDomain,
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

	errCh := make(chan error, 3)

	var mtlsSrv *http.Server
	if mtlsAddr := s.mtlsListenAddr(); mtlsAddr != "" && mtlsAddr != ":443" {
		mtlsSrv = &http.Server{
			Addr:              mtlsAddr,
			Handler:           s.mux,
			TLSConfig:         s.buildMTLSConfig(tlsCfg),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			slog.Info("mTLS device server listening", "listen", mtlsAddr, "omadm_host", s.mdmHost())
			if err := mtlsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				errCh <- fmt.Errorf("%s mTLS server error: %w", mtlsAddr, err)
			}
		}()
	}

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
		if mtlsSrv != nil {
			_ = mtlsSrv.Shutdown(context.Background())
		}
		return nil
	}
}
