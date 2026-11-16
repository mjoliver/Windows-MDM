// Package server sets up the HTTPS server with all routes for Pane.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchzmdm/latchz/internal/api"
	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/config"
	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/devauth"
	"github.com/latchzmdm/latchz/internal/enrollment"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/policy"
	"github.com/latchzmdm/latchz/internal/vault"
	"github.com/latchzmdm/latchz/internal/webhooks"
	"github.com/latchzmdm/latchz/internal/wns"
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
	apiHandler.ConfigureContentRelay("https://"+cfg.Server.Domain, jwtSecret)
	apiHandler.SetPackagesDir(cfg.MDM.PackagesDir)
	ca.SetPublicBaseURL("https://" + cfg.Server.Domain)
	apiHandler.SetDeviceAuth(ca.TLSPool(), proxyCertHeader)
	apiHandler.SetCA(ca)
	var secretVault *vault.Vault
	if len(cfg.Server.MasterSecret) >= vault.MinSecretLen {
		var err error
		secretVault, err = vault.New(cfg.Server.MasterSecret)
		if err != nil {
			return nil, fmt.Errorf("initialising secret vault: %w", err)
		}
		apiHandler.SetVault(secretVault)
		mdmHandler.SetVault(secretVault)
		policy.SetClientCertHandlers(apiHandler.ProvisionDeviceClientCert, apiHandler.RevokeDeviceClientCert)
	} else {
		policy.SetClientCertHandlers(nil, nil)
	}
	webhookDispatcher := webhooks.NewDispatcher(database.DB, secretVault)
	apiHandler.SetWebhooks(webhookDispatcher)

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
	enrollHandler.SetMDMHost(s.mdmHost())
	enrollHandler.SetPollSchedule(cfg.MDM.PollIntervalMinutes, cfg.MDM.PollOnLogin)
	mdmHandler.SetPollSchedule(cfg.MDM.PollIntervalMinutes, cfg.MDM.PollOnLogin)
	mdmHandler.SetDeviceUpdatedHook(func(devID string) {
		policy.ReconcileDynamicGroupsForDevice(database.DB, devID)
	})
	mdmHandler.SetComplianceHook(func(devID, prevStatus, currStatus string) {
		if currStatus != "non_compliant" {
			return
		}
		if prevStatus != "non_compliant" {
			webhookDispatcher.EmitAsync(webhooks.Event{
				Type:     "compliance.non_compliant",
				TargetID: devID,
				Summary:  fmt.Sprintf("Device %s drifted to non_compliant (was %s)", devID, prevStatus),
				Data: map[string]interface{}{
					"previous_status": prevStatus,
					"current_status":  currStatus,
				},
			})
		}
		if webhooks.IsAutoRemediateEnabled(database.DB) {
			policy.ApplyDevice(database.DB, devID)
			webhooks.RecordAutoRemediation(database.DB)
			webhookDispatcher.EmitAsync(webhooks.Event{
				Type:     "compliance.auto_remediated",
				TargetID: devID,
				Summary:  fmt.Sprintf("Auto-remediation re-queued desired CSP settings for drifted device %s", devID),
			})
		}
	})
	enrollHandler.SetEnrolledHook(func(devID, userEmail, devName, rawToken string) {
		var autoGroupID string
		if strings.HasPrefix(strings.TrimSpace(rawToken), auth.BulkTokenPrefix) {
			_, autoGroupID = auth.LookupBulkTokenAutoGroup(database.DB, rawToken)
			if autoGroupID != "" {
				_, _ = database.DB.Exec(db.Rebind(`
					INSERT INTO device_group_members (device_id, group_id)
					VALUES (?, ?)
					ON CONFLICT DO NOTHING
				`), devID, autoGroupID)
			}
		}
		policy.ReconcileDynamicGroupsForDevice(database.DB, devID)
		policy.ApplyDevice(database.DB, devID)

		webhookDispatcher.EmitAsync(webhooks.Event{
			Type:     "device.enroll",
			Actor:    userEmail,
			TargetID: devID,
			Summary:  fmt.Sprintf("Device %q (%s) enrolled by %s", devName, devID, userEmail),
			Data: map[string]interface{}{
				"device_name":   devName,
				"auto_group_id": autoGroupID,
			},
		})
	})
	policy.SetGroupAppReconciler(apiHandler.ReconcileDeviceGroupApps)
	if cfg.MDM.WNS.Enabled() {
		wnsClient := wns.NewClient(
			database.DB,
			cfg.MDM.WNS.PackageFamilyName,
			cfg.MDM.WNS.PackageSID,
			cfg.MDM.WNS.ClientSecret,
		)
		enrollHandler.SetWNSPFN(cfg.MDM.WNS.PackageFamilyName)
		mdmHandler.SetWNSPFN(cfg.MDM.WNS.PackageFamilyName)
		apiHandler.SetWNSClient(wnsClient)
		policy.SetWakeNotifier(wnsClient.NotifyAsync)
		slog.Info("wns: instant device wake-up enabled", "pfn", cfg.MDM.WNS.PackageFamilyName)
	} else {
		policy.SetWakeNotifier(nil)
	}
	s.routes()
	return s, nil
}

// mtlsListenAddr returns the dedicated mTLS listen address used for /omadm
// SyncML check-ins and ROBO certificate renewals when direct TLS is active and
// no separate SNI mdm_domain is configured. Keeping the enrollment listener
// client-cert-free prevents Windows WinHTTP (DeviceEnroller.exe) from aborting
// Discovery/XCEP/WSTEP with ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED.
func (s *Server) mtlsListenAddr() string {
	if s.cfg == nil || s.cfg.TLS.Mode == "none" {
		return ""
	}
	if s.cfg.Server.MTLSListen != "" {
		return s.cfg.Server.MTLSListen
	}
	if s.cfg.Server.MDMDomain == "" {
		if s.cfg.Server.Listen == ":8443" {
			return ":8444"
		}
		return ":8443"
	}
	return ""
}

// mdmHost returns the host[:port] advertised in WSTEP provisioning XML for
// /omadm device check-ins and ROBO certificate renewal.
func (s *Server) mdmHost() string {
	if s.cfg == nil {
		return ""
	}
	if s.cfg.Server.MDMDomain != "" {
		return s.cfg.Server.MDMDomain
	}
	if addr := s.mtlsListenAddr(); addr != "" && addr != s.cfg.Server.Listen {
		if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
			host := s.cfg.Server.Domain
			if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
				host = h
			}
			if port == "443" {
				return host
			}
			return net.JoinHostPort(host, port)
		}
	}
	return s.cfg.Server.Domain
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
	case "builtin":
		p, err := auth.NewBuiltin(database, jwtSecret, base, cfg.Auth.BootstrapAdmin)
		if err != nil {
			return nil, fmt.Errorf("initialising builtin auth provider: %w", err)
		}
		slog.Info("builtin auth provider initialised", "bootstrap_admin", cfg.Auth.BootstrapAdmin)
		return p, nil
	default:
		return nil, fmt.Errorf("no usable auth provider configured (provider=%q) — refusing to start", cfg.Auth.Provider)
	}
}

// Handler exposes the configured router so tests can drive the full route
// table with httptest without standing up a TLS listener.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// behindProxy reports whether the server runs behind a trusted reverse proxy and
// may therefore trust forwarded client-IP headers. True when explicitly
// configured (server.trusted_proxy), or implied by TLS being terminated upstream
// (tls.mode=none) or a forwarded client cert being trusted. Operators whose
// origin terminates TLS itself but sits behind an L7 proxy/load balancer that
// sets X-Forwarded-For must set server.trusted_proxy so the rate limiters key on
// the real client IP rather than collapsing every client into one bucket.
func (s *Server) behindProxy() bool {
	return s.cfg.Server.TrustedProxy || s.cfg.TLS.Mode == "none" || s.cfg.TLS.TrustProxyClientCert
}

// routes registers all HTTP handlers.
func (s *Server) routes() {
	r := s.mux

	// Standard middleware
	r.Use(middleware.RequestID)
	// Only trust client-supplied forwarding headers (X-Forwarded-For / X-Real-IP)
	// when actually behind a trusted terminating proxy. Otherwise a client could
	// spoof its source IP to evade the rate limiters below.
	if s.behindProxy() {
		r.Use(middleware.RealIP)
	}
	r.Use(s.loggingMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	// Throttle sensitive unauthenticated endpoints.
	authLimiter := newRateLimiter(20, time.Minute)
	emergencyLimiter := newRateLimiter(5, time.Minute)

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
	// the server refuses to start otherwise. Rate-limited to slow credential
	// stuffing / brute force.
	r.Group(func(gr chi.Router) {
		gr.Use(authLimiter.middleware)
		s.auth.MountRoutes(gr)
	})

	// MS-XCEP: certificate enrollment policy
	r.Post("/xcep", s.enrollment.HandleXCEP(s.ca))

	// Root CA download + RFC 5280 CRL & RFC 6960 OCSP responder
	r.Get("/pki/ca.pem", s.enrollment.HandleCADownload(s.ca))
	r.Get("/pki/crl.der", s.api.HandleServeCRLDER)
	r.Get("/pki/crl.pem", s.api.HandleServeCRLPEM)
	r.Post("/pki/ocsp", s.api.HandleOCSP)
	r.Get("/pki/ocsp/{reqB64}", s.api.HandleOCSP)

	// MS-WSTEP: certificate enrollment (device gets its client cert here). The
	// enrollment token is always validated by the real auth provider — there is
	// no accept-any-token bypass.
	r.Post("/wstep", s.enrollment.HandleWSTEP(s.ca, s.db.DB, s.auth.ValidateEnrollmentToken))

	// ── OMA-DM endpoint ─────────────────────────────────────────────────────
	// Enrolled devices check in here periodically (SyncML over HTTPS + mTLS)
	r.Post("/omadm", s.mdm.HandleOMADM)
	r.Post("/mdm/bitlocker/escrow", s.api.HandleDeviceEscrowBitLocker)

	// Signed, identity-encoding MSI content relay for Windows Delivery Optimization
	// (DoSvc). Strips Accept-Encoding upstream so CDNs like dl.google.com never
	// serve Content-Encoding: gzip on HTTP 206 partial byte-range slices.
	r.Get("/mdm/apps/{id}/{exp}/{sig}/package.msi", s.api.HandleServeAppContent)
	r.Head("/mdm/apps/{id}/{exp}/{sig}/package.msi", s.api.HandleServeAppContent)

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

			// admin gates state-changing and destructive operations; superAdmin gates
			// account & role mutations so an admin cannot escalate to super_admin.
			admin := s.requireRole("admin", "super_admin")
			superAdmin := s.requireRole("super_admin")

			r.Get("/me", s.api.HandleMe)

			// Devices
			r.Get("/devices", s.api.HandleListDevices)
			r.Get("/devices/{id}", s.api.HandleGetDevice)
			r.With(admin).Delete("/devices/{id}", s.api.HandleUnenrollDevice)
			r.With(admin).Post("/devices/{id}/lock", s.api.HandleLockDevice)
			r.With(admin).Post("/devices/{id}/reboot", s.api.HandleRebootDevice)
			r.With(admin).Post("/devices/{id}/rename", s.api.HandleRenameDevice)
			r.With(admin).Post("/devices/{id}/retire", s.api.HandleRetireDevice)
			r.With(admin).Post("/devices/{id}/wipe", s.api.HandleWipeDevice)
			r.With(admin).Post("/devices/{id}/sync", s.api.HandleSyncDevice)
			r.With(admin).Post("/devices/{id}/push", s.api.HandlePushWakeDevice)
			r.Get("/devices/{id}/commands", s.api.HandleGetDeviceCommands)
			r.Get("/devices/{id}/apps", s.api.HandleGetDeviceApps)
			r.Get("/devices/{id}/inventory", s.api.HandleGetDeviceInventory)
			r.With(admin).Post("/devices/{id}/inventory/sync", s.api.HandleSyncDeviceInventory)
			r.Get("/devices/{id}/posture", s.api.HandleGetDevicePosture)
			r.With(admin).Post("/devices/{id}/posture/refresh", s.api.HandleRefreshDevicePosture)
			r.Get("/devices/{id}/bitlocker", s.api.HandleGetDeviceBitLocker)
			r.With(admin).Post("/devices/{id}/bitlocker/escrow", s.api.HandleAdminEscrowBitLockerKey)
			r.With(admin).Post("/devices/{id}/bitlocker/keys/{keyId}/reveal", s.api.HandleRevealBitLockerKey)
			r.With(admin).Delete("/devices/{id}/bitlocker/keys/{keyId}", s.api.HandleDeleteBitLockerKey)
			r.With(admin).Post("/devices/{id}/bitlocker/rotate", s.api.HandleRotateBitLockerKeys)
			r.Get("/devices/{id}/laps", s.api.HandleGetDeviceLAPS)
			r.With(admin).Post("/devices/{id}/laps/reveal", s.api.HandleRevealDeviceLAPS)
			r.With(admin).Post("/devices/{id}/laps/rotate", s.api.HandleRotateDeviceLAPS)
			r.Get("/devices/{id}/updates", s.api.HandleGetDeviceUpdates)
			r.Get("/devices/{id}/security", s.api.HandleGetDeviceSecurity)
			r.With(admin).Post("/devices/{id}/defender/scan", s.api.HandleDefenderScanDevice)
			r.With(admin).Post("/devices/{id}/defender/update-signatures", s.api.HandleDefenderUpdateSignatures)
			r.Get("/devices/{id}/connectivity", s.api.HandleGetDeviceConnectivity)
			r.Get("/devices/{id}/lockdown", s.api.HandleGetDeviceLockdown)
			r.Get("/devices/{id}/hardening", s.api.HandleGetDeviceHardening)
			r.Get("/devices/{id}/csp-explorer", s.api.HandleGetDeviceCSPExplorer)
			r.With(admin).Post("/devices/{id}/csp-explorer", s.api.HandleCreateDeviceCSPQuery)
			r.With(admin).Delete("/devices/{id}/csp-explorer/{queryId}", s.api.HandleDeleteDeviceCSPQuery)

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
			r.With(admin).Post("/groups/preview-rules", s.api.HandlePreviewDynamicGroupRules)
			r.With(admin).Put("/groups/{id}", s.api.HandleUpdateGroup)
			r.With(admin).Delete("/groups/{id}", s.api.HandleDeleteGroup)
			r.With(admin).Post("/groups/{id}/reconcile", s.api.HandleReconcileGroup)
			r.With(admin).Put("/groups/{id}/devices", s.api.HandleAssignDeviceToGroup)
			r.With(admin).Put("/groups/{id}/profiles", s.api.HandleAssignProfileToGroup)

			// Applications (Win32 MSI via EnterpriseDesktopAppManagement CSP)
			r.Get("/apps/winget/search", s.api.HandleSearchWinGet)
			r.Get("/apps/winget/resolve", s.api.HandleResolveWinGet)
			r.With(admin).Post("/apps/winget/import", s.api.HandleImportWinGetApp)
			r.With(admin).Post("/apps/inspect", s.api.HandleInspectMSI)
			r.With(admin).Post("/apps/upload", s.api.HandleUploadApp)
			r.Get("/apps", s.api.HandleListApps)
			r.With(admin).Post("/apps", s.api.HandleCreateApp)
			r.Get("/apps/{id}", s.api.HandleGetApp)
			r.With(admin).Delete("/apps/{id}", s.api.HandleDeleteApp)
			r.With(admin).Put("/apps/{id}/groups", s.api.HandleAssignAppGroups)
			r.With(admin).Post("/apps/{id}/install", s.api.HandleInstallAppOnDevices)
			r.With(admin).Post("/apps/{id}/uninstall", s.api.HandleUninstallAppOnDevices)
			r.With(admin).Post("/apps/{id}/winget-refresh", s.api.HandleRefreshWinGetApp)

			// Windows Update Rings (Policy/Config/Update & Update CSPs)
			r.Get("/updates/rings", s.api.HandleListUpdateRings)
			r.With(admin).Post("/updates/rings", s.api.HandleCreateUpdateRing)
			r.Get("/updates/rings/{id}", s.api.HandleGetUpdateRing)
			r.With(admin).Put("/updates/rings/{id}", s.api.HandleUpdateUpdateRing)
			r.With(admin).Delete("/updates/rings/{id}", s.api.HandleDeleteUpdateRing)
			r.With(admin).Post("/updates/rings/{id}/pause", s.api.HandlePauseResumeUpdateRing)

			// Compliance, Security Posture, BitLocker & Cloud LAPS
			r.Get("/compliance", s.api.HandleFleetCompliance)
			r.Get("/compliance/{deviceId}", s.api.HandleDeviceCompliance)
			r.Get("/posture/summary", s.api.HandleFleetPostureSummary)
			r.Get("/bitlocker/policy", s.api.HandleGetBitLockerPolicy)
			r.With(admin).Put("/bitlocker/policy", s.api.HandleUpdateBitLockerPolicy)
			r.Get("/laps/policy", s.api.HandleGetLAPSPolicy)
			r.With(admin).Put("/laps/policy", s.api.HandleUpdateLAPSPolicy)
			r.Get("/security/policy", s.api.HandleGetEndpointSecurityPolicy)
			r.With(admin).Put("/security/policy", s.api.HandleUpdateEndpointSecurityPolicy)
			r.Get("/security/firewall-rules", s.api.HandleListFirewallRules)
			r.With(admin).Post("/security/firewall-rules", s.api.HandleCreateFirewallRule)
			r.With(admin).Delete("/security/firewall-rules/{id}", s.api.HandleDeleteFirewallRule)
			r.Get("/connectivity/profiles", s.api.HandleListConnectivityProfiles)
			r.With(admin).Post("/connectivity/profiles", s.api.HandleCreateConnectivityProfile)
			r.With(admin).Delete("/connectivity/profiles/{id}", s.api.HandleDeleteConnectivityProfile)
			r.Get("/pki/summary", s.api.HandleGetPKISummary)
			r.Get("/pki/certificates", s.api.HandleListPKICertificates)
			r.With(admin).Post("/pki/certificates/{certId}/revoke", s.api.HandleRevokePKICertificate)
			r.Get("/lockdown/policy", s.api.HandleGetLockdownPolicy)
			r.With(admin).Put("/lockdown/policy", s.api.HandleUpdateLockdownPolicy)
			r.Get("/hardening/policy", s.api.HandleGetHardeningPolicy)
			r.With(admin).Put("/hardening/policy", s.api.HandleUpdateHardeningPolicy)
			r.Get("/experience/policy", s.api.HandleGetExperiencePolicy)
			r.With(admin).Put("/experience/policy", s.api.HandleUpdateExperiencePolicy)
			r.Get("/compliance/automation", s.api.HandleGetComplianceAutomation)
			r.With(admin).Put("/compliance/automation", s.api.HandleUpdateComplianceAutomation)

			// Outbound SIEM / Chat Webhooks & Fleet Exports
			r.Get("/webhooks", s.api.HandleListWebhooks)
			r.With(admin).Post("/webhooks", s.api.HandleCreateWebhook)
			r.With(admin).Delete("/webhooks/{id}", s.api.HandleDeleteWebhook)
			r.With(admin).Post("/webhooks/{id}/test", s.api.HandleTestWebhook)
			r.Get("/webhooks/deliveries", s.api.HandleListWebhookDeliveries)
			r.Get("/export/devices", s.api.HandleExportDevices)
			r.Get("/export/software", s.api.HandleExportSoftware)

			// Bulk Enrollment Tokens & OOBE Staging Bootstrap
			r.Get("/enrollment/tokens", s.api.HandleListEnrollmentTokens)
			r.With(admin).Post("/enrollment/tokens", s.api.HandleCreateEnrollmentToken)
			r.With(admin).Delete("/enrollment/tokens/{id}", s.api.HandleDeleteEnrollmentToken)
			r.Get("/enrollment/bootstrap.ps1", s.api.HandleDownloadEnrollmentBootstrap)

			// Administration: Users & Audit Log
			r.With(admin).Get("/users", s.api.HandleListUsers)
			r.With(superAdmin).Post("/users", s.api.HandleCreateUser)
			r.With(superAdmin).Put("/users/{id}", s.api.HandleUpdateUser)
			r.With(superAdmin).Delete("/users/{id}", s.api.HandleDeleteUser)
			r.With(admin).Get("/audit", s.api.HandleListAudit)

			// System
			r.Get("/system/health", s.handleHealth)
		})
	})

	// Emergency access (rescue for lockouts) — strictly rate-limited to make the
	// token infeasible to brute-force.
	r.With(emergencyLimiter.middleware).Get("/emergency", s.handleEmergencyAccess)

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
			s.cfg.Server.MDMDomain,
			s.cfg.TLS.CacheDir,
			s.ca.TLSPool(),
			s.verifyPeerCert,
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

	var mtlsSrv *http.Server
	if mtlsAddr := s.mtlsListenAddr(); mtlsAddr != "" && mtlsAddr != s.cfg.Server.Listen {
		mtlsSrv = &http.Server{
			Addr:         mtlsAddr,
			Handler:      s.mux,
			TLSConfig:    s.buildMTLSConfig(tlsCfg),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
	}

	slog.Info("Latchz MDM starting",
		"listen", s.cfg.Server.Listen,
		"mtls_listen", s.mtlsListenAddr(),
		"domain", s.cfg.Server.Domain,
		"omadm_host", s.mdmHost(),
		"tls_mode", s.cfg.TLS.Mode,
	)
	return s.runHTTPS(ctx, httpSrv, mtlsSrv)
}

// runHTTPS runs the primary TLS server (and optional dedicated mTLS device
// listener) and handles graceful shutdown.
func (s *Server) runHTTPS(ctx context.Context, srv, mtlsSrv *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 2)
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()
	if mtlsSrv != nil {
		go func() {
			if err := mtlsSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				errCh <- fmt.Errorf("mTLS server error (%s): %w", mtlsSrv.Addr, err)
			}
		}()
	}

	shutdownAll := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err1 := srv.Shutdown(shutdownCtx)
		if mtlsSrv != nil {
			if err2 := mtlsSrv.Shutdown(shutdownCtx); err1 == nil {
				err1 = err2
			}
		}
		return err1
	}

	select {
	case err := <-errCh:
		_ = shutdownAll()
		return err
	case <-quit:
		slog.Info("shutting down")
		return shutdownAll()
	case <-ctx.Done():
		return shutdownAll()
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

// buildTLSConfig creates a TLS config for the primary HTTPS listener.
// Crucially, the enrollment listener uses tls.NoClientCert by default because
// Windows WinHTTP (DeviceEnroller.exe) aborts the handshake immediately with
// ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED if the server sends a TLS
// CertificateRequest during Discovery/XCEP/WSTEP. Enrolled device mTLS is
// handled either on the dedicated mTLS listener (mtlsListenAddr) or via SNI
// when server.mdm_domain is configured.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	switch s.cfg.TLS.Mode {
	case "self-signed":
		cert, err = generateSelfSignedCert(s.cfg.Server.Domain)
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert: %w", err)
		}
		slog.Warn("using self-signed TLS certificate (not suitable for production)",
			"domain", s.cfg.Server.Domain)

	case "manual":
		if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
			return nil, fmt.Errorf("tls.mode=manual requires tls.cert_file and tls.key_file")
		}
		cert, err = tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert/key: %w", err)
		}

	case "auto":
		// Handled in Run() via runAutoTLS — should not reach here
		return nil, fmt.Errorf("internal error: auto-TLS should be handled in Run()")

	case "none":
		// Handled in Run() via runHTTP — should not reach here
		return nil, fmt.Errorf("internal error: none mode should be handled in Run()")

	default:
		return nil, fmt.Errorf("unknown tls.mode %q — valid options: auto, manual, self-signed, none", s.cfg.TLS.Mode)
	}

	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	}
	if mdmDomain := s.cfg.Server.MDMDomain; mdmDomain != "" {
		base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello != nil && strings.EqualFold(hello.ServerName, mdmDomain) {
				return s.buildMTLSConfig(base), nil
			}
			return nil, nil
		}
	}
	return base, nil
}

// buildMTLSConfig clones a server tls.Config and enables optional-but-verified
// client certificate authentication for /omadm SyncML check-ins and ROBO renewals.
func (s *Server) buildMTLSConfig(base *tls.Config) *tls.Config {
	mtls := base.Clone()
	mtls.GetConfigForClient = nil
	mtls.ClientCAs = s.ca.TLSPool()
	mtls.ClientAuth = tls.VerifyClientCertIfGiven
	mtls.VerifyPeerCertificate = s.verifyPeerCert
	return mtls
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

// verifyPeerCert is a tls.Config VerifyPeerCertificate hook that rejects a
// presented client certificate at the handshake if it has been revoked. Client
// certs are optional (VerifyClientCertIfGiven), so an absent/unknown cert is
// allowed here and authorisation is left to the application layer.
func (s *Server) verifyPeerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil // malformed; the app layer will reject it
	}
	var revoked int
	err = s.db.DB.QueryRow(db.Rebind(
		`SELECT revoked FROM certificates WHERE thumbprint = ? AND cert_type IN ('device', 'client_pfx')`), devauth.Thumbprint(cert)).Scan(&revoked)
	if err == sql.ErrNoRows || err != nil {
		return nil
	}
	if revoked == 1 {
		return fmt.Errorf("client certificate has been revoked")
	}
	return nil
}

// securityHeaders sets baseline response hardening headers on every response.
// A strict CSP is intentionally NOT set globally because the enrollment callback
// pages rely on inline scripts required by the Windows WebAuthBroker; the SPA
// gets its own CSP in handleDashboard.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// CSP scoped to the SPA. 'unsafe-inline' for styles covers React inline
	// style attributes; Google Fonts is allowed for Outfit/Inter typography;
	// scripts remain restricted to same-origin bundle files.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src 'self' https://fonts.gstatic.com data:; "+
			"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
	webHandler().ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","version":"dev"}`))
}

func (s *Server) handleEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	expected := s.cfg.Server.EmergencyToken
	token := r.URL.Query().Get("token")
	// Disabled unless an emergency token is configured. Use a constant-time
	// comparison to avoid leaking the token via timing.
	if expected == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		http.Error(w, "invalid or missing emergency token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"emergency access granted"}`))
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
