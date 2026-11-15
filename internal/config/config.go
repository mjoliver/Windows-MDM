// Package config handles loading and validating Latchz server configuration.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level server configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	TLS      TLSConfig      `mapstructure:"tls"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	MDM      MDMConfig      `mapstructure:"mdm"`
}

// MDMConfig controls OMA-DM device check-in scheduling and management settings.
type MDMConfig struct {
	// PollIntervalMinutes sets DMClient Poll/IntervalForRemainingScheduledRetries
	// (in minutes) during WSTEP enrollment and reconciles enrolled devices over
	// SyncML. Default: 15 (check in every 15 minutes). Set to 0 to disable
	// scheduled background polling.
	PollIntervalMinutes int `mapstructure:"poll_interval_minutes"`
	// PollOnLogin sets DMClient Poll/PollOnLogin so Windows initiates an OMA-DM
	// management session whenever a user signs in. Default: true.
	PollOnLogin bool `mapstructure:"poll_on_login"`
	// PackagesDir is the local directory where uploaded Win32 .msi packages are
	// stored and served to enrolled devices. Default: ./packages.
	PackagesDir string `mapstructure:"packages_dir"`
	// WNS configures optional Windows Push Notification Services instant wake-ups.
	WNS WNSConfig `mapstructure:"wns"`
}

// WNSConfig holds optional Windows Push Notification Services (WNS) credentials
// from Microsoft Partner Center / Entra App Registration for instant device wake-ups.
// Leave all fields empty to disable WNS and rely on DMClient Poll check-ins.
type WNSConfig struct {
	// PackageFamilyName is provisioned into DMClient/Provider/LatchzMDM/Push/PFN
	// (e.g. "Company.LatchzMDM_8wekyb3d8bbwe").
	PackageFamilyName string `mapstructure:"package_family_name"`
	// PackageSID is the OAuth2 client_id sent to login.live.com/accesstoken.srf
	// (e.g. "ms-app://s-1-15-2-...").
	PackageSID string `mapstructure:"package_sid"`
	// ClientSecret is the WNS client secret paired with PackageSID.
	ClientSecret string `mapstructure:"client_secret"`
}

// Enabled reports whether WNS instant device wake-up is fully configured.
func (w WNSConfig) Enabled() bool {
	return w.PackageFamilyName != "" && w.PackageSID != "" && w.ClientSecret != ""
}

// ServerConfig controls the HTTP listener and domain settings.
type ServerConfig struct {
	// Listen is the address to bind, e.g. ":8443"
	Listen string `mapstructure:"listen"`
	// MTLSListen is an optional dedicated mTLS address (e.g. ":8443") used for
	// /omadm device check-ins and certificate-based WSTEP renewal when Listen
	// serves enrollment on :443 without requesting client certificates (Windows
	// WinHTTP aborts Discovery/XCEP/WSTEP if the :443 server requests a client cert).
	MTLSListen string `mapstructure:"mtls_listen"`
	// Domain is the public hostname of this MDM server, e.g. "mdm.mjo.gg"
	Domain string `mapstructure:"domain"`
	// MDMDomain is an optional dedicated SNI hostname on :443 (e.g. "mdm.mjo.gg")
	// that requests device client certificates via SNI while keeping Domain
	// client-cert-free for Windows WinHTTP enrollment.
	MDMDomain string `mapstructure:"mdm_domain"`
	// EnrollmentDomain is the email domain users enrol with, e.g. "mjo.gg"
	EnrollmentDomain string `mapstructure:"enrollment_domain"`
	// EmergencyToken bypasses normal auth for admin recovery. Keep secret.
	EmergencyToken string `mapstructure:"emergency_token"`
	// MasterSecret is the AES-256-GCM vault key for encrypting the Root CA private key in the DB.
	MasterSecret string `mapstructure:"master_secret"`
	// SupportURL is the URL shown on the login page as the "setup guide" link.
	// Leave empty to hide the link entirely.
	SupportURL string `mapstructure:"support_url"`

	// TrustedProxy indicates the server sits behind a trusted reverse proxy /
	// load balancer that sets X-Forwarded-For. Enable it so rate limiting and
	// request logging key on the real client IP. Leave false for direct exposure
	// (then forwarding headers are ignored, since a client could spoof them).
	// Implied by tls.mode=none and tls.trust_proxy_client_cert.
	TrustedProxy bool `mapstructure:"trusted_proxy"`
}

// TLSConfig controls how TLS certificates are obtained.
type TLSConfig struct {
	// Mode is one of:
	//   "auto"        - Let's Encrypt (requires port 80 open to internet)
	//   "manual"      - provide cert_file and key_file
	//   "self-signed" - auto-generate a self-signed cert (dev only)
	//   "none"        - no TLS (use when terminated by a proxy, e.g. Cloud Run)
	Mode     string `mapstructure:"mode"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	// CacheDir is where Let's Encrypt certs are stored (mode=auto only).
	// Defaults to ./certs
	CacheDir string `mapstructure:"cache_dir"`

	// TrustProxyClientCert enables authenticating OMA-DM devices via a client
	// certificate forwarded by a trusted terminating proxy (for tls.mode=none,
	// e.g. behind a load balancer doing mTLS). ONLY enable this when the proxy
	// strips any client-supplied value of ClientCertHeader and sets it itself.
	TrustProxyClientCert bool `mapstructure:"trust_proxy_client_cert"`
	// ClientCertHeader is the header carrying the URL-encoded PEM client cert
	// (e.g. nginx $ssl_client_escaped_cert). Default: X-Forwarded-Client-Cert.
	ClientCertHeader string `mapstructure:"client_cert_header"`
}

// DatabaseConfig selects the database backend.
type DatabaseConfig struct {
	// Driver is "sqlite" or "postgres"
	Driver string `mapstructure:"driver"`
	// DSN is the SQLite file path or PostgreSQL connection string
	DSN string `mapstructure:"dsn"`
}

// AuthConfig selects and configures the identity provider.
type AuthConfig struct {
	// Provider is one of: "oidc", "builtin". ("ldap" is reserved but not implemented.)
	Provider string     `mapstructure:"provider"`
	OIDC     OIDCConfig `mapstructure:"oidc"`

	// JWTSecret signs dashboard session JWTs and enrollment tokens. It MUST be a
	// stable, high-entropy value (>=32 bytes) in production so sessions survive
	// restarts and are valid across horizontally-scaled instances. If empty, a
	// random per-process secret is generated (dev only) and a warning is logged.
	JWTSecret string `mapstructure:"jwt_secret"`

	// BootstrapAdmin is the email granted super_admin on creation. This replaces
	// the insecure "first login becomes super_admin" behaviour: only this address
	// (or users promoted via the admin CLI) gets elevated privileges.
	BootstrapAdmin string `mapstructure:"bootstrap_admin"`
}

// OIDCConfig holds OpenID Connect provider settings.
type OIDCConfig struct {
	// Issuer is the OIDC discovery URL, e.g. "https://accounts.google.com"
	Issuer string `mapstructure:"issuer"`
	// ClientID and ClientSecret come from your OIDC provider's app registration
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	// AllowedDomains restricts login to specific email domains.
	// Leave empty to allow any authenticated account.
	AllowedDomains []string `mapstructure:"allowed_domains"`
}

// Load reads configuration from file, environment variables, and defaults.
// Priority: env vars > config file > defaults.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.listen", ":8443")
	v.SetDefault("server.mtls_listen", "")
	v.SetDefault("server.domain", "localhost:8443")
	v.SetDefault("server.mdm_domain", "")
	v.SetDefault("server.enrollment_domain", "")
	v.SetDefault("server.master_secret", "")
	v.SetDefault("server.emergency_token", "")
	v.SetDefault("server.support_url", "")
	v.SetDefault("server.trusted_proxy", false)
	v.SetDefault("tls.mode", "self-signed")
	v.SetDefault("tls.cache_dir", "./certs")
	v.SetDefault("tls.cert_file", "")
	v.SetDefault("tls.key_file", "")
	v.SetDefault("tls.trust_proxy_client_cert", false)
	v.SetDefault("tls.client_cert_header", "X-Forwarded-Client-Cert")
	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "./latchz.db")
	v.SetDefault("auth.provider", "oidc")
	v.SetDefault("auth.jwt_secret", "")
	v.SetDefault("auth.bootstrap_admin", "")
	v.SetDefault("auth.oidc.issuer", "")
	v.SetDefault("auth.oidc.client_id", "")
	v.SetDefault("auth.oidc.client_secret", "")
	v.SetDefault("auth.oidc.allowed_domains", []string{})
	v.SetDefault("mdm.poll_interval_minutes", 15)
	v.SetDefault("mdm.poll_on_login", true)
	v.SetDefault("mdm.packages_dir", "./packages")
	v.SetDefault("mdm.wns.package_family_name", "")
	v.SetDefault("mdm.wns.package_sid", "")
	v.SetDefault("mdm.wns.client_secret", "")

	// Explicit env bindings for nested keys (required for AutomaticEnv to work
	// with deeply nested viper keys — see github.com/spf13/viper#188)
	_ = v.BindEnv("server.domain", "LATCHZ_SERVER_DOMAIN")
	_ = v.BindEnv("server.mtls_listen", "LATCHZ_SERVER_MTLS_LISTEN")
	_ = v.BindEnv("server.mdm_domain", "LATCHZ_SERVER_MDM_DOMAIN")
	_ = v.BindEnv("server.enrollment_domain", "LATCHZ_SERVER_ENROLLMENT_DOMAIN")
	_ = v.BindEnv("server.master_secret", "LATCHZ_SERVER_MASTER_SECRET")
	_ = v.BindEnv("server.emergency_token", "LATCHZ_SERVER_EMERGENCY_TOKEN")
	_ = v.BindEnv("server.support_url", "LATCHZ_SERVER_SUPPORT_URL")
	_ = v.BindEnv("server.trusted_proxy", "LATCHZ_SERVER_TRUSTED_PROXY")
	_ = v.BindEnv("tls.mode", "LATCHZ_TLS_MODE")
	_ = v.BindEnv("tls.trust_proxy_client_cert", "LATCHZ_TLS_TRUST_PROXY_CLIENT_CERT")
	_ = v.BindEnv("tls.client_cert_header", "LATCHZ_TLS_CLIENT_CERT_HEADER")
	_ = v.BindEnv("database.driver", "LATCHZ_DATABASE_DRIVER")
	_ = v.BindEnv("database.dsn", "LATCHZ_DATABASE_DSN")
	_ = v.BindEnv("auth.provider", "LATCHZ_AUTH_PROVIDER")
	_ = v.BindEnv("auth.jwt_secret", "LATCHZ_AUTH_JWT_SECRET")
	_ = v.BindEnv("auth.bootstrap_admin", "LATCHZ_AUTH_BOOTSTRAP_ADMIN")
	_ = v.BindEnv("auth.oidc.issuer", "LATCHZ_AUTH_OIDC_ISSUER")
	_ = v.BindEnv("auth.oidc.client_id", "LATCHZ_AUTH_OIDC_CLIENT_ID")
	_ = v.BindEnv("auth.oidc.client_secret", "LATCHZ_AUTH_OIDC_CLIENT_SECRET")
	_ = v.BindEnv("auth.oidc.allowed_domains", "LATCHZ_AUTH_OIDC_ALLOWED_DOMAINS")
	_ = v.BindEnv("mdm.poll_interval_minutes", "LATCHZ_MDM_POLL_INTERVAL_MINUTES")
	_ = v.BindEnv("mdm.poll_on_login", "LATCHZ_MDM_POLL_ON_LOGIN")
	_ = v.BindEnv("mdm.packages_dir", "LATCHZ_MDM_PACKAGES_DIR")
	_ = v.BindEnv("mdm.wns.package_family_name", "LATCHZ_MDM_WNS_PACKAGE_FAMILY_NAME")
	_ = v.BindEnv("mdm.wns.package_sid", "LATCHZ_MDM_WNS_PACKAGE_SID")
	_ = v.BindEnv("mdm.wns.client_secret", "LATCHZ_MDM_WNS_CLIENT_SECRET")

	// Config file
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("latchz")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.latchz")
		v.AddConfigPath("/etc/latchz")
	}

	// Environment variables: LATCHZ_SERVER_LISTEN, LATCHZ_DATABASE_DSN, etc.
	v.SetEnvPrefix("LATCHZ")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional — only error if it was explicitly set
		if cfgFile != "" {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Fallback to standard PORT environment variable (commonly set by Cloud Run)
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Listen = ":" + port
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// minMasterSecretLen mirrors pki.MinMasterSecretLen (kept local to avoid a
// config->pki import). The master secret protects the Root CA private key.
const minMasterSecretLen = 16

func (c *Config) validate() error {
	// The vault key (master secret) is mandatory and must not be trivially short.
	if c.Server.MasterSecret == "" {
		return fmt.Errorf("server.master_secret (LATCHZ_SERVER_MASTER_SECRET) is required: it encrypts the Root CA private key")
	}
	if len(c.Server.MasterSecret) < minMasterSecretLen {
		return fmt.Errorf("server.master_secret must be at least %d characters (use a high-entropy random value)", minMasterSecretLen)
	}

	// A short or unset JWT secret is allowed (random per-process dev fallback),
	// but if provided it must be strong enough to be a real signing key.
	if c.Auth.JWTSecret != "" && len(c.Auth.JWTSecret) < 32 {
		return fmt.Errorf("auth.jwt_secret must be at least 32 characters when set")
	}

	if c.MDM.PollIntervalMinutes < 0 || c.MDM.PollIntervalMinutes > 10080 {
		return fmt.Errorf("mdm.poll_interval_minutes must be between 0 and 10080 (7 days), got %d", c.MDM.PollIntervalMinutes)
	}

	wnsAny := c.MDM.WNS.PackageFamilyName != "" || c.MDM.WNS.PackageSID != "" || c.MDM.WNS.ClientSecret != ""
	if wnsAny && !c.MDM.WNS.Enabled() {
		return fmt.Errorf("mdm.wns requires package_family_name, package_sid, and client_secret to all be set when WNS is enabled")
	}

	// Fail closed on the authentication provider: only fully-implemented,
	// fully-configured providers are accepted. An unset/unknown provider must
	// never silently disable authentication.
	switch c.Auth.Provider {
	case "oidc":
		if c.Auth.OIDC.Issuer == "" {
			return fmt.Errorf("auth.oidc.issuer is required when provider is oidc")
		}
		if c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("auth.oidc.client_id is required when provider is oidc")
		}
		if c.Auth.OIDC.ClientSecret == "" {
			return fmt.Errorf("auth.oidc.client_secret is required when provider is oidc")
		}
		// Require an explicit email-domain allowlist: an empty list would let
		// any account at the IdP (e.g. any Google account) sign in.
		if len(c.Auth.OIDC.AllowedDomains) == 0 {
			return fmt.Errorf("auth.oidc.allowed_domains must list at least one domain (an empty list would allow any account at the identity provider)")
		}
	case "builtin":
		if c.Auth.BootstrapAdmin == "" {
			return fmt.Errorf("auth.bootstrap_admin is required when provider is builtin (the initial admin account)")
		}
	case "ldap":
		return fmt.Errorf("auth.provider %q is not implemented", c.Auth.Provider)
	case "":
		return fmt.Errorf("auth.provider is required (one of: oidc, builtin) — refusing to start without authentication")
	default:
		return fmt.Errorf("auth.provider %q is invalid (one of: oidc, builtin)", c.Auth.Provider)
	}
	return nil
}
