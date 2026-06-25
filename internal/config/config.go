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
}

// ServerConfig controls the HTTP listener and domain settings.
type ServerConfig struct {
	// Listen is the address to bind, e.g. ":8443"
	Listen string `mapstructure:"listen"`
	// Domain is the public hostname of this MDM server, e.g. "mdm.mjo.gg"
	Domain string `mapstructure:"domain"`
	// EnrollmentDomain is the email domain users enrol with, e.g. "mjo.gg"
	EnrollmentDomain string `mapstructure:"enrollment_domain"`
	// EmergencyToken bypasses normal auth for admin recovery. Keep secret.
	EmergencyToken string `mapstructure:"emergency_token"`
	// MasterSecret is the AES-256-GCM vault key for encrypting the Root CA private key in the DB.
	MasterSecret string `mapstructure:"master_secret"`
	// SupportURL is the URL shown on the login page as the "setup guide" link.
	// Leave empty to hide the link entirely.
	SupportURL string `mapstructure:"support_url"`
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
	v.SetDefault("server.domain", "localhost:8443")
	v.SetDefault("server.enrollment_domain", "")
	v.SetDefault("server.master_secret", "")
	v.SetDefault("server.emergency_token", "")
	v.SetDefault("server.support_url", "")
	v.SetDefault("tls.mode", "self-signed")
	v.SetDefault("tls.cache_dir", "./certs")
	v.SetDefault("tls.cert_file", "")
	v.SetDefault("tls.key_file", "")
	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "./latchz.db")
	v.SetDefault("auth.provider", "oidc")
	v.SetDefault("auth.jwt_secret", "")
	v.SetDefault("auth.bootstrap_admin", "")
	v.SetDefault("auth.oidc.issuer", "")
	v.SetDefault("auth.oidc.client_id", "")
	v.SetDefault("auth.oidc.client_secret", "")
	v.SetDefault("auth.oidc.allowed_domains", []string{})

	// Explicit env bindings for nested keys (required for AutomaticEnv to work
	// with deeply nested viper keys — see github.com/spf13/viper#188)
	_ = v.BindEnv("server.domain", "LATCHZ_SERVER_DOMAIN")
	_ = v.BindEnv("server.enrollment_domain", "LATCHZ_SERVER_ENROLLMENT_DOMAIN")
	_ = v.BindEnv("server.master_secret", "LATCHZ_SERVER_MASTER_SECRET")
	_ = v.BindEnv("server.emergency_token", "LATCHZ_SERVER_EMERGENCY_TOKEN")
	_ = v.BindEnv("server.support_url", "LATCHZ_SERVER_SUPPORT_URL")
	_ = v.BindEnv("tls.mode", "LATCHZ_TLS_MODE")
	_ = v.BindEnv("database.driver", "LATCHZ_DATABASE_DRIVER")
	_ = v.BindEnv("database.dsn", "LATCHZ_DATABASE_DSN")
	_ = v.BindEnv("auth.provider", "LATCHZ_AUTH_PROVIDER")
	_ = v.BindEnv("auth.jwt_secret", "LATCHZ_AUTH_JWT_SECRET")
	_ = v.BindEnv("auth.bootstrap_admin", "LATCHZ_AUTH_BOOTSTRAP_ADMIN")
	_ = v.BindEnv("auth.oidc.issuer", "LATCHZ_AUTH_OIDC_ISSUER")
	_ = v.BindEnv("auth.oidc.client_id", "LATCHZ_AUTH_OIDC_CLIENT_ID")
	_ = v.BindEnv("auth.oidc.client_secret", "LATCHZ_AUTH_OIDC_CLIENT_SECRET")
	_ = v.BindEnv("auth.oidc.allowed_domains", "LATCHZ_AUTH_OIDC_ALLOWED_DOMAINS")

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

func (c *Config) validate() error {
	if c.Auth.Provider == "oidc" {
		if c.Auth.OIDC.Issuer == "" {
			return fmt.Errorf("auth.oidc.issuer is required when provider is oidc")
		}
		if c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("auth.oidc.client_id is required when provider is oidc")
		}
		if c.Auth.OIDC.ClientSecret == "" {
			return fmt.Errorf("auth.oidc.client_secret is required when provider is oidc")
		}
	}
	return nil
}
