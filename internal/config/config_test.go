package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_FileAndEnvOverride(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "latchz.yaml")
	contents := `
server:
  domain: file.example.com
  master_secret: "0123456789abcdef0"
auth:
  provider: oidc
  oidc:
    issuer: https://accounts.google.com
    client_id: id
    client_secret: secret
    allowed_domains: [example.com]
`
	if err := os.WriteFile(cfgPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	// Environment variables override file values.
	t.Setenv("LATCHZ_SERVER_DOMAIN", "env.example.com")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Domain != "env.example.com" {
		t.Fatalf("env should override file domain, got %q", cfg.Server.Domain)
	}
	if cfg.Auth.OIDC.Issuer != "https://accounts.google.com" {
		t.Fatalf("issuer not loaded from file: %q", cfg.Auth.OIDC.Issuer)
	}

	// Cloud Run's PORT maps to the listen address.
	t.Setenv("PORT", "9090")
	cfg2, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Server.Listen != ":9090" {
		t.Fatalf("PORT should set listen, got %q", cfg2.Server.Listen)
	}
	if cfg2.MDM.PollIntervalMinutes != 15 || !cfg2.MDM.PollOnLogin {
		t.Fatalf("expected default MDM poll schedule (15m, on_login=true), got (%d, %v)", cfg2.MDM.PollIntervalMinutes, cfg2.MDM.PollOnLogin)
	}

	t.Setenv("LATCHZ_MDM_POLL_INTERVAL_MINUTES", "30")
	t.Setenv("LATCHZ_MDM_POLL_ON_LOGIN", "false")
	cfg3, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg3.MDM.PollIntervalMinutes != 30 || cfg3.MDM.PollOnLogin {
		t.Fatalf("expected env override MDM poll schedule (30m, on_login=false), got (%d, %v)", cfg3.MDM.PollIntervalMinutes, cfg3.MDM.PollOnLogin)
	}
}

func validBase() *Config {
	return &Config{
		Server: ServerConfig{MasterSecret: "0123456789abcdefghij"},
		Auth: AuthConfig{
			Provider: "oidc",
			OIDC: OIDCConfig{
				Issuer:         "https://accounts.google.com",
				ClientID:       "id",
				ClientSecret:   "secret",
				AllowedDomains: []string{"example.com"},
			},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid oidc", func(c *Config) {}, false},
		{"missing master secret", func(c *Config) { c.Server.MasterSecret = "" }, true},
		{"short master secret", func(c *Config) { c.Server.MasterSecret = "short" }, true},
		{"empty provider fails closed", func(c *Config) { c.Auth.Provider = "" }, true},
		{"unknown provider fails closed", func(c *Config) { c.Auth.Provider = "magic" }, true},
		{"ldap not implemented", func(c *Config) { c.Auth.Provider = "ldap" }, true},
		{"oidc requires issuer", func(c *Config) { c.Auth.OIDC.Issuer = "" }, true},
		{"oidc requires client_id", func(c *Config) { c.Auth.OIDC.ClientID = "" }, true},
		{"oidc requires client_secret", func(c *Config) { c.Auth.OIDC.ClientSecret = "" }, true},
		{"oidc requires allowed_domains", func(c *Config) { c.Auth.OIDC.AllowedDomains = nil }, true},
		{"short jwt secret rejected", func(c *Config) { c.Auth.JWTSecret = "tooshort" }, true},
		{"long jwt secret ok", func(c *Config) { c.Auth.JWTSecret = "0123456789012345678901234567890123" }, false},
		{"builtin requires bootstrap_admin", func(c *Config) {
			c.Auth.Provider = "builtin"
			c.Auth.BootstrapAdmin = ""
		}, true},
		{"builtin with bootstrap_admin ok", func(c *Config) {
			c.Auth.Provider = "builtin"
			c.Auth.BootstrapAdmin = "admin@example.com"
		}, false},
		{"negative poll interval rejected", func(c *Config) {
			c.MDM.PollIntervalMinutes = -1
		}, true},
		{"excessive poll interval rejected", func(c *Config) {
			c.MDM.PollIntervalMinutes = 20000
		}, true},
		{"custom poll interval ok", func(c *Config) {
			c.MDM.PollIntervalMinutes = 60
		}, false},
		{"partial wns config rejected", func(c *Config) {
			c.MDM.WNS.PackageFamilyName = "Latchz.MDM_8wekyb3d8bbwe"
		}, true},
		{"complete wns config ok", func(c *Config) {
			c.MDM.WNS.PackageFamilyName = "Latchz.MDM_8wekyb3d8bbwe"
			c.MDM.WNS.PackageSID = "ms-app://s-1-15-2-12345"
			c.MDM.WNS.ClientSecret = "wns-secret"
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validBase()
			tt.mutate(c)
			err := c.validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
