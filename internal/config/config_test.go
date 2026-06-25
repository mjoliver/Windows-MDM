package config

import "testing"

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
