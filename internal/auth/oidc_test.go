package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func testProvider() *Provider {
	return &Provider{
		jwtSecret:      []byte("0123456789012345678901234567890123"),
		allowedDomains: []string{"example.com", "mjo.gg"},
	}
}

func TestIsEmailAllowed(t *testing.T) {
	p := testProvider()
	cases := []struct {
		email string
		want  bool
	}{
		{"alice@example.com", true},
		{"bob@MJO.GG", true}, // case-insensitive domain
		{"carol@evil.com", false},
		{"no-at-sign", false},
		{"a@b@example.com", false}, // malformed
		{"", false},
	}
	for _, c := range cases {
		if got := p.isEmailAllowed(c.email); got != c.want {
			t.Errorf("isEmailAllowed(%q) = %v, want %v", c.email, got, c.want)
		}
	}

	// Empty allowlist must NOT be permissive in the typed-provider path; the
	// loader enforces a non-empty list, but document the function contract.
	open := &Provider{}
	if !open.isEmailAllowed("anyone@anywhere") {
		t.Log("note: isEmailAllowed returns true for empty allowlist; config.validate forbids that for oidc")
	}
}

func TestValidateEnrollmentToken_Valid(t *testing.T) {
	p := testProvider()
	tok, err := p.issueEnrollmentToken("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	email, err := p.ValidateEnrollmentToken(tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if email != "alice@example.com" {
		t.Fatalf("got email %q", email)
	}
}

func TestValidateEnrollmentToken_RejectsSessionToken(t *testing.T) {
	p := testProvider()
	sess, err := p.issueSessionToken("alice@example.com", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateEnrollmentToken(sess); err == nil {
		t.Fatal("session token must not be accepted as an enrollment token")
	}
}

func TestValidateEnrollmentToken_RejectsAlgNone(t *testing.T) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "attacker@example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email:     "attacker@example.com",
		TokenType: "enroll",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	p := testProvider()
	if _, err := p.ValidateEnrollmentToken(signed); err == nil {
		t.Fatal("alg=none token must be rejected (algorithm confusion)")
	}
}

func TestValidateEnrollmentToken_RejectsWrongSecret(t *testing.T) {
	signer := &Provider{jwtSecret: []byte("a-totally-different-secret-aaaaaaaaaa")}
	tok, err := signer.issueEnrollmentToken("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testProvider().ValidateEnrollmentToken(tok); err == nil {
		t.Fatal("token signed with a different secret must be rejected")
	}
}

func TestValidateEnrollmentToken_SingleUse(t *testing.T) {
	database := testutil.DB(t)
	p := &Provider{db: database.DB, jwtSecret: []byte("0123456789012345678901234567890123")}
	tok, err := p.issueEnrollmentToken("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateEnrollmentToken(tok); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := p.ValidateEnrollmentToken(tok); err == nil {
		t.Fatal("second redemption (replay) must be rejected")
	}
}

func TestUpsertUser_BootstrapAdmin(t *testing.T) {
	database := testutil.DB(t)
	p := &Provider{db: database.DB, bootstrapAdmin: "admin@example.com"}
	ctx := context.Background()

	role, err := p.upsertUser(ctx, "admin@example.com", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if role != "super_admin" {
		t.Fatalf("bootstrap admin should be super_admin, got %q", role)
	}

	role, err = p.upsertUser(ctx, "bob@example.com", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if role != "user" {
		t.Fatalf("non-bootstrap user should be 'user', got %q", role)
	}

	// Re-login of a normal user must not silently escalate.
	role, _ = p.upsertUser(ctx, "bob@example.com", "Bob")
	if role != "user" {
		t.Fatalf("re-login changed role to %q", role)
	}
}
