package auth_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func TestTOTPGenerationVerificationAndRecoveryCodes(t *testing.T) {
	database := testutil.DB(t)
	v, err := vault.NewFast("unit-test-totp-master-secret-32chars!")
	if err != nil {
		t.Fatal(err)
	}

	sec, err := auth.GenerateTOTPSecret()
	if err != nil || len(sec) < 24 {
		t.Fatalf("GenerateTOTPSecret: sec=%q err=%v", sec, err)
	}
	uri := auth.BuildOTPAuthURL("Latchz MDM", "admin@lab.local", sec)
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+sec) {
		t.Fatalf("unexpected otpauth URI: %s", uri)
	}

	now := time.Unix(1700000000, 0).UTC()
	code, err := auth.ComputeTOTPCode(sec, now)
	if err != nil || len(code) != 6 {
		t.Fatalf("ComputeTOTPCode: code=%q err=%v", code, err)
	}
	if !auth.VerifyTOTPCode(sec, code, now.Add(20*time.Second)) {
		t.Fatal("expected VerifyTOTPCode to accept valid code within skew window")
	}
	if auth.VerifyTOTPCode(sec, "000000", now) && code != "000000" {
		t.Fatal("expected wrong TOTP code to fail")
	}

	plainCodes, hashesJSON, err := auth.GenerateRecoveryCodes(8)
	if err != nil || len(plainCodes) != 8 {
		t.Fatalf("GenerateRecoveryCodes: len=%d err=%v", len(plainCodes), err)
	}
	encSec, err := v.Encrypt(sec, auth.TOTPVaultAADPrefix+"admin@lab.local")
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB.Exec(`
		INSERT INTO users (id, email, role, auth_provider, totp_enabled, totp_secret_encrypted, totp_recovery_hashes)
		VALUES ('u-totp', 'admin@lab.local', 'super_admin', 'builtin', 1, ?, ?)
	`, encSec, hashesJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Valid TOTP passes
	ok, err := auth.VerifyUserSecondFactor(database.DB, v, "admin@lab.local", code, now)
	if err != nil || !ok {
		t.Fatalf("expected valid TOTP second factor to pass: ok=%t err=%v", ok, err)
	}

	// Single-use recovery code passes once, then fails on replay!
	okRec, err := auth.VerifyUserSecondFactor(database.DB, v, "admin@lab.local", plainCodes[0], now)
	if err != nil || !okRec {
		t.Fatalf("expected recovery code to pass on first use: ok=%t err=%v", okRec, err)
	}
	okReplay, _ := auth.VerifyUserSecondFactor(database.DB, v, "admin@lab.local", plainCodes[0], now)
	if okReplay {
		t.Fatal("expected replayed recovery code to be rejected")
	}
}

func TestScopedAPIKeyAuthenticationAndGuardrails(t *testing.T) {
	database := testutil.DB(t)
	rawKey, prefix, hashHex, err := auth.GenerateAPIKey()
	if err != nil || !strings.HasPrefix(rawKey, auth.APIKeyPrefix) {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	_, err = database.DB.Exec(`
		INSERT INTO api_keys (id, name, key_prefix, key_hash, scope, created_by, revoked)
		VALUES ('ak-1', 'SIEM Collector', ?, ?, 'read_only', 'admin@lab.local', 0)
	`, prefix, hashHex)
	if err != nil {
		t.Fatal(err)
	}

	actor, role, scope, id, err := auth.AuthenticateAPIKey(database.DB, rawKey)
	if err != nil || role != "user" || scope != "read_only" || id != "ak-1" || !strings.Contains(actor, "SIEM Collector") {
		t.Fatalf("AuthenticateAPIKey: actor=%q role=%q scope=%q id=%q err=%v", actor, role, scope, id, err)
	}
	if !auth.IsAPIKeyRequestAllowed("read_only", http.MethodGet, "/api/devices") {
		t.Fatal("read_only key should allow GET /api/devices")
	}
	if auth.IsAPIKeyRequestAllowed("read_only", http.MethodPost, "/api/devices/123/wipe") {
		t.Fatal("read_only key MUST NOT allow POST /api/devices/123/wipe")
	}
	if auth.IsAPIKeyRequestAllowed("ops", http.MethodPost, "/api/devices/123/wipe") {
		t.Fatal("ops key MUST NOT allow POST /api/devices/123/wipe")
	}
	if !auth.IsAPIKeyRequestAllowed("ops", http.MethodPost, "/api/devices/123/sync") {
		t.Fatal("ops key should allow POST /api/devices/123/sync")
	}
}
