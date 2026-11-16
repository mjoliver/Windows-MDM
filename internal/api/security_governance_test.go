package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func TestTOTPEnrollmentAPIKeysAndRevealJustification(t *testing.T) {
	database := testutil.DB(t)
	v, err := vault.NewFast("unit-test-m22-master-secret-32chars!")
	if err != nil {
		t.Fatal(err)
	}
	devID := testutil.SeedDevice(t, database, "HW-GOV-1")
	h := NewHandler(database.DB)
	h.SetVault(v)

	_, err = database.DB.Exec(`
		INSERT INTO users (id, email, role, auth_provider)
		VALUES ('u-admin', 'admin@lab.local', 'super_admin', 'builtin')
	`)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Setup + Enable TOTP 2FA
	wSetup := httptest.NewRecorder()
	h.HandleSetupMyTOTP(wSetup, withDeviceAndKeyRoute("POST", "/api/me/totp/setup", "", "", "", "admin@lab.local"))
	if wSetup.Code != http.StatusOK {
		t.Fatalf("POST /api/me/totp/setup: got %d body=%s", wSetup.Code, wSetup.Body.String())
	}
	var setupRes struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	_ = json.Unmarshal(wSetup.Body.Bytes(), &setupRes)
	code, err := auth.ComputeTOTPCode(setupRes.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	wEnable := httptest.NewRecorder()
	h.HandleEnableMyTOTP(wEnable, withDeviceAndKeyRoute("POST", "/api/me/totp/enable", `{"code":"`+code+`"}`, "", "", "admin@lab.local"))
	if wEnable.Code != http.StatusOK {
		t.Fatalf("POST /api/me/totp/enable: got %d body=%s", wEnable.Code, wEnable.Body.String())
	}
	var enRes struct {
		Enabled       bool     `json:"enabled"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(wEnable.Body.Bytes(), &enRes)
	if !enRes.Enabled || len(enRes.RecoveryCodes) != 8 {
		t.Fatalf("unexpected TOTP enable result: %+v", enRes)
	}

	// 2. Mint Scoped API Key -> verify raw secret is NOT leaked on list
	wCreateKey := httptest.NewRecorder()
	h.HandleCreateAPIKey(wCreateKey, withDeviceAndKeyRoute("POST", "/api/api-keys", `{
		"name": "Grafana ReadOnly",
		"scope": "read_only",
		"expires_in_days": 30
	}`, "", "", "admin@lab.local"))
	if wCreateKey.Code != http.StatusCreated {
		t.Fatalf("POST /api/api-keys: got %d body=%s", wCreateKey.Code, wCreateKey.Body.String())
	}
	var createdKey APIKeyItem
	_ = json.Unmarshal(wCreateKey.Body.Bytes(), &createdKey)
	if !strings.HasPrefix(createdKey.RawKey, auth.APIKeyPrefix) {
		t.Fatalf("unexpected raw key: %+v", createdKey)
	}

	wListKeys := httptest.NewRecorder()
	h.HandleListAPIKeys(wListKeys, withDeviceAndKeyRoute("GET", "/api/api-keys", "", "", "", "admin@lab.local"))
	if strings.Contains(wListKeys.Body.String(), createdKey.RawKey) {
		t.Fatalf("GET /api/api-keys leaked raw key: %s", wListKeys.Body.String())
	}

	// 3. Enable mandatory reveal justification -> verify BitLocker reveal enforces reason
	wEsc := httptest.NewRecorder()
	h.HandleAdminEscrowBitLockerKey(wEsc, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/bitlocker/escrow", `{
		"volume_letter": "C:",
		"recovery_password": "111111-222222-333333-444444-555555-666666-777777-888888"
	}`, devID, "", "admin@lab.local"))
	var escMeta struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(wEsc.Body.Bytes(), &escMeta)

	wGov := httptest.NewRecorder()
	h.HandleUpdateSecurityGovernance(wGov, withDeviceAndKeyRoute("PUT", "/api/security/governance", `{"require_reveal_justification":true}`, "", "", "admin@lab.local"))
	if wGov.Code != http.StatusOK {
		t.Fatalf("PUT /api/security/governance: got %d", wGov.Code)
	}

	// Reveal WITHOUT reason -> 400 Bad Request
	wNoReason := httptest.NewRecorder()
	h.HandleRevealBitLockerKey(wNoReason, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/bitlocker/keys/"+escMeta.ID+"/reveal", "", devID, escMeta.ID, "admin@lab.local"))
	if wNoReason.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when reveal justification is required and omitted, got %d", wNoReason.Code)
	}

	// Reveal WITH reason -> 200 OK & reason logged in audit_log
	wWithReason := httptest.NewRecorder()
	h.HandleRevealBitLockerKey(wWithReason, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/bitlocker/keys/"+escMeta.ID+"/reveal", `{"reason":"INC-9001 BitLocker boot prompt"}`, devID, escMeta.ID, "admin@lab.local"))
	if wWithReason.Code != http.StatusOK {
		t.Fatalf("expected 200 with reveal justification, got %d body=%s", wWithReason.Code, wWithReason.Body.String())
	}
	var auditDetails string
	_ = database.DB.QueryRow(`SELECT details FROM audit_log WHERE action = 'bitlocker.reveal_key' ORDER BY id DESC LIMIT 1`).Scan(&auditDetails)
	if !strings.Contains(auditDetails, "INC-9001") {
		t.Fatalf("expected audit_log to contain justification reason, got %s", auditDetails)
	}
}
