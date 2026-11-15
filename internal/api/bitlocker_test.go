package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func withDeviceAndKeyRoute(method, path, body, deviceID, keyID, actor string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	if deviceID != "" {
		rctx.URLParams.Add("id", deviceID)
	}
	if keyID != "" {
		rctx.URLParams.Add("keyId", keyID)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	if actor != "" {
		ctx = context.WithValue(ctx, CtxKeyEmail, actor)
	}
	return req.WithContext(ctx)
}

func TestBitLockerPolicyEscrowAndAuditedReveal(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	secVault, err := vault.NewFast("unit-test-master-secret-32-chars!!")
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(database.DB)
	h.SetVault(secVault)
	h.SetDeviceAuth(ca.TLSPool(), "")

	devID := testutil.SeedDevice(t, database, "HW-BL-1")
	clientCert := testutil.IssueClientCert(t, ca, devID, "LatchzMDMClient")

	// 1. Enable fleet BitLocker policy -> queues 4 Replace + 1 Get command on devID
	wPol := httptest.NewRecorder()
	polBody := `{"enabled":true,"require_device_encryption":true,"silent_encryption":true,"allow_standard_user":true,"os_drive_cipher":7,"fixed_drive_cipher":7,"removable_drive_cipher":4,"target_all_devices":true}`
	h.HandleUpdateBitLockerPolicy(wPol, withDeviceAndKeyRoute("PUT", "/api/bitlocker/policy", polBody, "", "", "admin@lab.local"))
	if wPol.Code != http.StatusOK {
		t.Fatalf("update bitlocker policy: want 200, got %d body=%s", wPol.Code, wPol.Body.String())
	}
	var polResp BitLockerPolicyResponse
	if err := json.Unmarshal(wPol.Body.Bytes(), &polResp); err != nil {
		t.Fatal(err)
	}
	if !polResp.Enabled || polResp.EnforcedDevices != 1 || polResp.CommandsQueued != 5 {
		t.Fatalf("unexpected policy response: %+v", polResp)
	}

	// 2. Device mTLS escrow requires verified client cert
	wUnauth := httptest.NewRecorder()
	h.HandleDeviceEscrowBitLocker(wUnauth, httptest.NewRequest("POST", "/mdm/bitlocker/escrow", strings.NewReader(`{"recovery_password":"111111-222222-333333-444444-555555-666666-777777-888888"}`)))
	if wUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated mTLS escrow: want 401, got %d", wUnauth.Code)
	}

	rawPwd := "419283-104928-558291-003918-774829-661029-884712-901234"
	mtlsReq := httptest.NewRequest("POST", "/mdm/bitlocker/escrow", strings.NewReader(`{"volume_letter":"c","protector_id":"a1b2c3d4-0000-4000-8000-111122223333","recovery_password":"`+rawPwd+`"}`))
	mtlsReq.TLS = testutil.ClientTLSState(clientCert)
	wEscrow := httptest.NewRecorder()
	h.HandleDeviceEscrowBitLocker(wEscrow, mtlsReq)
	if wEscrow.Code != http.StatusCreated {
		t.Fatalf("valid mTLS escrow: want 201, got %d body=%s", wEscrow.Code, wEscrow.Body.String())
	}

	// 3. Seed non-zero bitmask (0x2004 = OS unprotected + TPM unavailable) and verify metadata endpoint never leaks plaintext
	if _, err := database.Exec(`INSERT INTO device_posture (device_id, encryption_status) VALUES (?, ?)`, devID, 0x2004); err != nil {
		t.Fatal(err)
	}
	wDevBL := httptest.NewRecorder()
	h.HandleGetDeviceBitLocker(wDevBL, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/bitlocker", "", devID, "", "admin@lab.local"))
	if wDevBL.Code != http.StatusOK {
		t.Fatalf("get device bitlocker: want 200, got %d body=%s", wDevBL.Code, wDevBL.Body.String())
	}
	if strings.Contains(wDevBL.Body.String(), "419283") {
		t.Fatalf("metadata response leaked recovery password: %s", wDevBL.Body.String())
	}
	var devBL DeviceBitLockerResponse
	if err := json.Unmarshal(wDevBL.Body.Bytes(), &devBL); err != nil {
		t.Fatal(err)
	}
	if !devBL.Enforced || len(devBL.RecoveryKeys) != 1 || devBL.RecoveryKeys[0].KeyHint != "••••••-901234" || len(devBL.StatusReasons) != 2 {
		t.Fatalf("unexpected device bitlocker response: %+v", devBL)
	}

	// 4. Audited reveal decrypts exact 48-digit key and logs bitlocker.reveal_key
	keyID := devBL.RecoveryKeys[0].ID
	wRev := httptest.NewRecorder()
	h.HandleRevealBitLockerKey(wRev, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/bitlocker/keys/"+keyID+"/reveal", "", devID, keyID, "admin@lab.local"))
	if wRev.Code != http.StatusOK {
		t.Fatalf("reveal key: want 200, got %d body=%s", wRev.Code, wRev.Body.String())
	}
	var rev map[string]string
	if err := json.Unmarshal(wRev.Body.Bytes(), &rev); err != nil {
		t.Fatal(err)
	}
	if rev["recovery_password"] != rawPwd {
		t.Fatalf("revealed password mismatch: got %q, want %q", rev["recovery_password"], rawPwd)
	}

	var auditCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'bitlocker.reveal_key' AND user_email = 'admin@lab.local' AND target_id = ?`, devID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 bitlocker.reveal_key audit log entry, got %d", auditCount)
	}

	// 5. Disable policy -> retracts BitLocker CSP settings
	wDisable := httptest.NewRecorder()
	h.HandleUpdateBitLockerPolicy(wDisable, withDeviceAndKeyRoute("PUT", "/api/bitlocker/policy", `{"enabled":false,"target_all_devices":true}`, "", "", "admin@lab.local"))
	if wDisable.Code != http.StatusOK {
		t.Fatalf("disable policy: want 200, got %d", wDisable.Code)
	}
}
