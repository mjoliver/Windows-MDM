package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestEndpointHardeningPolicyLifecycle(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-HARDEN-API-1")
	h := NewHandler(database.DB)

	// 1. GET default hardening policy + official ASR catalog
	wGet := httptest.NewRecorder()
	h.HandleGetHardeningPolicy(wGet, withDeviceAndKeyRoute("GET", "/api/hardening/policy", "", "", "", "admin@lab.local"))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET hardening policy: want 200, got %d", wGet.Code)
	}
	var defPol EndpointHardeningPolicy
	if err := json.Unmarshal(wGet.Body.Bytes(), &defPol); err != nil {
		t.Fatal(err)
	}
	if defPol.Enabled || len(defPol.Catalog) < 10 {
		t.Fatalf("unexpected default hardening policy: %+v", defPol)
	}

	// 2. PUT enable ASR rules + SmartScreen hardening across fleet
	wPut := httptest.NewRecorder()
	h.HandleUpdateHardeningPolicy(wPut, withDeviceAndKeyRoute("PUT", "/api/hardening/policy", `{
		"enabled": true,
		"asr_rules": {
			"be9ba2d9-53ea-4cdc-84e5-9b1feed46555": 1,
			"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 2
		},
		"enable_smartscreen_shell": true,
		"prevent_smartscreen_override": true,
		"app_install_control": 3,
		"submit_samples_consent": 1,
		"disable_local_admin_merge": true,
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT hardening policy: want 200, got %d body=%s", wPut.Code, wPut.Body.String())
	}
	var saved EndpointHardeningPolicy
	if err := json.Unmarshal(wPut.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Enabled || saved.ActiveASRCount != 2 || saved.EnforcedDevices != 1 || saved.CommandsQueued != 6 {
		t.Fatalf("unexpected saved hardening policy: %+v", saved)
	}

	// 3. GET /api/devices/{id}/hardening
	wDev := httptest.NewRecorder()
	h.HandleGetDeviceHardening(wDev, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/hardening", "", devID, "", "admin@lab.local"))
	if wDev.Code != http.StatusOK {
		t.Fatalf("GET device hardening: want 200, got %d", wDev.Code)
	}
	var devState DeviceEndpointHardeningState
	if err := json.Unmarshal(wDev.Body.Bytes(), &devState); err != nil {
		t.Fatal(err)
	}
	if !devState.Enforced || devState.ActiveASRCount != 2 {
		t.Fatalf("unexpected device hardening state: %+v", devState)
	}

	// 4. Disable hardening -> verify <Delete> retraction queued
	wOff := httptest.NewRecorder()
	h.HandleUpdateHardeningPolicy(wOff, withDeviceAndKeyRoute("PUT", "/api/hardening/policy", `{
		"enabled": false,
		"asr_rules": {},
		"enable_smartscreen_shell": true,
		"prevent_smartscreen_override": true,
		"app_install_control": 0,
		"submit_samples_consent": 1,
		"disable_local_admin_merge": true,
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wOff.Code != http.StatusOK {
		t.Fatalf("PUT disable hardening: want 200, got %d", wOff.Code)
	}

	var delCount int
	if err := database.DB.QueryRow(`
		SELECT COUNT(*) FROM command_queue
		WHERE device_id = ? AND command_type = 'Delete'
		  AND oma_uri = './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules'
	`, devID).Scan(&delCount); err != nil {
		t.Fatal(err)
	}
	if delCount != 1 {
		t.Fatalf("expected 1 Delete command on AttackSurfaceReductionRules, got %d", delCount)
	}
}
