package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDeviceLockdownPolicyLifecycle(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-LOCK-API-1")
	h := NewHandler(database.DB)

	// 1. Enable USB block_all + DeviceLock policy
	wPut := httptest.NewRecorder()
	h.HandleUpdateLockdownPolicy(wPut, withDeviceAndKeyRoute("PUT", "/api/lockdown/policy", `{
		"enabled": true,
		"usb_storage_mode": "block_all",
		"require_password": true,
		"min_password_length": 12,
		"alphanumeric_required": true,
		"max_inactivity_minutes": 10,
		"max_failed_attempts": 6,
		"allow_camera": false,
		"allow_bluetooth": true,
		"kiosk_mode": "none",
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/lockdown/policy: want 200, got %d body=%s", wPut.Code, wPut.Body.String())
	}
	var pol DeviceLockdownPolicy
	if err := json.Unmarshal(wPut.Body.Bytes(), &pol); err != nil {
		t.Fatal(err)
	}
	if !pol.Enabled || pol.USBStorageMode != "block_all" || pol.EnforcedDevices != 1 || pol.CommandsQueued == 0 {
		t.Fatalf("unexpected lockdown policy response: %+v", pol)
	}

	// 2. Verify GET /api/devices/{id}/lockdown reports Enforced=true
	wDev := httptest.NewRecorder()
	h.HandleGetDeviceLockdown(wDev, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/lockdown", "", devID, "", "admin@lab.local"))
	if wDev.Code != http.StatusOK {
		t.Fatalf("GET device lockdown: want 200, got %d", wDev.Code)
	}
	var st DeviceLockdownState
	if err := json.Unmarshal(wDev.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Enforced {
		t.Fatalf("expected device lockdown Enforced=true, got %+v", st)
	}

	// 3. Disable policy -> verify retraction commands queued
	wDisable := httptest.NewRecorder()
	h.HandleUpdateLockdownPolicy(wDisable, withDeviceAndKeyRoute("PUT", "/api/lockdown/policy", `{
		"enabled": false,
		"usb_storage_mode": "allow",
		"require_password": true,
		"min_password_length": 8,
		"max_inactivity_minutes": 15,
		"max_failed_attempts": 10,
		"allow_camera": true,
		"allow_bluetooth": true,
		"kiosk_mode": "none",
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wDisable.Code != http.StatusOK {
		t.Fatalf("disable lockdown policy: want 200, got %d body=%s", wDisable.Code, wDisable.Body.String())
	}
	var disabledPol DeviceLockdownPolicy
	if err := json.Unmarshal(wDisable.Body.Bytes(), &disabledPol); err != nil {
		t.Fatal(err)
	}
	if disabledPol.Enabled || disabledPol.EnforcedDevices != 0 || disabledPol.CommandsQueued == 0 {
		t.Fatalf("expected retraction commands on disable, got %+v", disabledPol)
	}
}
