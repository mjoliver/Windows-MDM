package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDesktopExperiencePolicyAPI(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-EXP-API-1")
	h := NewHandler(database.DB)

	wGet := httptest.NewRecorder()
	h.HandleGetExperiencePolicy(wGet, withDeviceAndKeyRoute("GET", "/api/experience/policy", "", "", "", "admin@lab.local"))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET /api/experience/policy: got %d", wGet.Code)
	}

	wPut := httptest.NewRecorder()
	h.HandleUpdateExperiencePolicy(wPut, withDeviceAndKeyRoute("PUT", "/api/experience/policy", `{
		"enabled": true,
		"telemetry_level": 1,
		"disable_advertising_id": true,
		"block_tailored_experiences": true,
		"disable_widgets_news": true,
		"edge_smartscreen_enabled": true,
		"edge_prevent_ss_override": true,
		"edge_smartscreen_pua": true,
		"edge_block_password_manager": true,
		"edge_typosquatting_checker": true,
		"desktop_wallpaper_url": "",
		"lockscreen_image_url": "",
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/experience/policy: got %d body=%s", wPut.Code, wPut.Body.String())
	}
	var updated DesktopExperiencePolicy
	if err := json.Unmarshal(wPut.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.Enabled || updated.EnforcedDevices != 1 || updated.CommandsQueued != 9 {
		t.Fatalf("unexpected updated experience policy: %+v", updated)
	}

	// Mark commands complete and retract
	_, _ = database.DB.Exec(`UPDATE command_queue SET status = 'success' WHERE device_id = ?`, devID)
	wOff := httptest.NewRecorder()
	h.HandleUpdateExperiencePolicy(wOff, withDeviceAndKeyRoute("PUT", "/api/experience/policy", `{
		"enabled": false,
		"telemetry_level": 1,
		"disable_advertising_id": true,
		"block_tailored_experiences": true,
		"disable_widgets_news": true,
		"edge_smartscreen_enabled": true,
		"edge_prevent_ss_override": true,
		"edge_smartscreen_pua": true,
		"edge_block_password_manager": false,
		"edge_typosquatting_checker": true,
		"desktop_wallpaper_url": "",
		"lockscreen_image_url": "",
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wOff.Code != http.StatusOK {
		t.Fatalf("PUT disable experience policy: got %d", wOff.Code)
	}
	var retracted DesktopExperiencePolicy
	_ = json.Unmarshal(wOff.Body.Bytes(), &retracted)
	if retracted.Enabled || retracted.EnforcedDevices != 0 || retracted.CommandsQueued != 9 {
		t.Fatalf("unexpected retracted experience policy: %+v", retracted)
	}
}
