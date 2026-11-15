package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDevicePostureAndFleetSummary(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	devID := testutil.SeedDevice(t, database, "HW-POSTURE")

	// 1. Before posture collection -> Collected: false, labels "Unknown"
	wEmpty := httptest.NewRecorder()
	h.HandleGetDevicePosture(wEmpty, withRoute("GET", "/api/devices/"+devID+"/posture", "", devID))
	if wEmpty.Code != http.StatusOK {
		t.Fatalf("empty posture: want 200, got %d body=%s", wEmpty.Code, wEmpty.Body.String())
	}
	var empty DevicePosture
	if err := json.Unmarshal(wEmpty.Body.Bytes(), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Collected || empty.SecureBootLabel != "Unknown" {
		t.Fatalf("unexpected empty posture: %+v", empty)
	}

	// 2. Refresh posture -> queues Get commands for FirstCheckInURIs
	wRefresh := httptest.NewRecorder()
	h.HandleRefreshDevicePosture(wRefresh, withRoute("POST", "/api/devices/"+devID+"/posture/refresh", "", devID))
	if wRefresh.Code != http.StatusOK {
		t.Fatalf("refresh posture: want 200, got %d body=%s", wRefresh.Code, wRefresh.Body.String())
	}
	var pending int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Get'`, devID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending < 10 {
		t.Fatalf("expected >=10 queued Get commands for posture refresh, got %d", pending)
	}

	// 3. Seed posture telemetry and verify labels + fleet summary
	_, err := database.Exec(`
		INSERT INTO device_posture (
			device_id, total_ram_mb, total_storage_mb, free_storage_mb,
			bios_version, os_platform, tpm_version,
			secure_boot_state, encryption_status, antivirus_status, firewall_status
		) VALUES (?, 16384, 512000, 320000, 'UEFI 2.8', 'Windows 11 Pro', '2.0', 1, 0, 0, 0)
	`, devID)
	if err != nil {
		t.Fatal(err)
	}

	wGot := httptest.NewRecorder()
	h.HandleGetDevicePosture(wGot, withRoute("GET", "/api/devices/"+devID+"/posture", "", devID))
	if wGot.Code != http.StatusOK {
		t.Fatalf("populated posture: want 200, got %d body=%s", wGot.Code, wGot.Body.String())
	}
	var got DevicePosture
	if err := json.Unmarshal(wGot.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Collected || got.SecureBootLabel != "Enabled" || got.EncryptionLabel != "Encrypted" || got.AntivirusLabel != "Active & Monitoring" || got.FirewallLabel != "Active & Monitoring" {
		t.Fatalf("unexpected posture labels: %+v", got)
	}

	wSum := httptest.NewRecorder()
	h.HandleFleetPostureSummary(wSum, httptest.NewRequest("GET", "/api/posture/summary", nil))
	if wSum.Code != http.StatusOK {
		t.Fatalf("fleet posture summary: want 200, got %d", wSum.Code)
	}
	var sum FleetPostureSummary
	if err := json.Unmarshal(wSum.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.TotalActiveDevices != 1 || sum.PostureReportedDevices != 1 || sum.SecureBootEnabled != 1 || sum.BitLockerEncrypted != 1 || sum.AntivirusHealthy != 1 || sum.FirewallHealthy != 1 {
		t.Fatalf("unexpected fleet posture summary: %+v", sum)
	}

	// 5. WNS push without configured WNS client -> 503 Service Unavailable
	wPushDisabled := httptest.NewRecorder()
	h.HandlePushWakeDevice(wPushDisabled, withRoute("POST", "/api/devices/"+devID+"/push", "", devID))
	if wPushDisabled.Code != http.StatusServiceUnavailable {
		t.Fatalf("push wake without WNS config: want 503, got %d", wPushDisabled.Code)
	}

	// 6. Seed WNS channel row and verify posture exposes wns_channel_active=true
	if _, err := database.Exec(`INSERT INTO device_wns_channels (device_id, channel_uri, last_push_status) VALUES (?, ?, 'sent:received')`, devID, "https://wns2-bl2p.notify.windows.com/?token=abc"); err != nil {
		t.Fatal(err)
	}
	wGotWNS := httptest.NewRecorder()
	h.HandleGetDevicePosture(wGotWNS, withRoute("GET", "/api/devices/"+devID+"/posture", "", devID))
	var gotWNS DevicePosture
	if err := json.Unmarshal(wGotWNS.Body.Bytes(), &gotWNS); err != nil {
		t.Fatal(err)
	}
	if !gotWNS.WNSChannelActive || gotWNS.WNSLastPushStatus != "sent:received" {
		t.Fatalf("expected active WNS channel in posture response, got %+v", gotWNS)
	}
}
