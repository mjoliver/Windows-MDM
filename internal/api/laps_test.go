package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func TestLAPSPolicyProvisionRotateAndAuditedReveal(t *testing.T) {
	database := testutil.DB(t)
	secVault, err := vault.NewFast("unit-test-master-secret-32-chars!!")
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(database.DB)
	h.SetVault(secVault)
	devID := testutil.SeedDevice(t, database, "HW-LAPS-1")

	wPut := httptest.NewRecorder()
	h.HandleUpdateLAPSPolicy(wPut, withDeviceAndKeyRoute(
		"PUT", "/api/laps/policy",
		`{"enabled":true,"account_prefix":"lzadm","password_length":20,"rotation_days":14,"rotate_after_reveal_minutes":120,"target_all_devices":true,"group_ids":[]}`,
		"", "", "admin@lab.local",
	))
	if wPut.Code != http.StatusOK {
		t.Fatalf("update LAPS policy: want 200, got %d body=%s", wPut.Code, wPut.Body.String())
	}

	// Ensure plaintext password is NEVER stored in command_queue
	var rawPayload string
	if err := database.DB.QueryRow(`
		SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri LIKE '%/Password'
	`, devID).Scan(&rawPayload); err != nil {
		t.Fatalf("querying LAPS Password queue item: %v", err)
	}
	if rawPayload != mdm.VaultLAPSSentinel {
		t.Fatalf("command_queue leaked non-sentinel payload: %q", rawPayload)
	}

	wGet := httptest.NewRecorder()
	h.HandleGetDeviceLAPS(wGet, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/laps", "", devID, "", "admin@lab.local"))
	if wGet.Code != http.StatusOK {
		t.Fatalf("get device LAPS: want 200, got %d", wGet.Code)
	}
	if strings.Contains(wGet.Body.String(), "lv1:") {
		t.Fatalf("GET /devices/{id}/laps leaked ciphertext: %s", wGet.Body.String())
	}

	wRev := httptest.NewRecorder()
	h.HandleRevealDeviceLAPS(wRev, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/laps/reveal", "", devID, "", "admin@lab.local"))
	if wRev.Code != http.StatusOK {
		t.Fatalf("reveal LAPS: want 200, got %d body=%s", wRev.Code, wRev.Body.String())
	}
	var revealed RevealedLAPSCredentials
	if err := json.Unmarshal(wRev.Body.Bytes(), &revealed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(revealed.PendingAccount, "lzadm-") || len(revealed.PendingPassword) != 20 {
		t.Fatalf("unexpected revealed credentials: %+v", revealed)
	}

	wRot := httptest.NewRecorder()
	h.HandleRotateDeviceLAPS(wRot, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/laps/rotate", "", devID, "", "admin@lab.local"))
	if wRot.Code != http.StatusOK {
		t.Fatalf("rotate LAPS: want 200, got %d body=%s", wRot.Code, wRot.Body.String())
	}
}
