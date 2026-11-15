package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestUpdateRingsLifecyclePauseAndRetraction(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	devID := testutil.SeedDevice(t, database, "HW-WU-1")

	// 1. Create fleet-wide Pilot ring -> queues 8 Replace + 1 Get (9 commands)
	wCreate := httptest.NewRecorder()
	createBody := `{"name":"Pilot Ring","description":"Early adopters","quality_deferral_days":3,"feature_deferral_days":14,"active_hours_start":8,"active_hours_end":17,"quality_deadline_days":5,"feature_deadline_days":10,"grace_period_days":2,"target_all_devices":true,"priority":10}`
	h.HandleCreateUpdateRing(wCreate, withDeviceAndKeyRoute("POST", "/api/updates/rings", createBody, "", "", "admin@lab.local"))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create ring: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var created UpdateRing
	if err := json.Unmarshal(wCreate.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.GovernedDevices != 1 || created.CommandsQueued != 9 {
		t.Fatalf("unexpected created ring stats: %+v", created)
	}

	// 2. Pause quality updates -> sets ISO date and queues PauseQualityUpdatesStartTime Replace
	wPause := httptest.NewRecorder()
	h.HandlePauseResumeUpdateRing(wPause, withDeviceAndKeyRoute("POST", "/api/updates/rings/"+created.ID+"/pause", `{"target":"quality","paused":true}`, created.ID, "", "admin@lab.local"))
	if wPause.Code != http.StatusOK {
		t.Fatalf("pause ring: want 200, got %d body=%s", wPause.Code, wPause.Body.String())
	}
	var paused UpdateRing
	if err := json.Unmarshal(wPause.Body.Bytes(), &paused); err != nil {
		t.Fatal(err)
	}
	if !paused.QualityPaused || paused.QualityPauseStart == "" {
		t.Fatalf("expected quality_paused=true, got %+v", paused)
	}

	var pausePayload string
	if err := database.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ? AND command_type = 'Replace'`, devID, mdm.OMAPolicyUpdatePauseQualityStart).Scan(&pausePayload); err != nil {
		t.Fatalf("expected queued PauseQualityUpdatesStartTime Replace: %v", err)
	}

	// 3. Resume quality updates -> cancels pending Replace and queues Delete
	wResume := httptest.NewRecorder()
	h.HandlePauseResumeUpdateRing(wResume, withDeviceAndKeyRoute("POST", "/api/updates/rings/"+created.ID+"/pause", `{"target":"quality","paused":false}`, created.ID, "", "admin@lab.local"))
	if wResume.Code != http.StatusOK {
		t.Fatalf("resume ring: want 200, got %d", wResume.Code)
	}
	var delCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND oma_uri = ? AND command_type = 'Delete'`, devID, mdm.OMAPolicyUpdatePauseQualityStart).Scan(&delCount); err != nil {
		t.Fatal(err)
	}
	if delCount != 1 {
		t.Fatalf("expected Delete command on resume, got %d", delCount)
	}

	// 4. Delete ring -> retracts all 10 Update CSP URIs via Delete
	wDel := httptest.NewRecorder()
	h.HandleDeleteUpdateRing(wDel, withDeviceAndKeyRoute("DELETE", "/api/updates/rings/"+created.ID, "", created.ID, "", "admin@lab.local"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("delete ring: want 200, got %d", wDel.Code)
	}
}
