package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/testutil"
)

// withRoute builds a request carrying a chi URL param and an authenticated actor.
func withRoute(method, target, body, id string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, CtxKeyEmail, "admin@example.com")
	ctx = context.WithValue(ctx, CtxKeyRole, "admin")
	return r.WithContext(ctx)
}

func TestHandleListDevices(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	testutil.SeedDevice(t, database, "HW-LIST")

	w := httptest.NewRecorder()
	h.HandleListDevices(w, httptest.NewRequest("GET", "/api/devices", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "HW-LIST") {
		t.Fatalf("device not listed: %s", w.Body.String())
	}
}

func TestHandleGetDevice_NotFound(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	w := httptest.NewRecorder()
	h.HandleGetDevice(w, withRoute("GET", "/api/devices/missing", "", "missing"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandleWipeDevice(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	id := testutil.SeedDevice(t, database, "HW-WIPE")

	// Without confirmation → 400, no command queued.
	w := httptest.NewRecorder()
	h.HandleWipeDevice(w, withRoute("POST", "/x", `{"confirm":false}`, id))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without confirm, got %d", w.Code)
	}

	// With confirmation → 200, a wipe Exec is queued.
	w = httptest.NewRecorder()
	h.HandleWipeDevice(w, withRoute("POST", "/x", `{"confirm":true}`, id))
	if w.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Exec'`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 queued Exec (wipe), got %d", n)
	}
}

func TestHandleRebootDevice(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	id := testutil.SeedDevice(t, database, "HW-REBOOT")

	w := httptest.NewRecorder()
	h.HandleRebootDevice(w, withRoute("POST", "/api/devices/"+id+"/reboot", "", id))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var omaURI string
	if err := database.QueryRow(`SELECT oma_uri FROM command_queue WHERE device_id = ? AND command_type = 'Exec'`, id).Scan(&omaURI); err != nil {
		t.Fatal(err)
	}
	if omaURI != "./Device/Vendor/MSFT/Reboot/RebootNow" {
		t.Fatalf("unexpected reboot URI: %s", omaURI)
	}
}

func TestHandleUnenrollDevice(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	h := NewHandler(database.DB)
	id := testutil.SeedDevice(t, database, "HW-UNENROLL")
	testutil.IssueClientCert(t, ca, id, "x")

	w := httptest.NewRecorder()
	h.HandleUnenrollDevice(w, withRoute("DELETE", "/x", "", id))
	if w.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}

	var active, revoked int
	database.QueryRow(`SELECT is_active FROM devices WHERE id = ?`, id).Scan(&active)
	database.QueryRow(`SELECT revoked FROM certificates WHERE device_id = ?`, id).Scan(&revoked)
	if active != 0 {
		t.Fatal("device should be inactive after unenroll")
	}
	if revoked != 1 {
		t.Fatal("device cert should be revoked after unenroll")
	}
}

func TestHandleSyncDevice_QueuesPolicyReplace(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	devID := testutil.SeedDevice(t, database, "HW-SYNC")

	res, err := database.Exec(`
		INSERT INTO policy_catalog (oma_uri, display_name, category, csp_name, data_type, access_types)
		VALUES ('./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock', 'Max Inactivity', 'DeviceLock', 'Policy', 'integer', '["Get","Replace"]')
	`)
	if err != nil {
		t.Fatal(err)
	}
	catID, _ := res.LastInsertId()

	if _, err := database.Exec(`INSERT INTO profiles (id, name) VALUES ('prof-sync', 'Idle Lock')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO profile_settings (profile_id, catalog_id, desired_value) VALUES ('prof-sync', ?, '5')`, catID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO device_groups (id, name) VALUES ('grp-sync', 'Lab')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO device_group_members (device_id, group_id) VALUES (?, 'grp-sync')`, devID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO group_profiles (group_id, profile_id) VALUES ('grp-sync', 'prof-sync')`); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.HandleSyncDevice(w, withRoute("POST", "/api/devices/"+devID+"/sync", "", devID))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}

	var replaceCount, getCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Replace'`, devID).Scan(&replaceCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Get'`, devID).Scan(&getCount); err != nil {
		t.Fatal(err)
	}
	if replaceCount != 1 {
		t.Fatalf("expected HandleSyncDevice to queue 1 Replace via policy.ApplyDevice, got %d", replaceCount)
	}
	if getCount < 1 {
		t.Fatalf("expected HandleSyncDevice to queue at least 1 Get, got %d", getCount)
	}
}

func TestHandleRenameAndRetireDevice(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	devID := testutil.SeedDevice(t, database, "HW-RENAME-RETIRE")

	// Invalid hostname -> 400
	w := httptest.NewRecorder()
	h.HandleRenameDevice(w, withRoute("POST", "/api/devices/"+devID+"/rename", `{"hostname":"bad space"}`, devID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 on invalid hostname, got %d", w.Code)
	}

	// Valid hostname with %SERIAL% -> 200 and pending_hostname persisted
	w = httptest.NewRecorder()
	h.HandleRenameDevice(w, withRoute("POST", "/api/devices/"+devID+"/rename", `{"hostname":"LZ-%serial%","reboot_now":false}`, devID))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 on rename, got %d (%s)", w.Code, w.Body.String())
	}
	var pendingHost string
	_ = database.QueryRow(`SELECT pending_hostname FROM devices WHERE id = ?`, devID).Scan(&pendingHost)
	if pendingHost != "LZ-%SERIAL%" {
		t.Fatalf("pending_hostname = %q, want LZ-%%SERIAL%%", pendingHost)
	}

	// Retire without confirm -> 400
	w = httptest.NewRecorder()
	h.HandleRetireDevice(w, withRoute("POST", "/api/devices/"+devID+"/retire", `{"confirm":false}`, devID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without confirm on retire, got %d", w.Code)
	}

	// Retire with confirm -> 200, enrollment_state='retiring', DMClient Unenroll queued
	w = httptest.NewRecorder()
	h.HandleRetireDevice(w, withRoute("POST", "/api/devices/"+devID+"/retire", `{"confirm":true}`, devID))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 on retire, got %d (%s)", w.Code, w.Body.String())
	}
	var state, omaURI string
	_ = database.QueryRow(`SELECT enrollment_state FROM devices WHERE id = ?`, devID).Scan(&state)
	if state != "retiring" {
		t.Fatalf("enrollment_state = %q, want retiring", state)
	}
	if err := database.QueryRow(`SELECT oma_uri FROM command_queue WHERE device_id = ? AND status = 'pending'`, devID).Scan(&omaURI); err != nil {
		t.Fatal(err)
	}
	if omaURI != "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Unenroll" {
		t.Fatalf("unexpected retire oma_uri: %s", omaURI)
	}
}
