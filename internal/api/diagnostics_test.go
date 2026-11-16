package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDeviceCSPExplorerLifecycle(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-DIAG-API-1")
	h := NewHandler(database.DB)

	// 1. GET presets + empty history
	wGet := httptest.NewRecorder()
	h.HandleGetDeviceCSPExplorer(wGet, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/csp-explorer", "", devID, "", "admin@lab.local"))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET csp-explorer: want 200, got %d body=%s", wGet.Code, wGet.Body.String())
	}
	var initial struct {
		Presets []mdm.CSPPreset        `json:"presets"`
		Queries []CSPExplorerQueryItem `json:"queries"`
	}
	if err := json.Unmarshal(wGet.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if len(initial.Presets) < 10 || len(initial.Queries) != 0 {
		t.Fatalf("unexpected initial csp-explorer payload: presets=%d queries=%d", len(initial.Presets), len(initial.Queries))
	}

	// 2. Reject restricted URI (Accounts/Users password subtree)
	wBad := httptest.NewRecorder()
	h.HandleCreateDeviceCSPQuery(wBad, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/csp-explorer", `{
		"oma_uri": "./Device/Vendor/MSFT/Accounts/Users/lzadm-1/Password"
	}`, devID, "", "admin@lab.local"))
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on restricted Accounts/Users URI, got %d", wBad.Code)
	}

	// 3. Queue RebootRequired live CSP query
	wCreate := httptest.NewRecorder()
	h.HandleCreateDeviceCSPQuery(wCreate, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/csp-explorer", `{
		"oma_uri": "./Device/Vendor/MSFT/Reboot/RebootRequired"
	}`, devID, "", "admin@lab.local"))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("POST csp-explorer: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var created CSPExplorerQueryItem
	if err := json.Unmarshal(wCreate.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Label != "Reboot Pending Status" || created.QueueID <= 0 {
		t.Fatalf("unexpected created CSP query: %+v", created)
	}

	// Simulate device returning SyncML Results
	mdm.SyncCSPQueryStatus(database.DB, int(created.QueueID), "200")
	mdm.SyncCSPQueryResult(database.DB, int(created.QueueID), "false")

	// 4. Verify GET returns completed result_data="false"
	wAfter := httptest.NewRecorder()
	h.HandleGetDeviceCSPExplorer(wAfter, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/csp-explorer", "", devID, "", "admin@lab.local"))
	var after struct {
		Queries []CSPExplorerQueryItem `json:"queries"`
	}
	if err := json.Unmarshal(wAfter.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Queries) != 1 || after.Queries[0].Status != "success" || after.Queries[0].ResultData != "false" {
		t.Fatalf("unexpected completed CSP query: %+v", after.Queries)
	}

	// 5. Delete query history entry
	delReq := httptest.NewRequest("DELETE", "/api/devices/"+devID+"/csp-explorer/"+created.ID, strings.NewReader(""))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", devID)
	rctx.URLParams.Add("queryId", created.ID)
	ctx := context.WithValue(delReq.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, CtxKeyEmail, "admin@lab.local")
	wDel := httptest.NewRecorder()
	h.HandleDeleteDeviceCSPQuery(wDel, delReq.WithContext(ctx))
	if wDel.Code != http.StatusOK {
		t.Fatalf("DELETE csp-explorer query: want 200, got %d", wDel.Code)
	}
}
