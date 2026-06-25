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
