package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestBulkEnrollmentTokensAndBootstrapScriptAPI(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	h.ConfigureContentRelay("https://enterpriseenrollment.lab.local", []byte("0123456789abcdef0123456789abcdef"))

	_, err := database.DB.Exec(`INSERT INTO device_groups (id, name, description) VALUES ('grp-oobe', 'OOBE Kiosks', '')`)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create bulk token bound to grp-oobe
	wCreate := httptest.NewRecorder()
	h.HandleCreateEnrollmentToken(wCreate, withDeviceAndKeyRoute("POST", "/api/enrollment/tokens", `{
		"name": "Warehouse OOBE",
		"auto_group_id": "grp-oobe",
		"max_uses": 5,
		"expires_in_days": 30
	}`, "", "", "admin@lab.local"))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("POST /api/enrollment/tokens: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var created BulkEnrollmentTokenItem
	if err := json.Unmarshal(wCreate.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.RawToken, auth.BulkTokenPrefix) || created.AutoGroupName != "OOBE Kiosks" {
		t.Fatalf("unexpected created bulk token: %+v", created)
	}

	// 2. List tokens -> raw token MUST NOT be returned on list!
	wList := httptest.NewRecorder()
	h.HandleListEnrollmentTokens(wList, withDeviceAndKeyRoute("GET", "/api/enrollment/tokens", "", "", "", "admin@lab.local"))
	if wList.Code != http.StatusOK || strings.Contains(wList.Body.String(), created.RawToken) {
		t.Fatalf("GET /api/enrollment/tokens leaked raw token or failed: code=%d body=%s", wList.Code, wList.Body.String())
	}

	// 3. Consume once via auth.ConsumeBulkEnrollmentToken -> verify use_count=1 and auto_group_id
	owner, autoGrp, _, err := auth.ConsumeBulkEnrollmentToken(database.DB, created.RawToken)
	if err != nil || owner != "admin@lab.local" || autoGrp != "grp-oobe" {
		t.Fatalf("ConsumeBulkEnrollmentToken failed: owner=%q grp=%q err=%v", owner, autoGrp, err)
	}

	// 4. Download bootstrap.ps1
	wPS := httptest.NewRecorder()
	h.HandleDownloadEnrollmentBootstrap(wPS, withDeviceAndKeyRoute("GET", "/api/enrollment/bootstrap.ps1", "", "", "", "admin@lab.local"))
	if wPS.Code != http.StatusOK || !strings.Contains(wPS.Body.String(), "https://enterpriseenrollment.lab.local/pki/ca.pem") {
		t.Fatalf("unexpected bootstrap.ps1 response: code=%d body=%s", wPS.Code, wPS.Body.String())
	}

	// 5. Revoke token -> subsequent consume MUST fail
	wRev := httptest.NewRecorder()
	h.HandleDeleteEnrollmentToken(wRev, withDeviceAndKeyRoute("DELETE", "/api/enrollment/tokens/"+created.ID, "", created.ID, "", "admin@lab.local"))
	if wRev.Code != http.StatusOK {
		t.Fatalf("DELETE (revoke) token: want 200, got %d", wRev.Code)
	}
	if _, _, _, err := auth.ConsumeBulkEnrollmentToken(database.DB, created.RawToken); err == nil {
		t.Fatal("expected revoked bulk token to fail consumption")
	}
}
