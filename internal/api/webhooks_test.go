package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
	"github.com/latchzmdm/latchz/internal/webhooks"
)

func TestWebhooksAutomationAndExportsAPI(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-EXPORT-1")
	_, _ = database.DB.Exec(`
		UPDATE devices
		SET device_name = '=DANGER-PC', serial_number = 'SN-EXP-001', os_version = '10.0.22631.1'
		WHERE id = ?
	`, devID)
	_, _ = database.DB.Exec(`
		INSERT INTO device_software_inventory (device_id, app_key, name, version, publisher, source, install_date)
		VALUES (?, '7zip', '7-Zip 26.06', '26.06', 'Igor Pavlov', 'win32', '20261115')
	`, devID)

	v, err := vault.NewFast("unit-test-master-secret-api-webhooks")
	if err != nil {
		t.Fatal(err)
	}
	disp := webhooks.NewDispatcher(database.DB, v)

	h := NewHandler(database.DB)
	h.SetVault(v)
	h.SetWebhooks(disp)

	const secret = "whsec_api_test_98765"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !webhooks.VerifyHMACSignature(secret, r.Header.Get(webhooks.SignatureHeader), raw) {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 1. Create webhook
	wCreate := httptest.NewRecorder()
	h.HandleCreateWebhook(wCreate, withDeviceAndKeyRoute("POST", "/api/webhooks", `{
		"name": "SOC Slack",
		"url": "`+srv.URL+`",
		"format": "slack",
		"secret": "`+secret+`",
		"events": ["compliance.non_compliant", "bitlocker.reveal_key"]
	}`, "", "", "admin@lab.local"))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("POST /api/webhooks: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var created WebhookEndpoint
	if err := json.Unmarshal(wCreate.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.HasSecret || created.Format != "slack" {
		t.Fatalf("unexpected created webhook: %+v", created)
	}

	// 2. Test ping webhook
	wTest := httptest.NewRecorder()
	h.HandleTestWebhook(wTest, withDeviceAndKeyRoute("POST", "/api/webhooks/"+created.ID+"/test", "", created.ID, "", "admin@lab.local"))
	if wTest.Code != http.StatusOK {
		t.Fatalf("POST test webhook: want 200, got %d body=%s", wTest.Code, wTest.Body.String())
	}
	var pingRes webhooks.DeliveryResult
	if err := json.Unmarshal(wTest.Body.Bytes(), &pingRes); err != nil {
		t.Fatal(err)
	}
	if !pingRes.Success || pingRes.StatusCode != 200 {
		t.Fatalf("expected successful 200 test ping, got %+v", pingRes)
	}

	// 3. List deliveries
	wDeliv := httptest.NewRecorder()
	h.HandleListWebhookDeliveries(wDeliv, withDeviceAndKeyRoute("GET", "/api/webhooks/deliveries", "", "", "", "admin@lab.local"))
	if wDeliv.Code != http.StatusOK || !strings.Contains(wDeliv.Body.String(), `"webhook.test"`) {
		t.Fatalf("unexpected deliveries response: code=%d body=%s", wDeliv.Code, wDeliv.Body.String())
	}

	// 4. Update compliance automation
	wAuto := httptest.NewRecorder()
	h.HandleUpdateComplianceAutomation(wAuto, withDeviceAndKeyRoute("PUT", "/api/compliance/automation", `{"auto_remediate":true}`, "", "", "admin@lab.local"))
	if wAuto.Code != http.StatusOK || !strings.Contains(wAuto.Body.String(), `"auto_remediate":true`) {
		t.Fatalf("PUT compliance automation: code=%d body=%s", wAuto.Code, wAuto.Body.String())
	}

	// 5. Export devices CSV (check formula-injection sanitization) & JSON
	wDevCSV := httptest.NewRecorder()
	h.HandleExportDevices(wDevCSV, withDeviceAndKeyRoute("GET", "/api/export/devices?format=csv", "", "", "", "admin@lab.local"))
	if wDevCSV.Code != http.StatusOK || !strings.Contains(wDevCSV.Body.String(), "'=DANGER-PC") || !strings.Contains(wDevCSV.Body.String(), "SN-EXP-001") {
		t.Fatalf("unexpected device CSV export: code=%d body=%s", wDevCSV.Code, wDevCSV.Body.String())
	}

	wSwJSON := httptest.NewRecorder()
	h.HandleExportSoftware(wSwJSON, withDeviceAndKeyRoute("GET", "/api/export/software?format=json", "", "", "", "admin@lab.local"))
	if wSwJSON.Code != http.StatusOK || !strings.Contains(wSwJSON.Body.String(), "7-Zip 26.06") {
		t.Fatalf("unexpected software JSON export: code=%d body=%s", wSwJSON.Code, wSwJSON.Body.String())
	}

	// 6. Delete webhook
	wDel := httptest.NewRecorder()
	h.HandleDeleteWebhook(wDel, withDeviceAndKeyRoute("DELETE", "/api/webhooks/"+created.ID, "", created.ID, "", "admin@lab.local"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("DELETE webhook: want 200, got %d", wDel.Code)
	}
}
