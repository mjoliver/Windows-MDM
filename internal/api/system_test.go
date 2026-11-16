package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestSystemStatusPrometheusMetricsAndSQLiteHotBackup(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	_ = testutil.SeedDevice(t, database, "HW-SYS-1")

	h := NewHandler(database.DB)
	h.SetCA(ca)

	RecordOMADMMetric(18 * time.Millisecond)

	// 1. GET /api/system/status
	wSt := httptest.NewRecorder()
	h.HandleSystemStatus(wSt, withDeviceAndKeyRoute("GET", "/api/system/status", "", "", "", "admin@lab.local"))
	if wSt.Code != http.StatusOK {
		t.Fatalf("GET /api/system/status: got %d body=%s", wSt.Code, wSt.Body.String())
	}
	var st SystemStatus
	if err := json.Unmarshal(wSt.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.DBOK || !st.CALoaded || st.ActiveDevices != 1 || st.OMADMCheckinsTotal < 1 {
		t.Fatalf("unexpected system status: %+v", st)
	}

	// 2. GET /api/system/metrics (Prometheus format)
	wProm := httptest.NewRecorder()
	h.HandlePrometheusMetrics(wProm, withDeviceAndKeyRoute("GET", "/api/system/metrics", "", "", "", "admin@lab.local"))
	if wProm.Code != http.StatusOK {
		t.Fatalf("GET /api/system/metrics: got %d", wProm.Code)
	}
	promBody := wProm.Body.String()
	for _, want := range []string{
		"latchz_up 1",
		`latchz_devices_total{state="active"} 1`,
		"latchz_omadm_checkins_total ",
		"latchz_go_goroutines ",
	} {
		if !strings.Contains(promBody, want) {
			t.Fatalf("Prometheus output missing %q:\n%s", want, promBody)
		}
	}

	// 3. GET /api/system/backup (SQLite VACUUM INTO hot snapshot -> starts with "SQLite format 3\x00" magic!)
	wBak := httptest.NewRecorder()
	h.HandleDownloadBackup(wBak, withDeviceAndKeyRoute("GET", "/api/system/backup", "", "", "", "admin@lab.local"))
	if wBak.Code != http.StatusOK {
		t.Fatalf("GET /api/system/backup: got %d body=%s", wBak.Code, wBak.Body.String())
	}
	if !bytes.HasPrefix(wBak.Body.Bytes(), []byte("SQLite format 3\x00")) {
		t.Fatalf("downloaded backup lacks SQLite format 3 header (len=%d)", wBak.Body.Len())
	}
}
