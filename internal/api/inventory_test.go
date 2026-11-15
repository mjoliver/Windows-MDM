package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/winget"
)

func TestDeviceSoftwareInventoryAndWinGetRefresh(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-INV-API-1")
	h := NewHandler(database.DB)

	var releaseV27 atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/7/7zip/7zip", func(w http.ResponseWriter, _ *http.Request) {
		if releaseV27.Load() {
			_, _ = w.Write([]byte(`[{"name":"26.06","type":"dir"},{"name":"27.01","type":"dir"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"name":"26.06","type":"dir"}]`))
	})
	mux.HandleFunc("/raw/7/7zip/7zip/26.06/7zip.7zip.installer.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
PackageIdentifier: 7zip.7zip
PackageVersion: "26.06"
Installers:
- Architecture: x64
  InstallerType: wix
  InstallerUrl: https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi
  InstallerSha256: 6DC822569E777D9A3ECD5FFCBC22B55600AF87E6C5D9810A64E8566CF5A4AF9F
  ProductCode: '{23170F69-40C1-2702-2606-000001000000}'
  AppsAndFeaturesEntries:
  - UpgradeCode: '{23170F69-40C1-2702-0000-000004000000}'
`))
	})
	mux.HandleFunc("/raw/7/7zip/7zip/26.06/7zip.7zip.locale.en-US.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PackageName: 7-Zip\nPublisher: Igor Pavlov\n"))
	})
	mux.HandleFunc("/raw/7/7zip/7zip/27.01/7zip.7zip.installer.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
PackageIdentifier: 7zip.7zip
PackageVersion: "27.01"
Installers:
- Architecture: x64
  InstallerType: wix
  InstallerUrl: https://github.com/ip7z/7zip/releases/download/27.01/7z2701-x64.msi
  InstallerSha256: 111122569E777D9A3ECD5FFCBC22B55600AF87E6C5D9810A64E8566CF5A4AF9F
  ProductCode: '{23170F69-40C1-2702-2701-000001000000}'
  AppsAndFeaturesEntries:
  - UpgradeCode: '{23170F69-40C1-2702-0000-000004000000}'
`))
	})
	mux.HandleFunc("/raw/7/7zip/7zip/27.01/7zip.7zip.locale.en-US.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PackageName: 7-Zip\nPublisher: Igor Pavlov\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wg := winget.NewClient()
	wg.SetEndpoints(srv.Client(), srv.URL+"/gh", srv.URL+"/raw", "")
	h.SetWinGetClient(wg)
	h.SetContentHTTPClient(&http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: 2048000, Body: http.NoBody}, nil
	})})

	// 1. Seed endpoint software inventory BEFORE importing 7-Zip into catalog (simulating auto-updated 26.09 on device)
	_, err := database.DB.Exec(`
		INSERT INTO device_software_inventory (
			device_id, app_key, name, publisher, version, source, product_code, upgrade_code
		) VALUES
			(?, 'msi:{23170F69-40C1-2702-2609-000001000000}', '7-Zip 26.09 (x64 edition)', 'Igor Pavlov', '26.09.00.0', 'msi', '{23170F69-40C1-2702-2609-000001000000}', '{23170F69-40C1-2702-0000-000004000000}'),
			(?, 'win32:vscode', 'Microsoft Visual Studio Code', 'Microsoft Corporation', '1.99.2', 'win32', '', '')
	`, devID, devID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Import 7-Zip v26.06 from WinGet
	wImport := httptest.NewRecorder()
	h.HandleImportWinGetApp(wImport, withDeviceAndKeyRoute("POST", "/api/apps/winget/import", `{"package_id":"7zip.7zip","architecture":"x64"}`, "", "", "admin@lab.local"))
	if wImport.Code != http.StatusCreated {
		t.Fatalf("import 7zip: want 201, got %d body=%s", wImport.Code, wImport.Body.String())
	}
	var app MSIApp
	if err := json.Unmarshal(wImport.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	if app.WinGetPackageID != "7zip.7zip" {
		t.Fatalf("expected winget_package_id=7zip.7zip, got %q", app.WinGetPackageID)
	}

	// 3. Deploy 7-Zip to device — since device already has 26.09 >= 26.06, installed_version reconciles immediately!
	wDeploy := httptest.NewRecorder()
	h.HandleInstallAppOnDevices(wDeploy, withDeviceAndKeyRoute("POST", "/api/apps/"+app.ID+"/install", `{"device_ids":["`+devID+`"]}`, app.ID, "", "admin@lab.local"))
	if wDeploy.Code != http.StatusOK {
		t.Fatalf("deploy: want 200, got %d body=%s", wDeploy.Code, wDeploy.Body.String())
	}

	wDevApps := httptest.NewRecorder()
	h.HandleGetDeviceApps(wDevApps, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/apps", "", devID, "", "admin@lab.local"))
	if wDevApps.Code != http.StatusOK {
		t.Fatalf("device apps: want 200, got %d", wDevApps.Code)
	}
	var installs []DeviceAppInstall
	if err := json.Unmarshal(wDevApps.Body.Bytes(), &installs); err != nil {
		t.Fatal(err)
	}
	if len(installs) != 1 || installs[0].InstalledVersion != "26.09.00.0" || installs[0].VersionState != "auto_updated" {
		t.Fatalf("expected installed_version=26.09.00.0 & version_state=auto_updated, got %+v", installs)
	}

	// 4. Query GET /api/devices/{id}/inventory?q=7-zip
	wInv := httptest.NewRecorder()
	h.HandleGetDeviceInventory(wInv, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/inventory?q=7-zip", "", devID, "", "admin@lab.local"))
	if wInv.Code != http.StatusOK {
		t.Fatalf("device inventory: want 200, got %d", wInv.Code)
	}
	var invResp DeviceSoftwareInventoryResponse
	if err := json.Unmarshal(wInv.Body.Bytes(), &invResp); err != nil {
		t.Fatal(err)
	}
	if invResp.Total != 2 || len(invResp.Items) != 1 || invResp.Items[0].ManagedAppID != app.ID || invResp.Items[0].VersionState != "auto_updated" {
		t.Fatalf("unexpected filtered inventory response: %+v", invResp)
	}

	// 5. Queue software inventory sync (POST /api/devices/{id}/inventory/sync)
	wSync := httptest.NewRecorder()
	h.HandleSyncDeviceInventory(wSync, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/inventory/sync", "", devID, "", "admin@lab.local"))
	if wSync.Code != http.StatusOK {
		t.Fatalf("inventory sync: want 200, got %d body=%s", wSync.Code, wSync.Body.String())
	}

	// 6. Refresh WinGet catalog when upstream publishes 27.01 -> version_state flips to "update_available"!
	releaseV27.Store(true)
	wg2 := winget.NewClient()
	wg2.SetEndpoints(srv.Client(), srv.URL+"/gh", srv.URL+"/raw", "")
	h.SetWinGetClient(wg2)

	wRefresh := httptest.NewRecorder()
	h.HandleRefreshWinGetApp(wRefresh, withDeviceAndKeyRoute("POST", "/api/apps/"+app.ID+"/winget-refresh", "", app.ID, "", "admin@lab.local"))
	if wRefresh.Code != http.StatusOK {
		t.Fatalf("winget refresh: want 200, got %d body=%s", wRefresh.Code, wRefresh.Body.String())
	}
	var refResp struct {
		Updated         bool   `json:"updated"`
		PreviousVersion string `json:"previous_version"`
		LatestVersion   string `json:"latest_version"`
		App             MSIApp `json:"app"`
	}
	if err := json.Unmarshal(wRefresh.Body.Bytes(), &refResp); err != nil {
		t.Fatal(err)
	}
	if !refResp.Updated || refResp.PreviousVersion != "26.06" || refResp.LatestVersion != "27.01" || refResp.App.OutdatedCount != 1 {
		t.Fatalf("unexpected winget refresh payload: %+v", refResp)
	}

	var auditCount int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'app.winget_refresh' AND user_email = 'admin@lab.local'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 app.winget_refresh audit row, got %d", auditCount)
	}
}
