package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/winget"
)

func TestWinGetSearchAndImport(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)

	mux := http.NewServeMux()
	mux.HandleFunc("/gh/7/7zip/7zip", func(w http.ResponseWriter, _ *http.Request) {
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
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wg := winget.NewClient()
	wg.SetEndpoints(srv.Client(), srv.URL+"/gh", srv.URL+"/raw", "")
	h.SetWinGetClient(wg)
	h.SetContentHTTPClient(&http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: 1998848, Body: http.NoBody}, nil
	})})

	wSearch := httptest.NewRecorder()
	h.HandleSearchWinGet(wSearch, httptest.NewRequest("GET", "/api/apps/winget/search?q=7zip", nil))
	if wSearch.Code != http.StatusOK {
		t.Fatalf("winget search: want 200, got %d", wSearch.Code)
	}

	wImport := httptest.NewRecorder()
	h.HandleImportWinGetApp(wImport, withDeviceAndKeyRoute("POST", "/api/apps/winget/import", `{"package_id":"7zip.7zip","architecture":"x64"}`, "", "", "admin@lab.local"))
	if wImport.Code != http.StatusCreated {
		t.Fatalf("winget import: want 201, got %d body=%s", wImport.Code, wImport.Body.String())
	}
	var app MSIApp
	if err := json.Unmarshal(wImport.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	if app.Name != "7-Zip" || app.Version != "26.06" || app.ProductCode != "{23170F69-40C1-2702-2606-000001000000}" || app.FileSizeBytes != 1998848 {
		t.Fatalf("unexpected imported MSIApp: %+v", app)
	}
}
