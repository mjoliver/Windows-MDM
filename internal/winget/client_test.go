package winget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSearchAndResolveWinGetMSI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/7/7zip/7zip", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"9.20","type":"dir"},{"name":"26.06","type":"dir"}]`))
	})
	mux.HandleFunc("/raw/7/7zip/7zip/26.06/7zip.7zip.installer.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
PackageIdentifier: 7zip.7zip
PackageVersion: "26.06"
Installers:
- Architecture: x64
  InstallerType: exe
  InstallerUrl: https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.exe
  InstallerSha256: 9B697F65ECC2D9B0152F5EE96D72DDE522A7827690349D9307935DACF40F42EC
  ProductCode: 7-Zip
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
		_, _ = w.Write([]byte("PackageName: 7-Zip\nPublisher: Igor Pavlov\nShortDescription: File archiver\n"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.SetEndpoints(srv.Client(), srv.URL+"/gh", srv.URL+"/raw", "")

	results, err := c.Search(context.Background(), "7zip")
	if err != nil || len(results) == 0 || results[0].PackageID != "7zip.7zip" {
		t.Fatalf("Search(7zip) failed: %v, results=%+v", err, results)
	}

	resolved, err := c.ResolveMSI(context.Background(), "7zip.7zip", "x64")
	if err != nil {
		t.Fatalf("ResolveMSI failed: %v", err)
	}
	if resolved.Version != "26.06" || !strings.HasSuffix(resolved.InstallerURL, "7z2606-x64.msi") || resolved.ProductCode != "{23170F69-40C1-2702-2606-000001000000}" {
		t.Fatalf("unexpected ResolvedMSI: %+v", resolved)
	}

	if err := ValidatePackageID("../evil"); err == nil {
		t.Fatal("expected traversal package_id to be rejected")
	}
}
