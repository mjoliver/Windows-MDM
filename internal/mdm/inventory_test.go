package mdm

import (
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestCompareAppVersionsAndCanonicalBaseName(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"26.06", "26.06.00.0", 0},
		{"v157.0.8103.79", "157.0.8103.79", 0},
		{"158.0.8200.10", "157.0.8103.79", 1},
		{"157.0.8103.79", "158.0.8200.10", -1},
		{"2.0", "10.0", -1},
	}
	for _, tc := range cases {
		if got := CompareAppVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareAppVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	if got := CanonicalAppBaseName("7-Zip 26.06 (x64)"); got != "7-zip" {
		t.Fatalf("CanonicalAppBaseName(7-Zip) = %q, want 7-zip", got)
	}
	if CanonicalAppBaseName("Microsoft Edge") == CanonicalAppBaseName("Microsoft Edge WebView2 Runtime") {
		t.Fatal("CanonicalAppBaseName must not conflate Microsoft Edge and WebView2 Runtime")
	}
	if !appNamesCompatible("Google Chrome Enterprise", "Google Chrome (64-bit)") {
		t.Fatal("expected Google Chrome Enterprise to match Google Chrome (64-bit)")
	}
}

func TestSoftwareInventoryStructDataAndSelfUpdateReconciliation(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-INV-1")

	// Seed Google Chrome v157 in catalog and mark deployed on devID under old ProductCode
	oldProd := "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}"
	newProd := "{C9AA9911-8888-4444-AAAA-999999999999}"
	upgCode := "{8A69D345-D564-463C-AFF1-A69D9E530F96}"

	_, err := database.DB.Exec(`
		INSERT INTO msi_apps (
			id, name, publisher, version, product_code, upgrade_code,
			content_url, sha256, file_size_bytes, command_line
		) VALUES (
			'app-chrome', 'Google Chrome Enterprise', 'Google LLC', '157.0.8103.79', ?, ?,
			'https://dl.google.com/chrome.msi', '385A8817EC8513536E57E7177ACF226104E7F13910D83EA1BBFE39C3D9AC2D03', 104857600, '/quiet /norestart'
		)
	`, oldProd, upgCode)
	if err != nil {
		t.Fatalf("insert msi_apps: %v", err)
	}

	_, err = database.DB.Exec(`
		INSERT INTO device_app_installs (
			device_id, app_id, product_code, installed_version, installed_product_code,
			desired_action, status_code, status_label
		) VALUES (?, 'app-chrome', ?, '157.0.8103.79', ?, 'install', 70, 'Installed')
	`, devID, oldProd, oldProd)
	if err != nil {
		t.Fatalf("insert device_app_installs: %v", err)
	}

	// Simulate OMA-DM Results containing:
	// 1. Auto-updated Chrome v158.0.8200.10 under a brand-new ProductCode via EnterpriseDesktopAppManagement MSI StructData
	// 2. Unmanaged Win32 app (Notepad++ 8.7.5) via Win32AppInventory StructData
	results := []Results{{
		CmdID:  "2",
		CmdRef: "10",
		Items: []Item{
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7BC9AA9911-8888-4444-AAAA-999999999999%7D/Name"},
				Data:   "Google Chrome",
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7BC9AA9911-8888-4444-AAAA-999999999999%7D/Publisher"},
				Data:   "Google LLC",
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7BC9AA9911-8888-4444-AAAA-999999999999%7D/ProductVersion"},
				Data:   "158.0.8200.10",
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7BC9AA9911-8888-4444-AAAA-999999999999%7D/UpgradeCode"},
				Data:   upgCode,
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/npp-x64/Name"},
				Data:   "Notepad++ (64-bit x64)",
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/npp-x64/Publisher"},
				Data:   "Notepad++ Team",
			},
			{
				Source: &LocURI{LocURI: "./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/npp-x64/Version"},
				Data:   "8.7.5",
			},
		},
	}}

	if !updateSoftwareInventory(database.DB, devID, results) {
		t.Fatal("expected updateSoftwareInventory to report inventory updates")
	}

	var invCount int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM device_software_inventory WHERE device_id = ?`, devID).Scan(&invCount); err != nil {
		t.Fatal(err)
	}
	if invCount != 2 {
		t.Fatalf("want 2 software inventory rows, got %d", invCount)
	}

	var liveVer, liveProd string
	if err := database.DB.QueryRow(`
		SELECT installed_version, installed_product_code
		FROM device_app_installs
		WHERE device_id = ? AND app_id = 'app-chrome'
	`, devID).Scan(&liveVer, &liveProd); err != nil {
		t.Fatal(err)
	}
	if liveVer != "158.0.8200.10" || liveProd != newProd {
		t.Fatalf("expected Chrome self-update reconciled to (158.0.8200.10, %s), got (%q, %q)", newProd, liveVer, liveProd)
	}
}
