package mdm

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestEncodeAndParseMSIProductURI(t *testing.T) {
	uri := EncodeMSIProductURI("b3db5e18-7fda-3432-9931-2e60d41bd242", "DownloadInstall")
	want := "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/%7BB3DB5E18-7FDA-3432-9931-2E60D41BD242%7D/DownloadInstall"
	if uri != want {
		t.Fatalf("EncodeMSIProductURI = %q, want %q", uri, want)
	}

	prod, leaf, ok := ParseMSIProductURI(uri)
	if !ok || prod != "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}" || leaf != "DownloadInstall" {
		t.Fatalf("ParseMSIProductURI(%q) = (%q, %q, %v)", uri, prod, leaf, ok)
	}

	// Also parse unencoded braces or ./Vendor/MSFT/... reported by Windows DMClient
	prod2, leaf2, ok2 := ParseMSIProductURI("./Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{b3db5e18-7fda-3432-9931-2e60d41bd242}/Status")
	if !ok2 || prod2 != "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}" || leaf2 != "Status" {
		t.Fatalf("ParseMSIProductURI unescaped = (%q, %q, %v)", prod2, leaf2, ok2)
	}
}

func TestMSIInstallSyncMLMarshalingPreservesRawXMLAndADMXEscaping(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-MSI-1")

	spec := MSIInstallSpec{
		ProductCode:          "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}",
		Version:              "157.0.8103.79",
		ContentURL:           "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi",
		SHA256:               "385A8817EC8513536E57E7177ACF226104E7F13910D83EA1BBFE39C3D9AC2D03",
		CommandLine:          "/quiet /norestart",
		TimeoutMinutes:       15,
		RetryCount:           3,
		RetryIntervalMinutes: 5,
	}

	queued, err := EnqueueMSIInstall(database.DB, devID, spec)
	if err != nil {
		t.Fatalf("EnqueueMSIInstall: %v", err)
	}
	if queued != 5 {
		t.Fatalf("expected 5 queued commands (Add + Exec + 3 Status Gets), got %d", queued)
	}

	// Also queue a standard ADMX policy Replace to verify <enabled/> remains escaped
	if _, err := EnqueueReplace(database.DB, devID, "./Device/Vendor/MSFT/Policy/Config/Browser/AllowIncognito", "<enabled/>"); err != nil {
		t.Fatalf("EnqueueReplace: %v", err)
	}

	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil {
		t.Fatalf("loadPendingCommands: %v", err)
	}
	if len(pending) != 6 {
		t.Fatalf("expected 6 pending commands, got %d", len(pending))
	}
	if pending[0].CommandType != "Add" || pending[1].CommandType != "Exec" {
		t.Fatalf("expected Add followed by Exec, got %s then %s", pending[0].CommandType, pending[1].CommandType)
	}

	sess := &Session{NextCmdID: 2, CmdMap: make(map[string]int)}
	cmds := buildSyncMLCommands(sess, pending)

	var sb strings.Builder
	for _, c := range cmds {
		b, err := xml.Marshal(c)
		if err != nil {
			t.Fatalf("xml.Marshal(%T): %v", c, err)
		}
		sb.Write(b)
	}
	out := sb.String()

	if !strings.Contains(out, `<Format xmlns="syncml:metinf">xml</Format>`) {
		t.Fatalf("missing xml MetInf format in SyncML output: %s", out)
	}
	if !strings.Contains(out, `<Data><MsiInstallJob id="{B3DB5E18-7FDA-3432-9931-2E60D41BD242}">`) {
		t.Fatalf("expected unescaped <MsiInstallJob> inside <Data>, got: %s", out)
	}
	if strings.Contains(out, `&lt;MsiInstallJob`) {
		t.Fatalf("<MsiInstallJob> was erroneously XML-escaped: %s", out)
	}
	if !strings.Contains(out, `<Data>&lt;enabled/&gt;</Data>`) {
		t.Fatalf("ADMX policy <enabled/> must remain XML-escaped, got: %s", out)
	}
}

func TestUpdateAppInstallsRecordsStatus70(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-MSI-STATUS")

	_, err := database.Exec(`
		INSERT INTO msi_apps (id, name, publisher, version, product_code, content_url, sha256)
		VALUES ('app-chrome', 'Google Chrome', 'Google LLC', '157.0.8103.79', '{B3DB5E18-7FDA-3432-9931-2E60D41BD242}', 'https://dl.google.com/chrome.msi', '385A8817EC8513536E57E7177ACF226104E7F13910D83EA1BBFE39C3D9AC2D03')
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
		INSERT INTO device_app_installs (device_id, app_id, product_code, desired_action, status_label)
		VALUES (?, 'app-chrome', '{B3DB5E18-7FDA-3432-9931-2E60D41BD242}', 'install', 'Queued')
	`, devID)
	if err != nil {
		t.Fatal(err)
	}

	updateAppInstalls(database.DB, devID, map[string]string{
		EncodeMSIProductURI("{B3DB5E18-7FDA-3432-9931-2E60D41BD242}", "Status"):    "70",
		EncodeMSIProductURI("{B3DB5E18-7FDA-3432-9931-2E60D41BD242}", "LastError"): "0",
	})

	var code int
	var label, lastErr string
	if err := database.QueryRow(`
		SELECT status_code, status_label, last_error
		FROM device_app_installs
		WHERE device_id = ? AND app_id = 'app-chrome'
	`, devID).Scan(&code, &label, &lastErr); err != nil {
		t.Fatal(err)
	}
	if code != 70 || label != "Installed" || lastErr != "" {
		t.Fatalf("got code=%d label=%q lastErr=%q, want 70/Installed/empty", code, label, lastErr)
	}
}
