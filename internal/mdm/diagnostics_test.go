package mdm

import (
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestValidateCSPExplorerURIAndEditionLabels(t *testing.T) {
	u, err := ValidateCSPExplorerURI("Device/Vendor/MSFT/Reboot/RebootRequired")
	if err != nil || u != OMARebootRequired {
		t.Fatalf("ValidateCSPExplorerURI normalized = %q, err = %v", u, err)
	}

	for _, bad := range []string{
		"",
		"./Device/Vendor/MSFT/Accounts/Users/lzadm-1234/Password",
		"./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/ABC/PFXCertPassword",
		"./Vendor/MSFT/RemoteWipe/doWipe",
		"./Etc/Passwd",
		"./Device/Vendor/MSFT/../Secret",
		"./Device/Vendor/MSFT/Bad <xml>",
	} {
		if _, err := ValidateCSPExplorerURI(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}

	pro := int64(48)
	ent := int64(4)
	if got := WindowsEditionLabel(&pro); got != "Windows Pro" {
		t.Fatalf("WindowsEditionLabel(48) = %q, want Windows Pro", got)
	}
	if got := WindowsEditionLabel(&ent); got != "Windows Enterprise" {
		t.Fatalf("WindowsEditionLabel(4) = %q, want Windows Enterprise", got)
	}
	if b := ParseOptionalBoolInt("true"); !b.Valid || b.Int64 != 1 {
		t.Fatalf("ParseOptionalBoolInt(true) = %+v", b)
	}
	if b := ParseOptionalBoolInt("false"); !b.Valid || b.Int64 != 0 {
		t.Fatalf("ParseOptionalBoolInt(false) = %+v", b)
	}
}

func TestSyncCSPQueryLifecycleAndPostureRebootTelemetry(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-CSP-EXP")

	qID, err := EnqueueGet(database.DB, devID, OMARebootRequired)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB.Exec(`
		INSERT INTO device_csp_queries (id, device_id, queue_id, label, oma_uri, status, queried_by)
		VALUES ('cspq-1', ?, ?, 'Reboot Check', ?, 'pending', 'admin@lab.local')
	`, devID, qID, OMARebootRequired)
	if err != nil {
		t.Fatal(err)
	}

	sess := &Session{CmdMap: map[string]int{"5": int(qID)}}
	SyncCSPQueryStatus(database.DB, int(qID), StatusOK)
	updateDeviceFromResults(database.DB, devID, sess, []Results{
		{
			CmdRef: "5",
			Items: []Item{
				{Source: &LocURI{LocURI: OMARebootRequired}, Data: "false"},
				{Source: &LocURI{LocURI: OMAWindowsLicensingEdition}, Data: "48"},
				{Source: &LocURI{LocURI: OMADevDetailLocalTime}, Data: "2026-11-15T17:45:00-08:00"},
			},
		},
	})

	var st, code, data string
	if err := database.DB.QueryRow(`SELECT status, result_code, result_data FROM device_csp_queries WHERE id = 'cspq-1'`).Scan(&st, &code, &data); err != nil {
		t.Fatal(err)
	}
	if st != "success" || code != "200" || data == "" {
		t.Fatalf("unexpected csp query row: status=%q code=%q data=%q", st, code, data)
	}

	var reb, ed int
	var lt string
	if err := database.DB.QueryRow(`SELECT reboot_required, windows_edition, local_time FROM device_posture WHERE device_id = ?`, devID).Scan(&reb, &ed, &lt); err != nil {
		t.Fatal(err)
	}
	if reb != 0 || ed != 48 || lt != "2026-11-15T17:45:00-08:00" {
		t.Fatalf("unexpected posture telemetry: reboot=%d edition=%d local_time=%q", reb, ed, lt)
	}
}
