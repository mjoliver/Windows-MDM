package mdm

import (
	"database/sql"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestEnqueue_DedupsPendingCommands(t *testing.T) {
	database := testutil.DB(t)
	deviceID := testutil.SeedDevice(t, database, "HW-DEDUP")

	id1, err := EnqueueReplace(database.DB, deviceID, "./Vendor/MSFT/Policy/Config/Foo", "1")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := EnqueueReplace(database.DB, deviceID, "./Vendor/MSFT/Policy/Config/Foo", "2")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("expected dedup to reuse pending command (%d != %d)", id1, id2)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ?`, deviceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 queued command after dedup, got %d", count)
	}
	var payload string
	if err := database.QueryRow(`SELECT payload FROM command_queue WHERE id = ?`, id1).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != "2" {
		t.Fatalf("expected payload updated to latest value, got %q", payload)
	}
}

func TestUpdateCompliance_UpsertWorksOnSQLite(t *testing.T) {
	// Regression for the missing UNIQUE(device_id, catalog_id) on SQLite: the
	// ON CONFLICT upsert in updateCompliance previously errored on the default
	// driver, so compliance was never recorded.
	database := testutil.DB(t)
	deviceID := testutil.SeedDevice(t, database, "HW-COMPLIANCE")
	uri := "./Device/Vendor/MSFT/Policy/Config/Foo"
	cat := testutil.SeedCatalogEntry(t, database, uri, "integer")
	prof := testutil.SeedProfileWithSetting(t, database, cat, "1")
	testutil.AssignProfile(t, database, deviceID, prof)

	updateCompliance(database.DB, deviceID, map[string]string{uri: "1"})

	var isCompliant sql.NullInt64
	if err := database.QueryRow(
		`SELECT is_compliant FROM compliance_records WHERE device_id = ? AND catalog_id = ?`,
		deviceID, cat,
	).Scan(&isCompliant); err != nil {
		t.Fatalf("compliance upsert did not record a row: %v", err)
	}
	if !isCompliant.Valid || isCompliant.Int64 != 1 {
		t.Fatalf("expected compliant=1 (desired==actual), got %+v", isCompliant)
	}

	// And a non-matching value flips it to non-compliant via the upsert path.
	updateCompliance(database.DB, deviceID, map[string]string{uri: "999"})
	if err := database.QueryRow(
		`SELECT is_compliant FROM compliance_records WHERE device_id = ? AND catalog_id = ?`,
		deviceID, cat,
	).Scan(&isCompliant); err != nil {
		t.Fatal(err)
	}
	if !isCompliant.Valid || isCompliant.Int64 != 0 {
		t.Fatalf("expected compliant=0 after mismatch, got %+v", isCompliant)
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	database := testutil.DB(t)
	// command_queue.device_id REFERENCES devices(id); inserting for a missing
	// device must fail now that foreign_keys is ON.
	_, err := database.Exec(`INSERT INTO command_queue (device_id, command_type, oma_uri) VALUES ('does-not-exist', 'Get', './x')`)
	if err == nil {
		t.Fatal("expected a foreign-key violation for an unknown device_id")
	}
}

func TestUpdateDeviceFromResults_PopulatesSerialAndPosture(t *testing.T) {
	database := testutil.DB(t)
	deviceID := testutil.SeedDevice(t, database, "HW-INV")
	sess := &Session{DeviceID: deviceID, SessionID: "1", CmdMap: make(map[string]int)}

	results := []Results{{
		CmdRef: "2",
		Items: []Item{
			{Source: &LocURI{LocURI: OMADevDetailSMBIOSSerial}, Data: "SN-998877"},
			{Source: &LocURI{LocURI: OMADevDetailTotalRAM}, Data: "32768"},
			{Source: &LocURI{LocURI: OMADevDetailTotalStorage}, Data: "1024000"},
			{Source: &LocURI{LocURI: OMADevDetailFreeStorage}, Data: "750000"},
			{Source: &LocURI{LocURI: OMADeviceStatusSecureBoot}, Data: "1"},
			{Source: &LocURI{LocURI: OMABitLockerEncryptionStatus}, Data: "0"},
			{Source: &LocURI{LocURI: OMADeviceStatusAntivirus}, Data: "0"},
			{Source: &LocURI{LocURI: OMADeviceStatusFirewall}, Data: "0"},
			{Source: &LocURI{LocURI: OMADeviceStatusTPMVersion}, Data: "2.0"},
		},
	}}

	updateDeviceFromResults(database.DB, deviceID, sess, results)

	var serial string
	if err := database.QueryRow(`SELECT COALESCE(serial_number,'') FROM devices WHERE id = ?`, deviceID).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	if serial != "SN-998877" {
		t.Fatalf("serial_number = %q, want SN-998877", serial)
	}

	var ram, secBoot, bitlocker int64
	var tpm string
	if err := database.QueryRow(`
		SELECT total_ram_mb, secure_boot_state, encryption_status, tpm_version
		FROM device_posture WHERE device_id = ?
	`, deviceID).Scan(&ram, &secBoot, &bitlocker, &tpm); err != nil {
		t.Fatalf("device_posture row not created: %v", err)
	}
	if ram != 32768 || secBoot != 1 || bitlocker != 0 || tpm != "2.0" {
		t.Fatalf("unexpected posture row: ram=%d secBoot=%d bitlocker=%d tpm=%q", ram, secBoot, bitlocker, tpm)
	}
}
