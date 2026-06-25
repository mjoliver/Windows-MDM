package policy

import (
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestApplyDevice_RetractsUngovernedSettings(t *testing.T) {
	database := testutil.DB(t)
	deviceID := testutil.SeedDevice(t, database, "HW-RETRACT")
	uri := "./Vendor/MSFT/Policy/Config/Foo"
	cat := testutil.SeedCatalogEntry(t, database, uri, "integer")
	prof := testutil.SeedProfileWithSetting(t, database, cat, "1")
	gid := testutil.AssignProfile(t, database, deviceID, prof)

	// Apply the profile, then simulate the device reporting compliance so there
	// is a governed compliance record for this setting.
	ApplyDevice(database.DB, deviceID)
	if _, err := database.Exec(
		`INSERT INTO compliance_records (device_id, catalog_id, desired_value, actual_value, is_compliant) VALUES (?, ?, '1', '1', 1)`,
		deviceID, cat,
	); err != nil {
		t.Fatal(err)
	}

	// Un-govern the setting by removing the profile from the group, then resync.
	if _, err := database.Exec(`DELETE FROM group_profiles WHERE group_id = ? AND profile_id = ?`, gid, prof); err != nil {
		t.Fatal(err)
	}
	ApplyDevice(database.DB, deviceID)

	// A retraction (Delete, since the catalog has no default) must be queued.
	var n int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Delete'`, deviceID,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected a Delete retraction command for the ungoverned setting")
	}

	// And the compliance record is cleared so we don't retract repeatedly.
	if err := database.QueryRow(`SELECT COUNT(*) FROM compliance_records WHERE device_id = ?`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected compliance records cleared on retraction, got %d", n)
	}
}
