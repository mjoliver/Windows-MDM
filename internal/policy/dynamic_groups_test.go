package policy

import (
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestValidateAndEvaluateDynamicGroupRules(t *testing.T) {
	mode, rules, err := ValidateDynamicGroupConfig("ALL", []DynamicGroupRule{
		{Field: "hostname", Operator: "starts_with", Value: "CORP-"},
		{Field: "os_version", Operator: "contains", Value: "10.0.226"},
		{Field: "secure_boot", Operator: "equals", Value: "enabled"},
		{Field: "bitlocker", Operator: "equals", Value: "true"},
	})
	if err != nil {
		t.Fatalf("ValidateDynamicGroupConfig error: %v", err)
	}
	if mode != "all" || len(rules) != 4 {
		t.Fatalf("unexpected mode=%q len=%d", mode, len(rules))
	}

	snapMatch := DeviceRuleSnapshot{
		DeviceID:   "d1",
		Hostname:   "corp-laptop-01",
		OSVersion:  "10.0.22631.4037",
		SecureBoot: "true",
		BitLocker:  "true",
	}
	if !EvaluateDynamicGroupRules(snapMatch, mode, rules) {
		t.Fatal("expected snapMatch to satisfy all rules")
	}

	snapNoSB := snapMatch
	snapNoSB.SecureBoot = "false"
	if EvaluateDynamicGroupRules(snapNoSB, "all", rules) {
		t.Fatal("expected snapNoSB to fail under match_mode=all")
	}
	if !EvaluateDynamicGroupRules(snapNoSB, "any", rules) {
		t.Fatal("expected snapNoSB to pass under match_mode=any")
	}

	if _, _, err := ValidateDynamicGroupConfig("all", nil); err == nil {
		t.Fatal("expected error for empty dynamic rules")
	}
	if _, _, err := ValidateDynamicGroupConfig("xor", rules); err == nil {
		t.Fatal("expected error for invalid match_mode")
	}
}

func TestReconcileDynamicGroupsAppliesAndRetractsPolicies(t *testing.T) {
	database := testutil.DB(t)

	devWin11 := testutil.SeedDevice(t, database, "HW-WIN11")
	devWin10 := testutil.SeedDevice(t, database, "HW-WIN10")

	_, err := database.Exec(`UPDATE devices SET device_name = 'ENG-WIN11', os_version = '10.0.26100.1', manufacturer = 'Microsoft Corporation' WHERE id = ?`, devWin11)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`UPDATE devices SET device_name = 'SALES-WIN10', os_version = '10.0.19045.1', manufacturer = 'Dell Inc.' WHERE id = ?`, devWin10)
	if err != nil {
		t.Fatal(err)
	}

	res, err := database.Exec(`
		INSERT INTO policy_catalog (oma_uri, display_name, category, csp_name, data_type, access_types)
		VALUES ('./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock', 'Idle Lock', 'DeviceLock', 'Policy', 'integer', '["Get","Replace"]')
	`)
	if err != nil {
		t.Fatal(err)
	}
	catID, _ := res.LastInsertId()
	_, _ = database.Exec(`INSERT INTO profiles (id, name) VALUES ('prof-dyn', 'Win11 Baseline')`)
	_, _ = database.Exec(`INSERT INTO profile_settings (profile_id, catalog_id, desired_value) VALUES ('prof-dyn', ?, '10')`, catID)

	_, err = database.Exec(`
		INSERT INTO device_groups (id, name, is_dynamic, match_mode, dynamic_rules_json)
		VALUES ('grp-win11', 'All Win11 Devices', 1, 'all', '[{"field":"os_version","operator":"starts_with","value":"10.0.26"}]')
	`)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = database.Exec(`INSERT INTO group_profiles (group_id, profile_id) VALUES ('grp-win11', 'prof-dyn')`)

	added, removed := ReconcileDynamicGroup(database.DB, "grp-win11")
	if added != 1 || removed != 0 {
		t.Fatalf("ReconcileDynamicGroup = (+%d, -%d), want (+1, -0)", added, removed)
	}

	var queuedWin11, queuedWin10 int
	_ = database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Replace'`, devWin11).Scan(&queuedWin11)
	_ = database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Replace'`, devWin10).Scan(&queuedWin10)
	if queuedWin11 != 1 || queuedWin10 != 0 {
		t.Fatalf("queued Replace counts: win11=%d (want 1), win10=%d (want 0)", queuedWin11, queuedWin10)
	}

	// Simulate devWin10 upgrading to Windows 11 24H2 on check-in -> ReconcileDynamicGroupsForDevice auto-joins and queues policy!
	_, _ = database.Exec(`UPDATE devices SET os_version = '10.0.26100.2033' WHERE id = ?`, devWin10)
	if changed := ReconcileDynamicGroupsForDevice(database.DB, devWin10); changed != 1 {
		t.Fatalf("ReconcileDynamicGroupsForDevice changed=%d, want 1", changed)
	}
	_ = database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND command_type = 'Replace'`, devWin10).Scan(&queuedWin10)
	if queuedWin10 != 1 {
		t.Fatalf("expected upgraded device to receive group policy Replace, got %d", queuedWin10)
	}
}
