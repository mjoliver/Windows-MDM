// Package policy implements the policy resolution and enforcement engine.
// It resolves which OMA-DM commands a device should receive based on
// its group memberships and the profiles assigned to those groups.
package policy

import (
	"database/sql"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

// resolvedSetting is a single policy value to enforce on a device.
type resolvedSetting struct {
	OMAURI       string
	DesiredValue string
	ProfileID    string
	CatalogID    int
}

// ApplyGroup re-applies all profiles in a group to all devices in that group.
// Called asynchronously when profiles are assigned to groups or devices are added.
func ApplyGroup(db *sql.DB, groupID string) {
	// Get all devices in the group
	rows, err := db.Query(
		dbpkg.Rebind(`SELECT device_id FROM device_group_members WHERE group_id = ?`), groupID,
	)
	if err != nil {
		slog.Error("policy: fetching group members", "group_id", groupID, "err", err)
		return
	}
	defer rows.Close()

	var deviceIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			deviceIDs = append(deviceIDs, id)
		}
	}

	for _, deviceID := range deviceIDs {
		ApplyDevice(db, deviceID)
	}
}

// ApplyProfile re-applies a specific profile to all devices in all groups that use it.
// Called asynchronously when a profile is updated.
func ApplyProfile(db *sql.DB, profileID string) {
	// Find all groups that use this profile
	rows, err := db.Query(
		dbpkg.Rebind(`SELECT group_id FROM group_profiles WHERE profile_id = ?`), profileID,
	)
	if err != nil {
		slog.Error("policy: fetching groups for profile", "profile_id", profileID, "err", err)
		return
	}
	defer rows.Close()

	var groupIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			groupIDs = append(groupIDs, id)
		}
	}

	for _, groupID := range groupIDs {
		ApplyGroup(db, groupID)
	}
}

// ApplyDevice resolves all applicable profiles for a device and queues
// Replace commands for any setting not yet compliant.
//
// Resolution order (highest priority wins):
//  1. Direct device assignments (future feature)
//  2. Group profile assignments (first group wins in case of conflict)
func ApplyDevice(db *sql.DB, deviceID string) {
	settings, err := resolveDevice(db, deviceID)
	if err != nil {
		slog.Error("policy: resolving device settings", "device_id", deviceID, "err", err)
		return
	}

	if len(settings) == 0 {
		return
	}

	// Load current compliance values to skip already-compliant settings
	compliant := loadCompliantSettings(db, deviceID)

	queued := 0
	for _, s := range settings {
		// Skip if already compliant (device is already at the desired value)
		if actualVal, ok := compliant[s.OMAURI]; ok && actualVal == s.DesiredValue {
			continue
		}

		// Queue a Replace command for this setting
		if _, err := mdm.EnqueueReplace(db, deviceID, s.OMAURI, s.DesiredValue); err != nil {
			slog.Error("policy: queuing Replace command",
				"device_id", deviceID,
				"oma_uri", s.OMAURI,
				"err", err,
			)
			continue
		}
		queued++
	}

	if queued > 0 {
		slog.Info("policy: applied settings to device",
			"device_id", deviceID,
			"commands_queued", queued,
			"total_settings", len(settings),
		)
	}
}

// resolveDevice computes the full set of desired settings for a device
// by walking its group memberships and assigned profiles.
// In conflicts, the first profile wins (group order, then profile order).
func resolveDevice(db *sql.DB, deviceID string) ([]resolvedSetting, error) {
	// One query: device → groups → profiles → settings → catalog URI
	rows, err := db.Query(dbpkg.Rebind(`
		SELECT
			pc.oma_uri,
			ps.desired_value,
			ps.profile_id,
			ps.catalog_id
		FROM device_group_members dgm
		JOIN group_profiles gp ON gp.group_id = dgm.group_id
		JOIN profile_settings ps ON ps.profile_id = gp.profile_id
		JOIN policy_catalog pc ON pc.id = ps.catalog_id
		WHERE dgm.device_id = ?
		  AND pc.is_deprecated = 0
		ORDER BY dgm.group_id, gp.profile_id, pc.oma_uri
	`), deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Deduplicate: first value for each OMA-URI wins
	seen := make(map[string]bool)
	var settings []resolvedSetting
	for rows.Next() {
		var s resolvedSetting
		if err := rows.Scan(&s.OMAURI, &s.DesiredValue, &s.ProfileID, &s.CatalogID); err != nil {
			continue
		}
		if seen[s.OMAURI] {
			continue // first profile wins
		}
		seen[s.OMAURI] = true
		settings = append(settings, s)
	}
	return settings, rows.Err()
}

// loadCompliantSettings returns a map of OMA-URI → actual value for settings
// where the device is currently compliant.
func loadCompliantSettings(db *sql.DB, deviceID string) map[string]string {
	rows, err := db.Query(dbpkg.Rebind(`
		SELECT pc.oma_uri, cr.actual_value
		FROM compliance_records cr
		JOIN policy_catalog pc ON pc.id = cr.catalog_id
		WHERE cr.device_id = ? AND cr.is_compliant = 1
	`), deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var uri, val string
		if err := rows.Scan(&uri, &val); err == nil {
			result[uri] = val
		}
	}
	return result
}
