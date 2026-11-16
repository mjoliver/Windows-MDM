package policy

import (
	"database/sql"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultExperiencePolicyID = "default"

type loadedExperiencePolicy struct {
	enabled   bool
	targetAll bool
	spec      mdm.DesktopExperienceSpec
}

func loadDesktopExperiencePolicy(db *sql.DB) (loadedExperiencePolicy, bool) {
	var p loadedExperiencePolicy
	var enabled, disAdv, blockTailored, disWidgets int
	var edgeSS, edgeNoOver, edgePUA, edgeNoPwd, edgeTypo, targetAll int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT
			enabled, telemetry_level, disable_advertising_id, block_tailored_experiences, disable_widgets_news,
			edge_smartscreen_enabled, edge_prevent_ss_override, edge_smartscreen_pua,
			edge_block_password_manager, edge_typosquatting_checker,
			desktop_wallpaper_url, lockscreen_image_url, target_all_devices
		FROM desktop_experience_policies
		WHERE id = ?
	`), defaultExperiencePolicyID).Scan(
		&enabled, &p.spec.TelemetryLevel, &disAdv, &blockTailored, &disWidgets,
		&edgeSS, &edgeNoOver, &edgePUA,
		&edgeNoPwd, &edgeTypo,
		&p.spec.DesktopWallpaperURL, &p.spec.LockScreenImageURL, &targetAll,
	)
	if err != nil {
		return p, false
	}
	p.enabled = enabled != 0
	p.targetAll = targetAll != 0
	p.spec.DisableAdvertisingID = disAdv != 0
	p.spec.BlockTailoredExperiences = blockTailored != 0
	p.spec.DisableWidgetsNews = disWidgets != 0
	p.spec.EdgeSmartScreenEnabled = edgeSS != 0
	p.spec.EdgePreventSSOverride = edgeNoOver != 0
	p.spec.EdgeSmartScreenPUA = edgePUA != 0
	p.spec.EdgeBlockPasswordManager = edgeNoPwd != 0
	p.spec.EdgeTyposquattingChecker = edgeTypo != 0
	return p, true
}

func isDeviceExperienceGoverned(db *sql.DB, deviceID string, pol loadedExperiencePolicy) bool {
	if !pol.enabled {
		return false
	}
	if pol.targetAll {
		return true
	}
	var match int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT COUNT(*)
		FROM group_desktop_experience_policies gep
		JOIN device_group_members dgm ON dgm.group_id = gep.group_id
		WHERE gep.policy_id = ? AND dgm.device_id = ?
	`), defaultExperiencePolicyID, deviceID).Scan(&match)
	return match > 0
}

// ReconcileDesktopExperienceDevice enforces or retracts Windows 11 Privacy/Debloat,
// Microsoft Edge Security Baseline, and optional Corporate Branding CSPs on deviceID.
func ReconcileDesktopExperienceDevice(db *sql.DB, deviceID string) int {
	pol, exists := loadDesktopExperiencePolicy(db)
	governed := exists && isDeviceExperienceGoverned(db, deviceID, pol)

	var wasEnforced, prevBranding int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT enforced, branding_enforced FROM device_desktop_experience_state WHERE device_id = ?
	`), deviceID).Scan(&wasEnforced, &prevBranding)

	if governed {
		q, brandingNow, err := mdm.EnqueueDesktopExperience(db, deviceID, pol.spec, prevBranding != 0)
		if err != nil {
			slog.Error("policy: queueing desktop experience CSPs", "device_id", deviceID, "err", err)
			return q
		}
		brandInt := 0
		if brandingNow {
			brandInt = 1
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_desktop_experience_state (device_id, enforced, branding_enforced, updated_at)
			VALUES (?, 1, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id) DO UPDATE SET
				enforced          = 1,
				branding_enforced = EXCLUDED.branding_enforced,
				updated_at        = CURRENT_TIMESTAMP
		`), deviceID, brandInt)
		return q
	}

	if wasEnforced != 0 {
		q, err := mdm.RetractDesktopExperience(db, deviceID, prevBranding != 0)
		if err != nil {
			slog.Error("policy: retracting desktop experience CSPs", "device_id", deviceID, "err", err)
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			UPDATE device_desktop_experience_state
			SET enforced = 0, branding_enforced = 0, updated_at = CURRENT_TIMESTAMP
			WHERE device_id = ?
		`), deviceID)
		return q
	}
	return 0
}

// ReconcileDesktopExperienceFleet reconciles Windows Privacy/Debloat & Edge Baseline across all active devices.
func ReconcileDesktopExperienceFleet(db *sql.DB) (devicesAffected int, commandsQueued int) {
	rows, err := db.Query(`SELECT id FROM devices WHERE is_active = 1`)
	if err != nil {
		return 0, 0
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	for _, id := range ids {
		q := ReconcileDesktopExperienceDevice(db, id)
		if q > 0 {
			devicesAffected++
			commandsQueued += q
			notifyWake(id)
		}
	}
	return devicesAffected, commandsQueued
}
