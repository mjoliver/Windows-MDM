package policy

import (
	"database/sql"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultEndpointHardeningPolicyID = "default"

type loadedHardeningPolicy struct {
	enabled                    bool
	asrRules                   map[string]int
	activeASRCount             int
	enableSmartScreenShell     bool
	preventSmartScreenOverride bool
	appInstallControl          int
	submitSamplesConsent       int
	disableLocalAdminMerge     bool
	targetAll                  bool
}

func loadHardeningPolicy(db *sql.DB) (loadedHardeningPolicy, bool) {
	var p loadedHardeningPolicy
	var enabled, ssShell, ssPrevent, noMerge, targetAll int
	var asrJSON string
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT enabled, asr_rules_json,
		       enable_smartscreen_shell, prevent_smartscreen_override,
		       app_install_control, submit_samples_consent, disable_local_admin_merge,
		       target_all_devices
		FROM endpoint_hardening_policies
		WHERE id = ?
	`), defaultEndpointHardeningPolicyID).Scan(
		&enabled, &asrJSON,
		&ssShell, &ssPrevent,
		&p.appInstallControl, &p.submitSamplesConsent, &noMerge,
		&targetAll,
	)
	if err != nil {
		return p, false
	}
	p.enabled = enabled != 0
	p.asrRules = mdm.ParseASRRulesJSON(asrJSON)
	p.activeASRCount = len(p.asrRules)
	p.enableSmartScreenShell = ssShell != 0
	p.preventSmartScreenOverride = ssPrevent != 0
	p.disableLocalAdminMerge = noMerge != 0
	p.targetAll = targetAll != 0
	return p, true
}

func isDeviceHardeningGoverned(db *sql.DB, deviceID string, pol loadedHardeningPolicy) bool {
	if !pol.enabled {
		return false
	}
	if pol.targetAll {
		return true
	}
	var match int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT COUNT(*)
		FROM group_endpoint_hardening_policies ghp
		JOIN device_group_members dgm ON dgm.group_id = ghp.group_id
		WHERE ghp.policy_id = ? AND dgm.device_id = ?
	`), defaultEndpointHardeningPolicyID, deviceID).Scan(&match)
	return match > 0
}

// ReconcileEndpointHardeningDevice enforces or retracts Defender ASR & SmartScreen hardening on deviceID.
func ReconcileEndpointHardeningDevice(db *sql.DB, deviceID string) int {
	pol, exists := loadHardeningPolicy(db)
	governed := exists && isDeviceHardeningGoverned(db, deviceID, pol)

	var wasEnforced int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT enforced FROM device_endpoint_hardening_state WHERE device_id = ?
	`), deviceID).Scan(&wasEnforced)

	if governed {
		q, err := mdm.EnqueueEndpointHardening(db, deviceID, mdm.EndpointHardeningSpec{
			ASRRules:                   pol.asrRules,
			EnableSmartScreenShell:     pol.enableSmartScreenShell,
			PreventSmartScreenOverride: pol.preventSmartScreenOverride,
			AppInstallControl:          pol.appInstallControl,
			SubmitSamplesConsent:       pol.submitSamplesConsent,
			DisableLocalAdminMerge:     pol.disableLocalAdminMerge,
		})
		if err != nil {
			slog.Error("policy: queueing endpoint hardening CSPs", "device_id", deviceID, "err", err)
			return q
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_endpoint_hardening_state (device_id, enforced, active_asr_count, updated_at)
			VALUES (?, 1, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id) DO UPDATE SET
				enforced         = 1,
				active_asr_count = EXCLUDED.active_asr_count,
				updated_at       = CURRENT_TIMESTAMP
		`), deviceID, pol.activeASRCount)
		return q
	}

	if wasEnforced != 0 {
		q, err := mdm.RetractEndpointHardening(db, deviceID)
		if err != nil {
			slog.Error("policy: retracting endpoint hardening CSPs", "device_id", deviceID, "err", err)
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			UPDATE device_endpoint_hardening_state
			SET enforced = 0, active_asr_count = 0, updated_at = CURRENT_TIMESTAMP
			WHERE device_id = ?
		`), deviceID)
		return q
	}
	return 0
}

// ReconcileEndpointHardeningFleet reconciles Defender ASR & SmartScreen hardening across all active devices.
func ReconcileEndpointHardeningFleet(db *sql.DB) (enforcedDevices int, commandsQueued int) {
	rows, err := db.Query(`SELECT id FROM devices WHERE is_active = 1`)
	if err != nil {
		return 0, 0
	}
	var devIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			devIDs = append(devIDs, id)
		}
	}
	rows.Close()

	pol, exists := loadHardeningPolicy(db)
	for _, devID := range devIDs {
		q := ReconcileEndpointHardeningDevice(db, devID)
		if exists && isDeviceHardeningGoverned(db, devID, pol) {
			enforcedDevices++
		}
		if q > 0 {
			commandsQueued += q
			notifyWake(devID)
		}
	}
	return enforcedDevices, commandsQueued
}
