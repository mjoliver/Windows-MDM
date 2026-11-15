package policy

import (
	"database/sql"
	"errors"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultLockdownPolicyID = "default"

type storedLockdownPolicy struct {
	enabled          bool
	targetAllDevices bool
	spec             mdm.DeviceLockdownSpec
}

func loadStoredLockdownPolicy(db *sql.DB) (*storedLockdownPolicy, error) {
	var (
		enabled, reqPwd, alphaReq, allowCam, allowBT, targetAll int
		sp                                                      mdm.DeviceLockdownSpec
	)
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT enabled, usb_storage_mode,
		       require_password, min_password_length, alphanumeric_required,
		       max_inactivity_minutes, max_failed_attempts,
		       allow_camera, allow_bluetooth,
		       kiosk_mode, kiosk_account, kiosk_app_aumid,
		       target_all_devices
		FROM device_lockdown_policies
		WHERE id = ?
	`), defaultLockdownPolicyID).Scan(
		&enabled, &sp.USBStorageMode,
		&reqPwd, &sp.MinPasswordLength, &alphaReq,
		&sp.MaxInactivityMinutes, &sp.MaxFailedAttempts,
		&allowCam, &allowBT,
		&sp.KioskMode, &sp.KioskAccount, &sp.KioskAppAUMID,
		&targetAll,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sp.RequirePassword = reqPwd != 0
	sp.AlphanumericRequired = alphaReq != 0
	sp.AllowCamera = allowCam != 0
	sp.AllowBluetooth = allowBT != 0
	return &storedLockdownPolicy{
		enabled:          enabled != 0,
		targetAllDevices: targetAll != 0,
		spec:             sp,
	}, nil
}

func deviceGovernedByLockdown(db *sql.DB, deviceID string, pol *storedLockdownPolicy) bool {
	if pol == nil || !pol.enabled {
		return false
	}
	if pol.targetAllDevices {
		return true
	}
	var matched int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT COUNT(*)
		FROM device_group_members dgm
		JOIN group_device_lockdown_policies gdl ON gdl.group_id = dgm.group_id
		WHERE dgm.device_id = ? AND gdl.policy_id = ?
	`), deviceID, defaultLockdownPolicyID).Scan(&matched)
	return err == nil && matched > 0
}

// ReconcileLockdownDevice applies or retracts USB storage, DeviceLock, hardware
// privacy, and AssignedAccess kiosk CSPs for a single device.
func ReconcileLockdownDevice(db *sql.DB, deviceID string) int {
	pol, err := loadStoredLockdownPolicy(db)
	if err != nil {
		return 0
	}

	var prevEnforced, prevKiosk int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT enforced, kiosk_enforced FROM device_lockdown_state WHERE device_id = ?
	`), deviceID).Scan(&prevEnforced, &prevKiosk)

	if deviceGovernedByLockdown(db, deviceID, pol) {
		q, kioskNow, qerr := mdm.EnqueueDeviceLockdown(db, deviceID, pol.spec, prevKiosk != 0)
		if qerr != nil {
			slog.Error("policy: queueing device lockdown", "device_id", deviceID, "err", qerr)
			return q
		}
		kInt := 0
		if kioskNow {
			kInt = 1
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_lockdown_state (device_id, enforced, kiosk_enforced, updated_at)
			VALUES (?, 1, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id) DO UPDATE SET
				enforced       = 1,
				kiosk_enforced = EXCLUDED.kiosk_enforced,
				updated_at     = CURRENT_TIMESTAMP
		`), deviceID, kInt)
		return q
	}

	if prevEnforced != 0 {
		q, qerr := mdm.RetractDeviceLockdown(db, deviceID, prevKiosk != 0)
		if qerr != nil {
			slog.Error("policy: retracting device lockdown", "device_id", deviceID, "err", qerr)
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			UPDATE device_lockdown_state
			SET enforced = 0, kiosk_enforced = 0, updated_at = CURRENT_TIMESTAMP
			WHERE device_id = ?
		`), deviceID)
		return q
	}
	return 0
}

// ReconcileLockdownFleet reconciles Device Lockdown policies across all active devices.
func ReconcileLockdownFleet(db *sql.DB) (enforcedDevices int, commandsQueued int) {
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

	pol, _ := loadStoredLockdownPolicy(db)
	for _, devID := range devIDs {
		if deviceGovernedByLockdown(db, devID, pol) {
			enforcedDevices++
		}
		q := ReconcileLockdownDevice(db, devID)
		if q > 0 {
			commandsQueued += q
			notifyWake(devID)
		}
	}
	return enforcedDevices, commandsQueued
}
