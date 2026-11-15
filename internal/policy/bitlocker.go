package policy

import (
	"database/sql"
	"errors"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultBitLockerPolicyID = "default"

type storedBitLockerPolicy struct {
	enabled           bool
	requireEncryption bool
	silentEncryption  bool
	allowStandardUser bool
	osCipher          int
	fixedCipher       int
	removableCipher   int
	targetAllDevices  bool
}

func loadStoredBitLockerPolicy(db *sql.DB) (*storedBitLockerPolicy, error) {
	var (
		enabled, reqEnc, silent, stdUser, targetAll int
		osC, fixedC, remC                           int
	)
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT enabled, require_device_encryption, silent_encryption, allow_standard_user,
		       os_drive_cipher, fixed_drive_cipher, removable_drive_cipher, target_all_devices
		FROM bitlocker_policies
		WHERE id = ?
	`), defaultBitLockerPolicyID).Scan(
		&enabled, &reqEnc, &silent, &stdUser,
		&osC, &fixedC, &remC, &targetAll,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &storedBitLockerPolicy{
		enabled:           enabled != 0,
		requireEncryption: reqEnc != 0,
		silentEncryption:  silent != 0,
		allowStandardUser: stdUser != 0,
		osCipher:          osC,
		fixedCipher:       fixedC,
		removableCipher:   remC,
		targetAllDevices:  targetAll != 0,
	}, nil
}

func deviceGovernedByBitLocker(db *sql.DB, deviceID string, pol *storedBitLockerPolicy) bool {
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
		JOIN group_bitlocker_policies gbp ON gbp.group_id = dgm.group_id
		WHERE dgm.device_id = ? AND gbp.policy_id = ?
	`), deviceID, defaultBitLockerPolicyID).Scan(&matched)
	return err == nil && matched > 0
}

// ReconcileBitLockerDevice applies or retracts BitLocker CSP settings for a single device.
func ReconcileBitLockerDevice(db *sql.DB, deviceID string) int {
	pol, err := loadStoredBitLockerPolicy(db)
	if err != nil {
		return 0
	}

	var prevEnforced int
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT enforced FROM device_bitlocker_state WHERE device_id = ?
	`), deviceID).Scan(&prevEnforced)

	if deviceGovernedByBitLocker(db, deviceID, pol) {
		queued, err := mdm.EnqueueBitLockerPolicy(db, deviceID, mdm.BitLockerPolicySpec{
			RequireDeviceEncryption: pol.requireEncryption,
			SilentEncryption:        pol.silentEncryption,
			AllowStandardUser:       pol.allowStandardUser,
			OSDriveCipher:           pol.osCipher,
			FixedDriveCipher:        pol.fixedCipher,
			RemovableDriveCipher:    pol.removableCipher,
		})
		if err != nil {
			slog.Error("policy: queueing bitlocker policy", "device_id", deviceID, "err", err)
			return queued
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_bitlocker_state (device_id, enforced, updated_at)
			VALUES (?, 1, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id) DO UPDATE SET enforced = 1, updated_at = CURRENT_TIMESTAMP
		`), deviceID)
		return queued
	}

	if prevEnforced != 0 {
		queued, err := mdm.RetractBitLockerPolicy(db, deviceID)
		if err != nil {
			slog.Error("policy: retracting bitlocker policy", "device_id", deviceID, "err", err)
			return queued
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			UPDATE device_bitlocker_state SET enforced = 0, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?
		`), deviceID)
		return queued
	}
	return 0
}

// ReconcileBitLockerFleet reconciles BitLocker CSP state across all active devices
// and notifies WNS for any device with newly queued enforcement/retraction commands.
func ReconcileBitLockerFleet(db *sql.DB) (enforcedDevices int, totalCommands int) {
	rows, err := db.Query(dbpkg.Rebind(`SELECT id FROM devices WHERE is_active = 1`))
	if err != nil {
		slog.Error("policy: listing active devices for bitlocker reconcile", "err", err)
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

	pol, _ := loadStoredBitLockerPolicy(db)
	for _, id := range ids {
		q := ReconcileBitLockerDevice(db, id)
		if q > 0 {
			totalCommands += q
			notifyWake(id)
		}
		if deviceGovernedByBitLocker(db, id, pol) {
			enforcedDevices++
		}
	}
	return enforcedDevices, totalCommands
}
