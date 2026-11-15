package policy

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

type resolvedUpdateRing struct {
	id   string
	spec mdm.UpdateRingSpec
}

// ResolveDeviceUpdateRing returns the highest-priority Update Ring governing
// deviceID (lowest priority integer wins; group-targeted rings precede fleet-wide
// fallback at equal priority).
func ResolveDeviceUpdateRing(db *sql.DB, deviceID string) (*resolvedUpdateRing, error) {
	var r resolvedUpdateRing
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT
			ur.id,
			ur.allow_auto_update,
			ur.quality_deferral_days,
			ur.feature_deferral_days,
			ur.active_hours_start,
			ur.active_hours_end,
			ur.quality_deadline_days,
			ur.feature_deadline_days,
			ur.grace_period_days,
			COALESCE(ur.quality_pause_start, ''),
			COALESCE(ur.feature_pause_start, '')
		FROM update_rings ur
		LEFT JOIN group_update_rings gur ON gur.ring_id = ur.id
		LEFT JOIN device_group_members dgm ON dgm.group_id = gur.group_id AND dgm.device_id = ?
		WHERE ur.target_all_devices = 1 OR dgm.device_id IS NOT NULL
		ORDER BY ur.priority ASC, CASE WHEN dgm.device_id IS NOT NULL THEN 0 ELSE 1 END ASC, ur.created_at ASC
		LIMIT 1
	`), deviceID).Scan(
		&r.id,
		&r.spec.AllowAutoUpdate,
		&r.spec.QualityDeferralDays,
		&r.spec.FeatureDeferralDays,
		&r.spec.ActiveHoursStart,
		&r.spec.ActiveHoursEnd,
		&r.spec.QualityDeadlineDays,
		&r.spec.FeatureDeadlineDays,
		&r.spec.GracePeriodDays,
		&r.spec.QualityPauseStart,
		&r.spec.FeaturePauseStart,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ReconcileUpdateRingDevice applies or retracts Policy/Config/Update CSP settings
// for a single device based on its effective Update Ring assignment.
func ReconcileUpdateRingDevice(db *sql.DB, deviceID string) int {
	ring, err := ResolveDeviceUpdateRing(db, deviceID)
	if err != nil {
		slog.Error("policy: resolving update ring for device", "device_id", deviceID, "err", err)
		return 0
	}

	var (
		prevRingID               sql.NullString
		prevQPaused, prevFPaused int
	)
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT ring_id, quality_paused, feature_paused
		FROM device_update_status
		WHERE device_id = ?
	`), deviceID).Scan(&prevRingID, &prevQPaused, &prevFPaused)

	if ring != nil {
		queued, err := mdm.EnqueueUpdateRing(db, deviceID, ring.spec, prevQPaused != 0, prevFPaused != 0)
		if err != nil {
			slog.Error("policy: queueing update ring commands", "device_id", deviceID, "ring_id", ring.id, "err", err)
			return queued
		}
		qPaused := 0
		if strings.TrimSpace(ring.spec.QualityPauseStart) != "" {
			qPaused = 1
		}
		fPaused := 0
		if strings.TrimSpace(ring.spec.FeaturePauseStart) != "" {
			fPaused = 1
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_update_status (device_id, ring_id, quality_paused, feature_paused, updated_at)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id) DO UPDATE SET
				ring_id = EXCLUDED.ring_id,
				quality_paused = EXCLUDED.quality_paused,
				feature_paused = EXCLUDED.feature_paused,
				updated_at = CURRENT_TIMESTAMP
		`), deviceID, ring.id, qPaused, fPaused)
		return queued
	}

	if prevRingID.Valid && prevRingID.String != "" {
		queued, err := mdm.RetractUpdateRing(db, deviceID)
		if err != nil {
			slog.Error("policy: retracting update ring commands", "device_id", deviceID, "err", err)
			return queued
		}
		_, _ = db.Exec(dbpkg.Rebind(`
			UPDATE device_update_status
			SET ring_id = NULL, quality_paused = 0, feature_paused = 0, updated_at = CURRENT_TIMESTAMP
			WHERE device_id = ?
		`), deviceID)
		return queued
	}
	return 0
}

// ReconcileUpdateRingsFleet reconciles Update Ring assignments across all active devices.
func ReconcileUpdateRingsFleet(db *sql.DB) (governedDevices int, totalCommands int) {
	rows, err := db.Query(dbpkg.Rebind(`SELECT id FROM devices WHERE is_active = 1`))
	if err != nil {
		slog.Error("policy: listing active devices for update ring reconcile", "err", err)
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
		q := ReconcileUpdateRingDevice(db, id)
		if q > 0 {
			totalCommands += q
			notifyWake(id)
		}
		if r, _ := ResolveDeviceUpdateRing(db, id); r != nil {
			governedDevices++
		}
	}
	return governedDevices, totalCommands
}
