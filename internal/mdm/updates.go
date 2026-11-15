package mdm

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/latchzmdm/latchz/internal/db"
)

const (
	OMAPolicyUpdateAllowAutoUpdate   = "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate"
	OMAPolicyUpdateDeferQualityDays  = "./Device/Vendor/MSFT/Policy/Config/Update/DeferQualityUpdatesPeriodInDays"
	OMAPolicyUpdateDeferFeatureDays  = "./Device/Vendor/MSFT/Policy/Config/Update/DeferFeatureUpdatesPeriodInDays"
	OMAPolicyUpdateActiveHoursStart  = "./Device/Vendor/MSFT/Policy/Config/Update/ActiveHoursStart"
	OMAPolicyUpdateActiveHoursEnd    = "./Device/Vendor/MSFT/Policy/Config/Update/ActiveHoursEnd"
	OMAPolicyUpdateQualityDeadline   = "./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForQualityUpdates"
	OMAPolicyUpdateFeatureDeadline   = "./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForFeatureUpdates"
	OMAPolicyUpdateDeadlineGrace     = "./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineGracePeriod"
	OMAPolicyUpdatePauseQualityStart = "./Device/Vendor/MSFT/Policy/Config/Update/PauseQualityUpdatesStartTime"
	OMAPolicyUpdatePauseFeatureStart = "./Device/Vendor/MSFT/Policy/Config/Update/PauseFeatureUpdatesStartTime"

	OMAUpdateLastSuccessfulScanTime = "./Device/Vendor/MSFT/Update/LastSuccessfulScanTime"
)

// UpdateRingSpec describes desired Windows Update for Business / Update CSP settings.
type UpdateRingSpec struct {
	AllowAutoUpdate     int
	QualityDeferralDays int
	FeatureDeferralDays int
	ActiveHoursStart    int
	ActiveHoursEnd      int
	QualityDeadlineDays int
	FeatureDeadlineDays int
	GracePeriodDays     int
	QualityPauseStart   string // "YYYY-MM-DD" or ""
	FeaturePauseStart   string // "YYYY-MM-DD" or ""
}

func cancelPendingUpdateOpposite(dbConn *sql.DB, deviceID, omaURI, cancelType string) {
	_, _ = dbConn.Exec(db.Rebind(`
		DELETE FROM command_queue
		WHERE device_id = ? AND oma_uri = ? AND command_type = ? AND status = 'pending'
	`), deviceID, omaURI, cancelType)
}

// EnqueueUpdateRing queues OMA-DM Replace/Delete + status Get commands to enforce
// a Windows Update Ring on a target device.
func EnqueueUpdateRing(dbConn *sql.DB, deviceID string, spec UpdateRingSpec, wasQualityPaused, wasFeaturePaused bool) (int, error) {
	replaces := []struct {
		uri string
		val string
	}{
		{OMAPolicyUpdateAllowAutoUpdate, strconv.Itoa(spec.AllowAutoUpdate)},
		{OMAPolicyUpdateDeferQualityDays, strconv.Itoa(spec.QualityDeferralDays)},
		{OMAPolicyUpdateDeferFeatureDays, strconv.Itoa(spec.FeatureDeferralDays)},
		{OMAPolicyUpdateActiveHoursStart, strconv.Itoa(spec.ActiveHoursStart)},
		{OMAPolicyUpdateActiveHoursEnd, strconv.Itoa(spec.ActiveHoursEnd)},
		{OMAPolicyUpdateQualityDeadline, strconv.Itoa(spec.QualityDeadlineDays)},
		{OMAPolicyUpdateFeatureDeadline, strconv.Itoa(spec.FeatureDeadlineDays)},
		{OMAPolicyUpdateDeadlineGrace, strconv.Itoa(spec.GracePeriodDays)},
	}

	var queued int
	for _, r := range replaces {
		cancelPendingUpdateOpposite(dbConn, deviceID, r.uri, "Delete")
		if _, err := EnqueueReplace(dbConn, deviceID, r.uri, r.val); err != nil {
			return queued, err
		}
		queued++
	}

	qPause := strings.TrimSpace(spec.QualityPauseStart)
	if qPause != "" {
		cancelPendingUpdateOpposite(dbConn, deviceID, OMAPolicyUpdatePauseQualityStart, "Delete")
		if _, err := EnqueueReplace(dbConn, deviceID, OMAPolicyUpdatePauseQualityStart, qPause); err != nil {
			return queued, err
		}
		queued++
	} else if wasQualityPaused {
		cancelPendingUpdateOpposite(dbConn, deviceID, OMAPolicyUpdatePauseQualityStart, "Replace")
		if _, err := EnqueueDelete(dbConn, deviceID, OMAPolicyUpdatePauseQualityStart); err != nil {
			return queued, err
		}
		queued++
	}

	fPause := strings.TrimSpace(spec.FeaturePauseStart)
	if fPause != "" {
		cancelPendingUpdateOpposite(dbConn, deviceID, OMAPolicyUpdatePauseFeatureStart, "Delete")
		if _, err := EnqueueReplace(dbConn, deviceID, OMAPolicyUpdatePauseFeatureStart, fPause); err != nil {
			return queued, err
		}
		queued++
	} else if wasFeaturePaused {
		cancelPendingUpdateOpposite(dbConn, deviceID, OMAPolicyUpdatePauseFeatureStart, "Replace")
		if _, err := EnqueueDelete(dbConn, deviceID, OMAPolicyUpdatePauseFeatureStart); err != nil {
			return queued, err
		}
		queued++
	}

	if _, err := EnqueueGet(dbConn, deviceID, OMAUpdateLastSuccessfulScanTime); err == nil {
		queued++
	}
	return queued, nil
}

// RetractUpdateRing removes all Latchz-managed Policy/Config/Update settings from
// a device that is no longer assigned to any Update Ring.
func RetractUpdateRing(dbConn *sql.DB, deviceID string) (int, error) {
	uris := []string{
		OMAPolicyUpdateAllowAutoUpdate,
		OMAPolicyUpdateDeferQualityDays,
		OMAPolicyUpdateDeferFeatureDays,
		OMAPolicyUpdateActiveHoursStart,
		OMAPolicyUpdateActiveHoursEnd,
		OMAPolicyUpdateQualityDeadline,
		OMAPolicyUpdateFeatureDeadline,
		OMAPolicyUpdateDeadlineGrace,
		OMAPolicyUpdatePauseQualityStart,
		OMAPolicyUpdatePauseFeatureStart,
	}
	var queued int
	for _, uri := range uris {
		cancelPendingUpdateOpposite(dbConn, deviceID, uri, "Replace")
		if _, err := EnqueueDelete(dbConn, deviceID, uri); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func updateWindowsUpdateTelemetry(dbConn *sql.DB, deviceID string, values map[string]string) {
	var scanTime string
	for rawURI, val := range values {
		if normalizePostureURI(rawURI) == OMAUpdateLastSuccessfulScanTime {
			scanTime = strings.TrimSpace(val)
		}
	}
	if scanTime == "" {
		return
	}
	_, _ = dbConn.Exec(db.Rebind(`
		INSERT INTO device_update_status (device_id, last_scan_time, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT (device_id) DO UPDATE SET
			last_scan_time = EXCLUDED.last_scan_time,
			updated_at = CURRENT_TIMESTAMP
	`), deviceID, scanTime)
}
