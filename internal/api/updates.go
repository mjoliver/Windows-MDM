package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/policy"
)

// UpdateRing represents a Windows Update for Business deployment ring.
type UpdateRing struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	AllowAutoUpdate     int       `json:"allow_auto_update"`
	QualityDeferralDays int       `json:"quality_deferral_days"`
	FeatureDeferralDays int       `json:"feature_deferral_days"`
	ActiveHoursStart    int       `json:"active_hours_start"`
	ActiveHoursEnd      int       `json:"active_hours_end"`
	QualityDeadlineDays int       `json:"quality_deadline_days"`
	FeatureDeadlineDays int       `json:"feature_deadline_days"`
	GracePeriodDays     int       `json:"grace_period_days"`
	QualityPauseStart   string    `json:"quality_pause_start"`
	FeaturePauseStart   string    `json:"feature_pause_start"`
	QualityPaused       bool      `json:"quality_paused"`
	FeaturePaused       bool      `json:"feature_paused"`
	TargetAllDevices    bool      `json:"target_all_devices"`
	Priority            int       `json:"priority"`
	GroupIDs            []string  `json:"group_ids"`
	DeviceCount         int       `json:"device_count"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	GovernedDevices     int       `json:"governed_devices,omitempty"`
	CommandsQueued      int       `json:"commands_queued,omitempty"`
}

// DeviceUpdateTelemetry exposes the effective Update Ring and scan telemetry for a single device.
type DeviceUpdateTelemetry struct {
	DeviceID            string     `json:"device_id"`
	RingID              string     `json:"ring_id"`
	RingName            string     `json:"ring_name"`
	QualityDeferralDays *int       `json:"quality_deferral_days"`
	FeatureDeferralDays *int       `json:"feature_deferral_days"`
	ActiveHoursStart    *int       `json:"active_hours_start"`
	ActiveHoursEnd      *int       `json:"active_hours_end"`
	QualityPaused       bool       `json:"quality_paused"`
	FeaturePaused       bool       `json:"feature_paused"`
	LastScanTime        string     `json:"last_scan_time"`
	UpdatedAt           *time.Time `json:"updated_at"`
}

type updateRingInput struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	AllowAutoUpdate     *int     `json:"allow_auto_update"`
	QualityDeferralDays *int     `json:"quality_deferral_days"`
	FeatureDeferralDays *int     `json:"feature_deferral_days"`
	ActiveHoursStart    *int     `json:"active_hours_start"`
	ActiveHoursEnd      *int     `json:"active_hours_end"`
	QualityDeadlineDays *int     `json:"quality_deadline_days"`
	FeatureDeadlineDays *int     `json:"feature_deadline_days"`
	GracePeriodDays     *int     `json:"grace_period_days"`
	TargetAllDevices    bool     `json:"target_all_devices"`
	Priority            *int     `json:"priority"`
	GroupIDs            []string `json:"group_ids"`
}

func validateUpdateRingInput(in *updateRingInput) (UpdateRing, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return UpdateRing{}, errors.New("ring name is required")
	}
	intOrDefault := func(p *int, def int) int {
		if p == nil {
			return def
		}
		return *p
	}
	autoUpd := intOrDefault(in.AllowAutoUpdate, 2)
	if autoUpd < 2 || autoUpd > 5 {
		return UpdateRing{}, errors.New("allow_auto_update must be between 2 and 5")
	}
	qDef := intOrDefault(in.QualityDeferralDays, 7)
	if qDef < 0 || qDef > 30 {
		return UpdateRing{}, errors.New("quality_deferral_days must be between 0 and 30")
	}
	fDef := intOrDefault(in.FeatureDeferralDays, 30)
	if fDef < 0 || fDef > 365 {
		return UpdateRing{}, errors.New("feature_deferral_days must be between 0 and 365")
	}
	ahStart := intOrDefault(in.ActiveHoursStart, 8)
	ahEnd := intOrDefault(in.ActiveHoursEnd, 17)
	if ahStart < 0 || ahStart > 23 || ahEnd < 0 || ahEnd > 23 || ahStart == ahEnd {
		return UpdateRing{}, errors.New("active_hours_start and active_hours_end must be distinct hours in 0..23")
	}
	span := (ahEnd - ahStart + 24) % 24
	if span > 18 {
		return UpdateRing{}, errors.New("active hours span cannot exceed 18 hours per Windows Update CSP")
	}
	qDead := intOrDefault(in.QualityDeadlineDays, 7)
	fDead := intOrDefault(in.FeatureDeadlineDays, 14)
	if qDead < 0 || qDead > 30 || fDead < 0 || fDead > 30 {
		return UpdateRing{}, errors.New("deadline days must be between 0 and 30")
	}
	grace := intOrDefault(in.GracePeriodDays, 2)
	if grace < 0 || grace > 7 {
		return UpdateRing{}, errors.New("grace_period_days must be between 0 and 7")
	}
	prio := intOrDefault(in.Priority, 100)
	if prio < 1 || prio > 10000 {
		return UpdateRing{}, errors.New("priority must be between 1 and 10000")
	}

	return UpdateRing{
		Name:                name,
		Description:         strings.TrimSpace(in.Description),
		AllowAutoUpdate:     autoUpd,
		QualityDeferralDays: qDef,
		FeatureDeferralDays: fDef,
		ActiveHoursStart:    ahStart,
		ActiveHoursEnd:      ahEnd,
		QualityDeadlineDays: qDead,
		FeatureDeadlineDays: fDead,
		GracePeriodDays:     grace,
		TargetAllDevices:    in.TargetAllDevices,
		Priority:            prio,
		GroupIDs:            in.GroupIDs,
	}, nil
}

func (h *Handler) loadUpdateRing(r *http.Request, id string) (UpdateRing, error) {
	var (
		ring      UpdateRing
		targetAll int
	)
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			id, name, COALESCE(description, ''),
			allow_auto_update, quality_deferral_days, feature_deferral_days,
			active_hours_start, active_hours_end,
			quality_deadline_days, feature_deadline_days, grace_period_days,
			COALESCE(quality_pause_start, ''), COALESCE(feature_pause_start, ''),
			target_all_devices, priority, created_at, updated_at
		FROM update_rings
		WHERE id = ?
	`), id).Scan(
		&ring.ID, &ring.Name, &ring.Description,
		&ring.AllowAutoUpdate, &ring.QualityDeferralDays, &ring.FeatureDeferralDays,
		&ring.ActiveHoursStart, &ring.ActiveHoursEnd,
		&ring.QualityDeadlineDays, &ring.FeatureDeadlineDays, &ring.GracePeriodDays,
		&ring.QualityPauseStart, &ring.FeaturePauseStart,
		&targetAll, &ring.Priority, &ring.CreatedAt, &ring.UpdatedAt,
	)
	if err != nil {
		return ring, err
	}
	ring.TargetAllDevices = targetAll != 0
	ring.QualityPaused = strings.TrimSpace(ring.QualityPauseStart) != ""
	ring.FeaturePaused = strings.TrimSpace(ring.FeaturePauseStart) != ""
	ring.GroupIDs = []string{}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_update_rings WHERE ring_id = ? ORDER BY group_id
	`), id)
	if err == nil {
		for gRows.Next() {
			var gid string
			if gRows.Scan(&gid) == nil {
				ring.GroupIDs = append(ring.GroupIDs, gid)
			}
		}
		gRows.Close()
	}

	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COUNT(*) FROM device_update_status WHERE ring_id = ?
	`), id).Scan(&ring.DeviceCount)

	return ring, nil
}

// HandleListUpdateRings lists all configured Windows Update Rings ordered by priority.
// GET /api/updates/rings
func (h *Handler) HandleListUpdateRings(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id FROM update_rings ORDER BY priority ASC, created_at ASC
	`))
	if err != nil {
		slog.Error("api: listing update rings", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list update rings")
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	rings := make([]UpdateRing, 0, len(ids))
	for _, id := range ids {
		if ring, err := h.loadUpdateRing(r, id); err == nil {
			rings = append(rings, ring)
		}
	}
	respondOK(w, rings)
}

// HandleGetUpdateRing returns a single Update Ring.
// GET /api/updates/rings/{id}
func (h *Handler) HandleGetUpdateRing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ring, err := h.loadUpdateRing(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "update ring not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load update ring")
		return
	}
	respondOK(w, ring)
}

// HandleCreateUpdateRing creates a new Windows Update Ring and reconciles fleet enforcement.
// POST /api/updates/rings
func (h *Handler) HandleCreateUpdateRing(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var in updateRingInput
	if !decodeBody(w, r, &in) {
		return
	}
	validated, err := validateUpdateRingInput(&in)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	id := uuid.New().String()
	targetAll := 0
	if validated.TargetAllDevices {
		targetAll = 1
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO update_rings (
			id, name, description, allow_auto_update,
			quality_deferral_days, feature_deferral_days,
			active_hours_start, active_hours_end,
			quality_deadline_days, feature_deadline_days, grace_period_days,
			target_all_devices, priority, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`),
		id, validated.Name, validated.Description, validated.AllowAutoUpdate,
		validated.QualityDeferralDays, validated.FeatureDeferralDays,
		validated.ActiveHoursStart, validated.ActiveHoursEnd,
		validated.QualityDeadlineDays, validated.FeatureDeadlineDays, validated.GracePeriodDays,
		targetAll, validated.Priority,
	)
	if err != nil {
		slog.Error("api: creating update ring", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create update ring")
		return
	}

	seen := make(map[string]bool)
	for _, gid := range validated.GroupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_update_rings (group_id, ring_id) VALUES (?, ?)
		`), gid, id); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit update ring")
		return
	}

	gov, queued := policy.ReconcileUpdateRingsFleet(h.db)
	h.audit(r, actor, "updates.ring_create", "update_ring", id,
		fmt.Sprintf(`{"name":%q,"quality_deferral":%d,"feature_deferral":%d,"commands_queued":%d}`,
			validated.Name, validated.QualityDeferralDays, validated.FeatureDeferralDays, queued))

	ring, err := h.loadUpdateRing(r, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load created update ring")
		return
	}
	ring.GovernedDevices = gov
	ring.CommandsQueued = queued
	respondCreated(w, ring)
}

// HandleUpdateUpdateRing modifies an existing Update Ring and reconciles devices.
// PUT /api/updates/rings/{id}
func (h *Handler) HandleUpdateUpdateRing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.loadUpdateRing(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "update ring not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var in updateRingInput
	if !decodeBody(w, r, &in) {
		return
	}
	validated, err := validateUpdateRingInput(&in)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	targetAll := 0
	if validated.TargetAllDevices {
		targetAll = 1
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE update_rings
		SET name = ?, description = ?, allow_auto_update = ?,
		    quality_deferral_days = ?, feature_deferral_days = ?,
		    active_hours_start = ?, active_hours_end = ?,
		    quality_deadline_days = ?, feature_deadline_days = ?, grace_period_days = ?,
		    target_all_devices = ?, priority = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`),
		validated.Name, validated.Description, validated.AllowAutoUpdate,
		validated.QualityDeferralDays, validated.FeatureDeferralDays,
		validated.ActiveHoursStart, validated.ActiveHoursEnd,
		validated.QualityDeadlineDays, validated.FeatureDeadlineDays, validated.GracePeriodDays,
		targetAll, validated.Priority, id,
	)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update ring")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM group_update_rings WHERE ring_id = ?`), id); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update ring groups")
		return
	}
	seen := make(map[string]bool)
	for _, gid := range validated.GroupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_update_rings (group_id, ring_id) VALUES (?, ?)
		`), gid, id); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit ring update")
		return
	}

	gov, queued := policy.ReconcileUpdateRingsFleet(h.db)
	h.audit(r, actor, "updates.ring_update", "update_ring", id,
		fmt.Sprintf(`{"name":%q,"commands_queued":%d}`, validated.Name, queued))

	ring, err := h.loadUpdateRing(r, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload update ring")
		return
	}
	ring.GovernedDevices = gov
	ring.CommandsQueued = queued
	respondOK(w, ring)
}

// HandleDeleteUpdateRing deletes an Update Ring and retracts settings from governed devices.
// DELETE /api/updates/rings/{id}
func (h *Handler) HandleDeleteUpdateRing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM update_rings WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete update ring")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "update ring not found")
		return
	}

	_, queued := policy.ReconcileUpdateRingsFleet(h.db)
	h.audit(r, actor, "updates.ring_delete", "update_ring", id, fmt.Sprintf(`{"retraction_commands":%d}`, queued))
	respondOK(w, map[string]interface{}{"status": "deleted", "commands_queued": queued})
}

// HandlePauseResumeUpdateRing pauses (35-day ISO start date) or resumes Quality
// and/or Feature updates on an Update Ring.
// POST /api/updates/rings/{id}/pause
func (h *Handler) HandlePauseResumeUpdateRing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	existing, err := h.loadUpdateRing(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "update ring not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		Target string `json:"target"` // "quality", "feature", or "both"
		Paused bool   `json:"paused"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	target := strings.ToLower(strings.TrimSpace(body.Target))
	if target != "quality" && target != "feature" && target != "both" {
		respondErr(w, http.StatusBadRequest, `target must be "quality", "feature", or "both"`)
		return
	}

	todayISO := time.Now().UTC().Format("2006-01-02")
	qStart := existing.QualityPauseStart
	fStart := existing.FeaturePauseStart
	if target == "quality" || target == "both" {
		if body.Paused {
			qStart = todayISO
		} else {
			qStart = ""
		}
	}
	if target == "feature" || target == "both" {
		if body.Paused {
			fStart = todayISO
		} else {
			fStart = ""
		}
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE update_rings
		SET quality_pause_start = ?, feature_pause_start = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`), qStart, fStart, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update pause state")
		return
	}

	gov, queued := policy.ReconcileUpdateRingsFleet(h.db)
	actionName := "updates.ring_resume"
	if body.Paused {
		actionName = "updates.ring_pause"
	}
	h.audit(r, actor, actionName, "update_ring", id,
		fmt.Sprintf(`{"target":%q,"paused":%t,"commands_queued":%d}`, target, body.Paused, queued))

	ring, err := h.loadUpdateRing(r, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload update ring")
		return
	}
	ring.GovernedDevices = gov
	ring.CommandsQueued = queued
	respondOK(w, ring)
}

// HandleGetDeviceUpdates returns the active Update Ring and scan telemetry for a device.
// GET /api/devices/{id}/updates
func (h *Handler) HandleGetDeviceUpdates(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := DeviceUpdateTelemetry{DeviceID: id}
	var (
		ringID                   sql.NullString
		qPaused, fPaused         int
		lastScan                 string
		updatedAt                time.Time
		ringName                 sql.NullString
		qDef, fDef, ahStart, ahE sql.NullInt64
	)
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			dus.ring_id, dus.quality_paused, dus.feature_paused,
			COALESCE(dus.last_scan_time, ''), dus.updated_at,
			ur.name, ur.quality_deferral_days, ur.feature_deferral_days,
			ur.active_hours_start, ur.active_hours_end
		FROM device_update_status dus
		LEFT JOIN update_rings ur ON ur.id = dus.ring_id
		WHERE dus.device_id = ?
	`), id).Scan(
		&ringID, &qPaused, &fPaused,
		&lastScan, &updatedAt,
		&ringName, &qDef, &fDef, &ahStart, &ahE,
	)
	if err == nil {
		out.RingID = ringID.String
		out.RingName = ringName.String
		out.QualityPaused = qPaused != 0
		out.FeaturePaused = fPaused != 0
		out.LastScanTime = lastScan
		t := updatedAt
		out.UpdatedAt = &t
		toIntPtr := func(n sql.NullInt64) *int {
			if !n.Valid {
				return nil
			}
			v := int(n.Int64)
			return &v
		}
		out.QualityDeferralDays = toIntPtr(qDef)
		out.FeatureDeferralDays = toIntPtr(fDef)
		out.ActiveHoursStart = toIntPtr(ahStart)
		out.ActiveHoursEnd = toIntPtr(ahE)
	}
	respondOK(w, out)
}
