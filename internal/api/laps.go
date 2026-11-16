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
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultLAPSPolicyID = "default"

// LAPSPolicy represents fleet-wide agentless Cloud LAPS configuration.
type LAPSPolicy struct {
	Enabled                  bool       `json:"enabled"`
	AccountPrefix            string     `json:"account_prefix"`
	PasswordLength           int        `json:"password_length"`
	RotationDays             int        `json:"rotation_days"`
	RotateAfterRevealMinutes int        `json:"rotate_after_reveal_minutes"`
	TargetAllDevices         bool       `json:"target_all_devices"`
	GroupIDs                 []string   `json:"group_ids"`
	ActiveDevices            int        `json:"active_devices"`
	RotatingDevices          int        `json:"rotating_devices"`
	UpdatedBy                string     `json:"updated_by"`
	UpdatedAt                *time.Time `json:"updated_at"`
	GovernedDevices          int        `json:"governed_devices,omitempty"`
	CommandsQueued           int        `json:"commands_queued,omitempty"`
}

// DeviceLAPSStatus exposes safe metadata (never passwords) for a device's managed local admin.
type DeviceLAPSStatus struct {
	DeviceID            string     `json:"device_id"`
	Governed            bool       `json:"governed"`
	Status              string     `json:"status"`
	ActiveAccount       string     `json:"active_account"`
	PreviousAccount     string     `json:"previous_account"`
	PendingAccount      string     `json:"pending_account"`
	HasActivePassword   bool       `json:"has_active_password"`
	HasPreviousPassword bool       `json:"has_previous_password"`
	HasPendingPassword  bool       `json:"has_pending_password"`
	LastError           string     `json:"last_error"`
	LastRotatedAt       *time.Time `json:"last_rotated_at"`
	ExpiresAt           *time.Time `json:"expires_at"`
	UpdatedAt           *time.Time `json:"updated_at"`
}

// RevealedLAPSCredentials is returned strictly by the audited POST /api/devices/{id}/laps/reveal endpoint.
type RevealedLAPSCredentials struct {
	DeviceID                 string     `json:"device_id"`
	Status                   string     `json:"status"`
	ActiveAccount            string     `json:"active_account"`
	ActivePassword           string     `json:"active_password,omitempty"`
	PreviousAccount          string     `json:"previous_account,omitempty"`
	PreviousPassword         string     `json:"previous_password,omitempty"`
	PendingAccount           string     `json:"pending_account,omitempty"`
	PendingPassword          string     `json:"pending_password,omitempty"`
	ExpiresAt                *time.Time `json:"expires_at"`
	RotateAfterRevealMinutes int        `json:"rotate_after_reveal_minutes"`
}

func (h *Handler) loadLAPSPolicy(r *http.Request) (LAPSPolicy, error) {
	pol := LAPSPolicy{
		Enabled:                  false,
		AccountPrefix:            "lzadm",
		PasswordLength:           20,
		RotationDays:             14,
		RotateAfterRevealMinutes: 240,
		TargetAllDevices:         true,
		GroupIDs:                 []string{},
	}

	var enabled, targetAll int
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enabled, account_prefix, password_length, rotation_days,
		       rotate_after_reveal_minutes, target_all_devices, updated_by, updated_at
		FROM laps_policies
		WHERE id = ?
	`), defaultLAPSPolicyID).Scan(
		&enabled, &pol.AccountPrefix, &pol.PasswordLength, &pol.RotationDays,
		&pol.RotateAfterRevealMinutes, &targetAll, &pol.UpdatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pol, err
	}
	if err == nil {
		pol.Enabled = enabled != 0
		pol.TargetAllDevices = targetAll != 0
		t := updatedAt
		pol.UpdatedAt = &t
	}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_laps_policies WHERE policy_id = ? ORDER BY group_id ASC
	`), defaultLAPSPolicyID)
	if err == nil {
		defer gRows.Close()
		for gRows.Next() {
			var gid string
			if gRows.Scan(&gid) == nil {
				pol.GroupIDs = append(pol.GroupIDs, gid)
			}
		}
	}

	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COALESCE(SUM(CASE WHEN dla.status = 'active' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dla.status IN ('provisioning', 'rotating') THEN 1 ELSE 0 END), 0)
		FROM device_local_admins dla
		JOIN devices d ON d.id = dla.device_id
		WHERE d.is_active = 1
	`)).Scan(&pol.ActiveDevices, &pol.RotatingDevices)

	return pol, nil
}

// HandleGetLAPSPolicy returns fleet-wide Cloud LAPS settings and active counts.
// GET /api/laps/policy
func (h *Handler) HandleGetLAPSPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.loadLAPSPolicy(r)
	if err != nil {
		slog.Error("api: loading LAPS policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load Cloud LAPS policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateLAPSPolicy updates fleet-wide Cloud LAPS settings and reconciles governed devices.
// PUT /api/laps/policy
func (h *Handler) HandleUpdateLAPSPolicy(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
		return
	}
	actor := emailFromCtx(r)

	var body struct {
		Enabled                  bool     `json:"enabled"`
		AccountPrefix            string   `json:"account_prefix"`
		PasswordLength           int      `json:"password_length"`
		RotationDays             int      `json:"rotation_days"`
		RotateAfterRevealMinutes int      `json:"rotate_after_reveal_minutes"`
		TargetAllDevices         bool     `json:"target_all_devices"`
		GroupIDs                 []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	prefix, err := mdm.NormalizeLAPSPrefix(body.AccountPrefix)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pwdLen := body.PasswordLength
	if pwdLen == 0 {
		pwdLen = 20
	}
	if pwdLen < 14 || pwdLen > 32 {
		respondErr(w, http.StatusBadRequest, "password_length must be between 14 and 32")
		return
	}
	rotDays := body.RotationDays
	if rotDays == 0 {
		rotDays = 14
	}
	if rotDays < 1 || rotDays > 90 {
		respondErr(w, http.StatusBadRequest, "rotation_days must be between 1 and 90")
		return
	}
	if body.RotateAfterRevealMinutes < 0 || body.RotateAfterRevealMinutes > 1440 {
		respondErr(w, http.StatusBadRequest, "rotate_after_reveal_minutes must be between 0 and 1440")
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO laps_policies (
			id, enabled, account_prefix, password_length, rotation_days,
			rotate_after_reveal_minutes, target_all_devices, updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			enabled                     = EXCLUDED.enabled,
			account_prefix              = EXCLUDED.account_prefix,
			password_length             = EXCLUDED.password_length,
			rotation_days               = EXCLUDED.rotation_days,
			rotate_after_reveal_minutes = EXCLUDED.rotate_after_reveal_minutes,
			target_all_devices          = EXCLUDED.target_all_devices,
			updated_by                  = EXCLUDED.updated_by,
			updated_at                  = EXCLUDED.updated_at
	`),
		defaultLAPSPolicyID, boolToSQLInt(body.Enabled), prefix, pwdLen, rotDays,
		body.RotateAfterRevealMinutes, boolToSQLInt(body.TargetAllDevices), actor, now,
	)
	if err != nil {
		slog.Error("api: saving LAPS policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save Cloud LAPS policy")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM group_laps_policies WHERE policy_id = ?
	`), defaultLAPSPolicyID); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update LAPS group assignments")
		return
	}

	seen := make(map[string]bool)
	for _, rawGID := range body.GroupIDs {
		gid := strings.TrimSpace(rawGID)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_laps_policies (group_id, policy_id) VALUES (?, ?)
		`), gid, defaultLAPSPolicyID); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit LAPS policy")
		return
	}

	governedDevices, queued := h.reconcileFleetLAPS(r, prefix, pwdLen)

	h.audit(r, actor, "laps.update_policy", "laps_policy", defaultLAPSPolicyID,
		fmt.Sprintf(`{"enabled":%t,"prefix":%q,"rotation_days":%d,"governed_devices":%d,"commands_queued":%d}`,
			body.Enabled, prefix, rotDays, governedDevices, queued))

	pol, err := h.loadLAPSPolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload Cloud LAPS policy")
		return
	}
	pol.GovernedDevices = governedDevices
	pol.CommandsQueued = queued
	respondOK(w, pol)
}

func (h *Handler) reconcileFleetLAPS(r *http.Request, prefix string, pwdLen int) (governedCount int, totalQueued int) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id FROM devices WHERE is_active = 1
	`))
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

	for _, devID := range devIDs {
		gov, _, _, _ := mdm.IsDeviceLAPSGoverned(h.db, devID)
		if gov {
			governedCount++
			var status, activeAcct string
			var pendingQueueID int
			var expiresAt sql.NullTime
			err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
				SELECT status, active_account, pending_queue_id, expires_at
				FROM device_local_admins
				WHERE device_id = ?
			`), devID).Scan(&status, &activeAcct, &pendingQueueID, &expiresAt)

			needsProvision := errors.Is(err, sql.ErrNoRows) ||
				status == "unconfigured" ||
				status == "revoked" ||
				(activeAcct == "" && pendingQueueID == 0) ||
				(status == "active" && expiresAt.Valid && time.Now().UTC().After(expiresAt.Time))

			if needsProvision && pendingQueueID == 0 {
				if _, q, qErr := mdm.EnqueueLAPSRotation(h.db, h.vault, devID, prefix, pwdLen); qErr == nil && q > 0 {
					totalQueued += q
					h.wakeDevice(devID)
				}
			}
		} else {
			if q, rErr := mdm.EnqueueLAPSRevocation(h.db, devID); rErr == nil && q > 0 {
				totalQueued += q
				h.wakeDevice(devID)
			}
		}
	}
	return governedCount, totalQueued
}

// HandleGetDeviceLAPS returns non-secret Cloud LAPS state for a single device.
// GET /api/devices/{id}/laps
func (h *Handler) HandleGetDeviceLAPS(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists int
	if err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COUNT(*) FROM devices WHERE id = ? AND is_active = 1
	`), id).Scan(&exists); err != nil || exists == 0 {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	gov, _, _, _ := mdm.IsDeviceLAPSGoverned(h.db, id)
	out := DeviceLAPSStatus{
		DeviceID: id,
		Governed: gov,
		Status:   "unconfigured",
	}

	var activeEnc, prevEnc, pendingEnc string
	var lastRot, expAt sql.NullTime
	var updAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT status, active_account, active_password_encrypted,
		       previous_account, previous_password_encrypted,
		       pending_account, pending_password_encrypted,
		       last_error, last_rotated_at, expires_at, updated_at
		FROM device_local_admins
		WHERE device_id = ?
	`), id).Scan(
		&out.Status, &out.ActiveAccount, &activeEnc,
		&out.PreviousAccount, &prevEnc,
		&out.PendingAccount, &pendingEnc,
		&out.LastError, &lastRot, &expAt, &updAt,
	)
	if err == nil {
		out.HasActivePassword = activeEnc != ""
		out.HasPreviousPassword = prevEnc != ""
		out.HasPendingPassword = pendingEnc != ""
		if lastRot.Valid {
			t := lastRot.Time
			out.LastRotatedAt = &t
		}
		if expAt.Valid {
			t := expAt.Time
			out.ExpiresAt = &t
		}
		u := updAt
		out.UpdatedAt = &u
	}
	respondOK(w, out)
}

// HandleRevealDeviceLAPS decrypts the device's current (and fallback previous/pending)
// Cloud LAPS local administrator password, permanently logs `laps.reveal_password` in
// audit_log, and shortens expires_at to the configured post-reveal rotation window.
// POST /api/devices/{id}/laps/reveal
func (h *Handler) HandleRevealDeviceLAPS(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
		return
	}
	reason, ok := h.extractAndValidateRevealReason(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var status, activeAcct, activeEnc, prevAcct, prevEnc, pendingAcct, pendingEnc string
	var expAt sql.NullTime
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT dla.status, dla.active_account, dla.active_password_encrypted,
		       dla.previous_account, dla.previous_password_encrypted,
		       dla.pending_account, dla.pending_password_encrypted,
		       dla.expires_at
		FROM device_local_admins dla
		JOIN devices d ON d.id = dla.device_id
		WHERE dla.device_id = ? AND d.is_active = 1
	`), id).Scan(&status, &activeAcct, &activeEnc, &prevAcct, &prevEnc, &pendingAcct, &pendingEnc, &expAt)
	if errors.Is(err, sql.ErrNoRows) || (activeEnc == "" && prevEnc == "" && pendingEnc == "") {
		respondErr(w, http.StatusNotFound, "no Cloud LAPS credentials have been provisioned for this device yet")
		return
	}
	if err != nil {
		slog.Error("api: querying device LAPS credentials", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load device LAPS credentials")
		return
	}

	aad := mdm.LAPSVaultAADPrefix + id
	res := RevealedLAPSCredentials{
		DeviceID:        id,
		Status:          status,
		ActiveAccount:   activeAcct,
		PreviousAccount: prevAcct,
		PendingAccount:  pendingAcct,
	}

	if activeEnc != "" {
		plain, err := h.vault.Decrypt(activeEnc, aad)
		if err != nil {
			slog.Error("api: decrypting active LAPS password", "device_id", id, "err", err)
			respondErr(w, http.StatusInternalServerError, "vault decryption failed for active LAPS credential")
			return
		}
		res.ActivePassword = plain
	}
	if prevEnc != "" {
		if plain, err := h.vault.Decrypt(prevEnc, aad); err == nil {
			res.PreviousPassword = plain
		}
	}
	if pendingEnc != "" {
		if plain, err := h.vault.Decrypt(pendingEnc, aad); err == nil {
			res.PendingPassword = plain
		}
	}

	postRevealMins := 240
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT rotate_after_reveal_minutes FROM laps_policies WHERE id = ?
	`), defaultLAPSPolicyID).Scan(&postRevealMins)
	res.RotateAfterRevealMinutes = postRevealMins

	var finalExp *time.Time
	if expAt.Valid {
		t := expAt.Time
		finalExp = &t
	}
	if postRevealMins > 0 && activeAcct != "" {
		shortened := time.Now().UTC().Add(time.Duration(postRevealMins) * time.Minute)
		if finalExp == nil || shortened.Before(*finalExp) {
			finalExp = &shortened
			_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
				UPDATE device_local_admins SET expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?
			`), shortened, id)
		}
	}
	res.ExpiresAt = finalExp

	h.audit(r, actor, "laps.reveal_password", "device", id,
		fmt.Sprintf(`{"active_account":%q,"pending_account":%q,"reason":%q}`, activeAcct, pendingAcct, reason))
	slog.Info("Cloud LAPS password revealed", "device_id", id, "account", activeAcct, "actor", actor)

	respondOK(w, res)
}

// HandleRotateDeviceLAPS immediately queues a fresh ephemeral local administrator
// account & password rotation for the target device.
// POST /api/devices/{id}/laps/rotate
func (h *Handler) HandleRotateDeviceLAPS(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
		return
	}
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var exists int
	if err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COUNT(*) FROM devices WHERE id = ? AND is_active = 1
	`), id).Scan(&exists); err != nil || exists == 0 {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	prefix := "lzadm"
	pwdLen := 20
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT account_prefix, password_length FROM laps_policies WHERE id = ?
	`), defaultLAPSPolicyID).Scan(&prefix, &pwdLen)

	newAcct, queued, err := mdm.EnqueueLAPSRotation(h.db, h.vault, id, prefix, pwdLen)
	if err != nil {
		slog.Error("api: queueing LAPS rotation", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue Cloud LAPS rotation: "+err.Error())
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "laps.rotate_password", "device", id,
		fmt.Sprintf(`{"pending_account":%q,"commands_queued":%d}`, newAcct, queued))

	respondOK(w, map[string]interface{}{
		"status":          "rotating",
		"pending_account": newAcct,
		"commands_queued": queued,
	})
}

func boolToSQLInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
