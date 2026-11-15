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
	"github.com/latchzmdm/latchz/internal/policy"
)

const defaultLockdownPolicyID = "default"

// DeviceLockdownPolicy represents fleet-wide USB removable storage, DeviceLock,
// hardware privacy, and single-app AssignedAccess kiosk configuration.
type DeviceLockdownPolicy struct {
	Enabled              bool       `json:"enabled"`
	USBStorageMode       string     `json:"usb_storage_mode"`
	RequirePassword      bool       `json:"require_password"`
	MinPasswordLength    int        `json:"min_password_length"`
	AlphanumericRequired bool       `json:"alphanumeric_required"`
	MaxInactivityMinutes int        `json:"max_inactivity_minutes"`
	MaxFailedAttempts    int        `json:"max_failed_attempts"`
	AllowCamera          bool       `json:"allow_camera"`
	AllowBluetooth       bool       `json:"allow_bluetooth"`
	KioskMode            string     `json:"kiosk_mode"`
	KioskAccount         string     `json:"kiosk_account"`
	KioskAppAUMID        string     `json:"kiosk_app_aumid"`
	TargetAllDevices     bool       `json:"target_all_devices"`
	GroupIDs             []string   `json:"group_ids"`
	EnforcedDevices      int        `json:"enforced_devices"`
	CommandsQueued       int        `json:"commands_queued,omitempty"`
	UpdatedBy            string     `json:"updated_by"`
	UpdatedAt            *time.Time `json:"updated_at"`
}

// DeviceLockdownState exposes per-device lockdown & kiosk state.
type DeviceLockdownState struct {
	DeviceID      string     `json:"device_id"`
	Enforced      bool       `json:"enforced"`
	KioskEnforced bool       `json:"kiosk_enforced"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

func (h *Handler) loadLockdownPolicy(r *http.Request) (DeviceLockdownPolicy, error) {
	pol := DeviceLockdownPolicy{
		Enabled:              false,
		USBStorageMode:       "allow",
		RequirePassword:      true,
		MinPasswordLength:    8,
		AlphanumericRequired: false,
		MaxInactivityMinutes: 15,
		MaxFailedAttempts:    10,
		AllowCamera:          true,
		AllowBluetooth:       true,
		KioskMode:            "none",
		KioskAccount:         "KioskUser",
		KioskAppAUMID:        "",
		TargetAllDevices:     true,
		GroupIDs:             []string{},
	}

	var enabled, reqPwd, alphaReq, allowCam, allowBT, targetAll int
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enabled, usb_storage_mode,
		       require_password, min_password_length, alphanumeric_required,
		       max_inactivity_minutes, max_failed_attempts,
		       allow_camera, allow_bluetooth,
		       kiosk_mode, kiosk_account, kiosk_app_aumid,
		       target_all_devices, updated_by, updated_at
		FROM device_lockdown_policies
		WHERE id = ?
	`), defaultLockdownPolicyID).Scan(
		&enabled, &pol.USBStorageMode,
		&reqPwd, &pol.MinPasswordLength, &alphaReq,
		&pol.MaxInactivityMinutes, &pol.MaxFailedAttempts,
		&allowCam, &allowBT,
		&pol.KioskMode, &pol.KioskAccount, &pol.KioskAppAUMID,
		&targetAll, &pol.UpdatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pol, err
	}
	if err == nil {
		pol.Enabled = enabled != 0
		pol.RequirePassword = reqPwd != 0
		pol.AlphanumericRequired = alphaReq != 0
		pol.AllowCamera = allowCam != 0
		pol.AllowBluetooth = allowBT != 0
		pol.TargetAllDevices = targetAll != 0
		t := updatedAt
		pol.UpdatedAt = &t
	}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_device_lockdown_policies WHERE policy_id = ? ORDER BY group_id ASC
	`), defaultLockdownPolicyID)
	if err == nil {
		defer gRows.Close()
		for gRows.Next() {
			var gid string
			if gRows.Scan(&gid) == nil {
				pol.GroupIDs = append(pol.GroupIDs, gid)
			}
		}
	}

	_ = h.db.QueryRowContext(r.Context(), `
		SELECT COUNT(*)
		FROM device_lockdown_state dls
		JOIN devices d ON d.id = dls.device_id
		WHERE d.is_active = 1 AND dls.enforced = 1
	`).Scan(&pol.EnforcedDevices)

	return pol, nil
}

// HandleGetLockdownPolicy returns the fleet USB storage, DeviceLock & Kiosk policy.
// GET /api/lockdown/policy
func (h *Handler) HandleGetLockdownPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.loadLockdownPolicy(r)
	if err != nil {
		slog.Error("api: loading device lockdown policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load device lockdown policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateLockdownPolicy saves the fleet Device Lockdown policy and reconciles devices.
// PUT /api/lockdown/policy
func (h *Handler) HandleUpdateLockdownPolicy(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Enabled              bool     `json:"enabled"`
		USBStorageMode       string   `json:"usb_storage_mode"`
		RequirePassword      bool     `json:"require_password"`
		MinPasswordLength    int      `json:"min_password_length"`
		AlphanumericRequired bool     `json:"alphanumeric_required"`
		MaxInactivityMinutes int      `json:"max_inactivity_minutes"`
		MaxFailedAttempts    int      `json:"max_failed_attempts"`
		AllowCamera          bool     `json:"allow_camera"`
		AllowBluetooth       bool     `json:"allow_bluetooth"`
		KioskMode            string   `json:"kiosk_mode"`
		KioskAccount         string   `json:"kiosk_account"`
		KioskAppAUMID        string   `json:"kiosk_app_aumid"`
		TargetAllDevices     bool     `json:"target_all_devices"`
		GroupIDs             []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	usbMode := strings.ToLower(strings.TrimSpace(body.USBStorageMode))
	if usbMode == "" {
		usbMode = "allow"
	}
	if !mdm.ValidUSBStorageMode(usbMode) {
		respondErr(w, http.StatusBadRequest, "usb_storage_mode must be 'allow', 'read_only', or 'block_all'")
		return
	}

	minLen := body.MinPasswordLength
	if minLen == 0 {
		minLen = 8
	}
	if minLen < 4 || minLen > 16 {
		respondErr(w, http.StatusBadRequest, "min_password_length must be between 4 and 16")
		return
	}
	if body.MaxInactivityMinutes < 0 || body.MaxInactivityMinutes > 999 {
		respondErr(w, http.StatusBadRequest, "max_inactivity_minutes must be between 0 and 999")
		return
	}
	if body.MaxFailedAttempts != 0 && (body.MaxFailedAttempts < 4 || body.MaxFailedAttempts > 16) {
		respondErr(w, http.StatusBadRequest, "max_failed_attempts must be 0 or between 4 and 16")
		return
	}

	kioskMode := strings.ToLower(strings.TrimSpace(body.KioskMode))
	if kioskMode == "" {
		kioskMode = "none"
	}
	if kioskMode != "none" && kioskMode != "single_app" {
		respondErr(w, http.StatusBadRequest, "kiosk_mode must be 'none' or 'single_app'")
		return
	}
	kioskAcct := strings.TrimSpace(body.KioskAccount)
	if kioskAcct == "" {
		kioskAcct = "KioskUser"
	}
	kioskAUMID := strings.TrimSpace(body.KioskAppAUMID)
	if kioskMode == "single_app" {
		if _, err := mdm.BuildKioskModeAppJSON(kioskAcct, kioskAUMID); err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO device_lockdown_policies (
			id, enabled, usb_storage_mode,
			require_password, min_password_length, alphanumeric_required,
			max_inactivity_minutes, max_failed_attempts,
			allow_camera, allow_bluetooth,
			kiosk_mode, kiosk_account, kiosk_app_aumid,
			target_all_devices, updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			enabled                = EXCLUDED.enabled,
			usb_storage_mode       = EXCLUDED.usb_storage_mode,
			require_password       = EXCLUDED.require_password,
			min_password_length    = EXCLUDED.min_password_length,
			alphanumeric_required  = EXCLUDED.alphanumeric_required,
			max_inactivity_minutes = EXCLUDED.max_inactivity_minutes,
			max_failed_attempts    = EXCLUDED.max_failed_attempts,
			allow_camera           = EXCLUDED.allow_camera,
			allow_bluetooth        = EXCLUDED.allow_bluetooth,
			kiosk_mode             = EXCLUDED.kiosk_mode,
			kiosk_account          = EXCLUDED.kiosk_account,
			kiosk_app_aumid        = EXCLUDED.kiosk_app_aumid,
			target_all_devices     = EXCLUDED.target_all_devices,
			updated_by             = EXCLUDED.updated_by,
			updated_at             = EXCLUDED.updated_at
	`),
		defaultLockdownPolicyID, boolToSQLInt(body.Enabled), usbMode,
		boolToSQLInt(body.RequirePassword), minLen, boolToSQLInt(body.AlphanumericRequired),
		body.MaxInactivityMinutes, body.MaxFailedAttempts,
		boolToSQLInt(body.AllowCamera), boolToSQLInt(body.AllowBluetooth),
		kioskMode, kioskAcct, kioskAUMID,
		boolToSQLInt(body.TargetAllDevices), actor, now,
	)
	if err != nil {
		slog.Error("api: saving device lockdown policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save device lockdown policy")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM group_device_lockdown_policies WHERE policy_id = ?
	`), defaultLockdownPolicyID); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update lockdown group assignments")
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
			INSERT INTO group_device_lockdown_policies (group_id, policy_id) VALUES (?, ?)
		`), gid, defaultLockdownPolicyID); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit device lockdown policy")
		return
	}

	enforced, queued := policy.ReconcileLockdownFleet(h.db)

	h.audit(r, actor, "lockdown.update_policy", "device_lockdown_policy", defaultLockdownPolicyID,
		fmt.Sprintf(`{"enabled":%t,"usb_storage_mode":%q,"kiosk_mode":%q,"enforced_devices":%d,"commands_queued":%d}`,
			body.Enabled, usbMode, kioskMode, enforced, queued))

	pol, err := h.loadLockdownPolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload device lockdown policy")
		return
	}
	pol.CommandsQueued = queued
	respondOK(w, pol)
}

// HandleGetDeviceLockdown returns lockdown & kiosk status for a single device.
// GET /api/devices/{id}/lockdown
func (h *Handler) HandleGetDeviceLockdown(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	st := DeviceLockdownState{DeviceID: id}
	var enf, kiosk int
	var updatedAt sql.NullTime
	if err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enforced, kiosk_enforced, updated_at FROM device_lockdown_state WHERE device_id = ?
	`), id).Scan(&enf, &kiosk, &updatedAt); err == nil {
		st.Enforced = enf != 0
		st.KioskEnforced = kiosk != 0
		if updatedAt.Valid {
			t := updatedAt.Time
			st.UpdatedAt = &t
		}
	}
	respondOK(w, st)
}
