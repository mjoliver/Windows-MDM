package api

import (
	"database/sql"
	"encoding/json"
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

const defaultHardeningPolicyID = "default"

// EndpointHardeningPolicy represents fleet-wide Defender ASR, SmartScreen & App Install Control configuration.
type EndpointHardeningPolicy struct {
	Enabled                    bool                      `json:"enabled"`
	ASRRules                   map[string]int            `json:"asr_rules"`
	ActiveASRCount             int                       `json:"active_asr_count"`
	EnableSmartScreenShell     bool                      `json:"enable_smartscreen_shell"`
	PreventSmartScreenOverride bool                      `json:"prevent_smartscreen_override"`
	AppInstallControl          int                       `json:"app_install_control"`
	SubmitSamplesConsent       int                       `json:"submit_samples_consent"`
	DisableLocalAdminMerge     bool                      `json:"disable_local_admin_merge"`
	TargetAllDevices           bool                      `json:"target_all_devices"`
	GroupIDs                   []string                  `json:"group_ids"`
	EnforcedDevices            int                       `json:"enforced_devices"`
	CommandsQueued             int                       `json:"commands_queued,omitempty"`
	UpdatedBy                  string                    `json:"updated_by"`
	UpdatedAt                  *time.Time                `json:"updated_at"`
	Catalog                    []mdm.ASRRuleCatalogEntry `json:"catalog"`
}

// DeviceEndpointHardeningState exposes per-device ASR & SmartScreen enforcement state.
type DeviceEndpointHardeningState struct {
	DeviceID       string     `json:"device_id"`
	Enforced       bool       `json:"enforced"`
	ActiveASRCount int        `json:"active_asr_count"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

func (h *Handler) loadEndpointHardeningPolicy(r *http.Request) (EndpointHardeningPolicy, error) {
	pol := EndpointHardeningPolicy{
		Enabled:                    false,
		ASRRules:                   map[string]int{},
		EnableSmartScreenShell:     true,
		PreventSmartScreenOverride: true,
		AppInstallControl:          0,
		SubmitSamplesConsent:       1,
		DisableLocalAdminMerge:     true,
		TargetAllDevices:           true,
		GroupIDs:                   []string{},
		Catalog:                    mdm.OfficialASRRuleCatalog,
	}

	var enabled, ssShell, ssPrevent, noMerge, targetAll int
	var asrJSON string
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enabled, asr_rules_json,
		       enable_smartscreen_shell, prevent_smartscreen_override,
		       app_install_control, submit_samples_consent, disable_local_admin_merge,
		       target_all_devices, updated_by, updated_at
		FROM endpoint_hardening_policies
		WHERE id = ?
	`), defaultHardeningPolicyID).Scan(
		&enabled, &asrJSON,
		&ssShell, &ssPrevent,
		&pol.AppInstallControl, &pol.SubmitSamplesConsent, &noMerge,
		&targetAll, &pol.UpdatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pol, err
	}
	if err == nil {
		pol.Enabled = enabled != 0
		pol.ASRRules = mdm.ParseASRRulesJSON(asrJSON)
		pol.ActiveASRCount = len(pol.ASRRules)
		pol.EnableSmartScreenShell = ssShell != 0
		pol.PreventSmartScreenOverride = ssPrevent != 0
		pol.DisableLocalAdminMerge = noMerge != 0
		pol.TargetAllDevices = targetAll != 0
		t := updatedAt
		pol.UpdatedAt = &t
	}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_endpoint_hardening_policies WHERE policy_id = ? ORDER BY group_id ASC
	`), defaultHardeningPolicyID)
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
		FROM device_endpoint_hardening_state dhs
		JOIN devices d ON d.id = dhs.device_id
		WHERE d.is_active = 1 AND dhs.enforced = 1
	`).Scan(&pol.EnforcedDevices)

	return pol, nil
}

// HandleGetHardeningPolicy returns the fleet Defender ASR & SmartScreen hardening policy + official ASR catalog.
// GET /api/hardening/policy
func (h *Handler) HandleGetHardeningPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.loadEndpointHardeningPolicy(r)
	if err != nil {
		slog.Error("api: loading endpoint hardening policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load endpoint hardening policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateHardeningPolicy saves the fleet Defender ASR & SmartScreen policy and reconciles devices.
// PUT /api/hardening/policy
func (h *Handler) HandleUpdateHardeningPolicy(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Enabled                    bool           `json:"enabled"`
		ASRRules                   map[string]int `json:"asr_rules"`
		EnableSmartScreenShell     bool           `json:"enable_smartscreen_shell"`
		PreventSmartScreenOverride bool           `json:"prevent_smartscreen_override"`
		AppInstallControl          int            `json:"app_install_control"`
		SubmitSamplesConsent       int            `json:"submit_samples_consent"`
		DisableLocalAdminMerge     bool           `json:"disable_local_admin_merge"`
		TargetAllDevices           bool           `json:"target_all_devices"`
		GroupIDs                   []string       `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	normASR, activeCount, err := mdm.ValidateAndNormalizeASRRules(body.ASRRules)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.AppInstallControl < 0 || body.AppInstallControl > 3 {
		respondErr(w, http.StatusBadRequest, "app_install_control must be 0, 1, 2, or 3")
		return
	}
	if body.SubmitSamplesConsent < 0 || body.SubmitSamplesConsent > 3 {
		respondErr(w, http.StatusBadRequest, "submit_samples_consent must be 0, 1, 2, or 3")
		return
	}

	asrBytes, err := json.Marshal(normASR)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to encode asr_rules")
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
		INSERT INTO endpoint_hardening_policies (
			id, enabled, asr_rules_json,
			enable_smartscreen_shell, prevent_smartscreen_override,
			app_install_control, submit_samples_consent, disable_local_admin_merge,
			target_all_devices, updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			enabled                      = EXCLUDED.enabled,
			asr_rules_json               = EXCLUDED.asr_rules_json,
			enable_smartscreen_shell     = EXCLUDED.enable_smartscreen_shell,
			prevent_smartscreen_override = EXCLUDED.prevent_smartscreen_override,
			app_install_control          = EXCLUDED.app_install_control,
			submit_samples_consent       = EXCLUDED.submit_samples_consent,
			disable_local_admin_merge    = EXCLUDED.disable_local_admin_merge,
			target_all_devices           = EXCLUDED.target_all_devices,
			updated_by                   = EXCLUDED.updated_by,
			updated_at                   = EXCLUDED.updated_at
	`),
		defaultHardeningPolicyID,
		boolToSQLInt(body.Enabled),
		string(asrBytes),
		boolToSQLInt(body.EnableSmartScreenShell),
		boolToSQLInt(body.PreventSmartScreenOverride),
		body.AppInstallControl,
		body.SubmitSamplesConsent,
		boolToSQLInt(body.DisableLocalAdminMerge),
		boolToSQLInt(body.TargetAllDevices),
		actor,
		now,
	)
	if err != nil {
		slog.Error("api: upserting endpoint hardening policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save endpoint hardening policy")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM group_endpoint_hardening_policies WHERE policy_id = ?
	`), defaultHardeningPolicyID); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update hardening groups")
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
			INSERT INTO group_endpoint_hardening_policies (group_id, policy_id) VALUES (?, ?)
		`), gid, defaultHardeningPolicyID); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit endpoint hardening policy")
		return
	}

	enforced, queued := policy.ReconcileEndpointHardeningFleet(h.db)

	h.audit(r, actor, "hardening.policy_update", "endpoint_hardening_policy", defaultHardeningPolicyID,
		fmt.Sprintf(`{"enabled":%t,"active_asr_rules":%d,"enforced_devices":%d,"commands_queued":%d}`,
			body.Enabled, activeCount, enforced, queued))

	pol, err := h.loadEndpointHardeningPolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload endpoint hardening policy")
		return
	}
	pol.EnforcedDevices = enforced
	pol.CommandsQueued = queued
	respondOK(w, pol)
}

// HandleGetDeviceHardening returns per-device Defender ASR & SmartScreen hardening state.
// GET /api/devices/{id}/hardening
func (h *Handler) HandleGetDeviceHardening(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := DeviceEndpointHardeningState{DeviceID: id}
	var enforced int
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enforced, active_asr_count, updated_at
		FROM device_endpoint_hardening_state
		WHERE device_id = ?
	`), id).Scan(&enforced, &out.ActiveASRCount, &updatedAt)
	if err == nil {
		out.Enforced = enforced != 0
		t := updatedAt
		out.UpdatedAt = &t
	}
	respondOK(w, out)
}
