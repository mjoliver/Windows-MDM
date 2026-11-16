package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/policy"
)

const defaultExperiencePolicyID = "default"

// DesktopExperiencePolicy represents fleet-wide Windows 11 Privacy/Debloat,
// Corporate Branding, and Microsoft Edge Browser Security Baseline settings.
type DesktopExperiencePolicy struct {
	Enabled                  bool       `json:"enabled"`
	TelemetryLevel           int        `json:"telemetry_level"`
	DisableAdvertisingID     bool       `json:"disable_advertising_id"`
	BlockTailoredExperiences bool       `json:"block_tailored_experiences"`
	DisableWidgetsNews       bool       `json:"disable_widgets_news"`
	EdgeSmartScreenEnabled   bool       `json:"edge_smartscreen_enabled"`
	EdgePreventSSOverride    bool       `json:"edge_prevent_ss_override"`
	EdgeSmartScreenPUA       bool       `json:"edge_smartscreen_pua"`
	EdgeBlockPasswordManager bool       `json:"edge_block_password_manager"`
	EdgeTyposquattingChecker bool       `json:"edge_typosquatting_checker"`
	DesktopWallpaperURL      string     `json:"desktop_wallpaper_url"`
	LockScreenImageURL       string     `json:"lockscreen_image_url"`
	TargetAllDevices         bool       `json:"target_all_devices"`
	GroupIDs                 []string   `json:"group_ids"`
	EnforcedDevices          int        `json:"enforced_devices"`
	CommandsQueued           int        `json:"commands_queued,omitempty"`
	UpdatedBy                string     `json:"updated_by"`
	UpdatedAt                *time.Time `json:"updated_at"`
}

func (h *Handler) loadExperiencePolicy(r *http.Request) (DesktopExperiencePolicy, error) {
	pol := DesktopExperiencePolicy{
		Enabled:                  false,
		TelemetryLevel:           1,
		DisableAdvertisingID:     true,
		BlockTailoredExperiences: true,
		DisableWidgetsNews:       true,
		EdgeSmartScreenEnabled:   true,
		EdgePreventSSOverride:    true,
		EdgeSmartScreenPUA:       true,
		EdgeBlockPasswordManager: false,
		EdgeTyposquattingChecker: true,
		TargetAllDevices:         true,
		GroupIDs:                 []string{},
	}

	var enabled, disAdv, blockTailored, disWidgets int
	var edgeSS, edgeNoOver, edgePUA, edgeNoPwd, edgeTypo, targetAll int
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			enabled, telemetry_level, disable_advertising_id, block_tailored_experiences, disable_widgets_news,
			edge_smartscreen_enabled, edge_prevent_ss_override, edge_smartscreen_pua,
			edge_block_password_manager, edge_typosquatting_checker,
			desktop_wallpaper_url, lockscreen_image_url,
			target_all_devices, updated_by, updated_at
		FROM desktop_experience_policies
		WHERE id = ?
	`), defaultExperiencePolicyID).Scan(
		&enabled, &pol.TelemetryLevel, &disAdv, &blockTailored, &disWidgets,
		&edgeSS, &edgeNoOver, &edgePUA,
		&edgeNoPwd, &edgeTypo,
		&pol.DesktopWallpaperURL, &pol.LockScreenImageURL,
		&targetAll, &pol.UpdatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pol, err
	}
	if err == nil {
		pol.Enabled = enabled != 0
		pol.DisableAdvertisingID = disAdv != 0
		pol.BlockTailoredExperiences = blockTailored != 0
		pol.DisableWidgetsNews = disWidgets != 0
		pol.EdgeSmartScreenEnabled = edgeSS != 0
		pol.EdgePreventSSOverride = edgeNoOver != 0
		pol.EdgeSmartScreenPUA = edgePUA != 0
		pol.EdgeBlockPasswordManager = edgeNoPwd != 0
		pol.EdgeTyposquattingChecker = edgeTypo != 0
		pol.TargetAllDevices = targetAll != 0
		t := updatedAt
		pol.UpdatedAt = &t
	}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_desktop_experience_policies WHERE policy_id = ? ORDER BY group_id ASC
	`), defaultExperiencePolicyID)
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
		FROM device_desktop_experience_state des
		JOIN devices d ON d.id = des.device_id
		WHERE d.is_active = 1 AND des.enforced = 1
	`).Scan(&pol.EnforcedDevices)

	return pol, nil
}

// HandleGetExperiencePolicy returns the fleet Windows 11 Privacy/Debloat, Branding & Edge Browser policy.
// GET /api/experience/policy
func (h *Handler) HandleGetExperiencePolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.loadExperiencePolicy(r)
	if err != nil {
		slog.Error("api: loading desktop experience policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load desktop experience policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateExperiencePolicy saves the fleet Windows 11 Privacy/Debloat, Branding & Edge Browser policy and reconciles devices.
// PUT /api/experience/policy
func (h *Handler) HandleUpdateExperiencePolicy(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Enabled                  bool     `json:"enabled"`
		TelemetryLevel           int      `json:"telemetry_level"`
		DisableAdvertisingID     bool     `json:"disable_advertising_id"`
		BlockTailoredExperiences bool     `json:"block_tailored_experiences"`
		DisableWidgetsNews       bool     `json:"disable_widgets_news"`
		EdgeSmartScreenEnabled   bool     `json:"edge_smartscreen_enabled"`
		EdgePreventSSOverride    bool     `json:"edge_prevent_ss_override"`
		EdgeSmartScreenPUA       bool     `json:"edge_smartscreen_pua"`
		EdgeBlockPasswordManager bool     `json:"edge_block_password_manager"`
		EdgeTyposquattingChecker bool     `json:"edge_typosquatting_checker"`
		DesktopWallpaperURL      string   `json:"desktop_wallpaper_url"`
		LockScreenImageURL       string   `json:"lockscreen_image_url"`
		TargetAllDevices         bool     `json:"target_all_devices"`
		GroupIDs                 []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	if body.TelemetryLevel != 0 && body.TelemetryLevel != 1 && body.TelemetryLevel != 3 {
		respondErr(w, http.StatusBadRequest, "telemetry_level must be 0 (Security/Enterprise), 1 (Required/Basic), or 3 (Optional)")
		return
	}
	deskURL, err := mdm.ValidateOptionalBrandingURL(body.DesktopWallpaperURL)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "desktop_wallpaper_url: "+err.Error())
		return
	}
	lockURL, err := mdm.ValidateOptionalBrandingURL(body.LockScreenImageURL)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "lockscreen_image_url: "+err.Error())
		return
	}

	now := time.Now().UTC()
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO desktop_experience_policies (
			id, enabled, telemetry_level, disable_advertising_id, block_tailored_experiences, disable_widgets_news,
			edge_smartscreen_enabled, edge_prevent_ss_override, edge_smartscreen_pua,
			edge_block_password_manager, edge_typosquatting_checker,
			desktop_wallpaper_url, lockscreen_image_url,
			target_all_devices, updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			enabled                     = EXCLUDED.enabled,
			telemetry_level             = EXCLUDED.telemetry_level,
			disable_advertising_id      = EXCLUDED.disable_advertising_id,
			block_tailored_experiences  = EXCLUDED.block_tailored_experiences,
			disable_widgets_news        = EXCLUDED.disable_widgets_news,
			edge_smartscreen_enabled    = EXCLUDED.edge_smartscreen_enabled,
			edge_prevent_ss_override    = EXCLUDED.edge_prevent_ss_override,
			edge_smartscreen_pua        = EXCLUDED.edge_smartscreen_pua,
			edge_block_password_manager = EXCLUDED.edge_block_password_manager,
			edge_typosquatting_checker  = EXCLUDED.edge_typosquatting_checker,
			desktop_wallpaper_url       = EXCLUDED.desktop_wallpaper_url,
			lockscreen_image_url        = EXCLUDED.lockscreen_image_url,
			target_all_devices          = EXCLUDED.target_all_devices,
			updated_by                  = EXCLUDED.updated_by,
			updated_at                  = EXCLUDED.updated_at
	`),
		defaultExperiencePolicyID,
		boolToSQLInt(body.Enabled),
		body.TelemetryLevel,
		boolToSQLInt(body.DisableAdvertisingID),
		boolToSQLInt(body.BlockTailoredExperiences),
		boolToSQLInt(body.DisableWidgetsNews),
		boolToSQLInt(body.EdgeSmartScreenEnabled),
		boolToSQLInt(body.EdgePreventSSOverride),
		boolToSQLInt(body.EdgeSmartScreenPUA),
		boolToSQLInt(body.EdgeBlockPasswordManager),
		boolToSQLInt(body.EdgeTyposquattingChecker),
		deskURL,
		lockURL,
		boolToSQLInt(body.TargetAllDevices),
		actor,
		now,
	)
	if err != nil {
		slog.Error("api: upserting desktop experience policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save desktop experience policy")
		return
	}

	_, _ = tx.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM group_desktop_experience_policies WHERE policy_id = ?`), defaultExperiencePolicyID)
	seen := make(map[string]bool)
	for _, rawG := range body.GroupIDs {
		gid := strings.TrimSpace(rawG)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		_, _ = tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_desktop_experience_policies (policy_id, group_id) VALUES (?, ?)
		`), defaultExperiencePolicyID, gid)
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit desktop experience policy")
		return
	}

	_, queued := policy.ReconcileDesktopExperienceFleet(h.db)

	h.audit(r, actor, "experience.policy_update", "desktop_experience_policy", defaultExperiencePolicyID,
		fmt.Sprintf(`{"enabled":%t,"telemetry_level":%d,"commands_queued":%d}`, body.Enabled, body.TelemetryLevel, queued))

	pol, err := h.loadExperiencePolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload desktop experience policy")
		return
	}
	pol.CommandsQueued = queued
	respondOK(w, pol)
}
