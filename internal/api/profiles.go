package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/policy"
)

// Profile is the JSON representation of a configuration profile.
type Profile struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Settings    []PolicySetting `json:"settings,omitempty"`
}

// PolicySetting is one policy entry within a profile.
type PolicySetting struct {
	CatalogID     int         `json:"catalog_id"`
	OMAURI        string      `json:"oma_uri"`
	DisplayName   string      `json:"display_name"`
	Description   string      `json:"description"`
	DataType      string      `json:"data_type"`
	DesiredValue  string      `json:"desired_value"`
	AllowedValues interface{} `json:"allowed_values,omitempty"`
}

// HandleListProfiles returns all profiles.
// GET /api/profiles
func (h *Handler) HandleListProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id, name, COALESCE(description,''), COALESCE(created_by,''), created_at, updated_at
		FROM profiles ORDER BY name ASC
	`))
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list profiles")
		return
	}
	defer rows.Close()

	var profiles []Profile
	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		profiles = append(profiles, p)
	}
	if profiles == nil {
		profiles = []Profile{}
	}
	respondOK(w, profiles)
}

// HandleGetProfile returns a profile with all its policy settings.
// GET /api/profiles/{id}
func (h *Handler) HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := h.loadProfile(r, id)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "profile not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondOK(w, p)
}

// HandleCreateProfile creates a new configuration profile.
// POST /api/profiles
func (h *Handler) HandleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Settings    []struct {
			CatalogID    int    `json:"catalog_id"`
			DesiredValue string `json:"desired_value"`
		} `json:"settings"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}

	actor := emailFromCtx(r)
	id := uuid.New().String()

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(),
		dbpkg.Rebind(`INSERT INTO profiles (id, name, description, created_by) VALUES (?, ?, ?, ?)`),
		id, body.Name, body.Description, actor,
	)
	if err != nil {
		slog.Error("api: creating profile", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create profile")
		return
	}

	for _, s := range body.Settings {
		_, err = tx.ExecContext(r.Context(),
			dbpkg.Rebind(`INSERT INTO profile_settings (profile_id, catalog_id, desired_value) VALUES (?, ?, ?)`),
			id, s.CatalogID, s.DesiredValue,
		)
		if err != nil {
			slog.Error("api: inserting profile setting", "catalog_id", s.CatalogID, "err", err)
			respondErr(w, http.StatusInternalServerError, fmt.Sprintf("failed to add setting for catalog_id %d", s.CatalogID))
			return
		}
	}

	h.audit(r, actor, "profile.create", "profile", id, fmt.Sprintf(`{"name":%q}`, body.Name))
	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	p, _ := h.loadProfile(r, id)
	slog.Info("profile created", "profile_id", id, "name", body.Name, "actor", actor)
	respondCreated(w, p)
}

// HandleUpdateProfile replaces a profile's settings entirely.
// PUT /api/profiles/{id}
func (h *Handler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Settings    []struct {
			CatalogID    int    `json:"catalog_id"`
			DesiredValue string `json:"desired_value"`
		} `json:"settings"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	// Validation: don't allow wiping out the name
	updateName := body.Name
	updateDesc := body.Description
	if updateName == "" {
		_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind("SELECT name, description FROM profiles WHERE id = ?"), id).Scan(&updateName, &updateDesc)
	}

	res, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE profiles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`), updateName, updateDesc, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update profile")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "profile not found")
		return
	}

	// Replace all settings
	_, _ = tx.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM profile_settings WHERE profile_id = ?`), id)
	for _, s := range body.Settings {
		_, err = tx.ExecContext(r.Context(),
			dbpkg.Rebind(`INSERT INTO profile_settings (profile_id, catalog_id, desired_value) VALUES (?, ?, ?)`),
			id, s.CatalogID, s.DesiredValue,
		)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, fmt.Sprintf("failed to add setting %d", s.CatalogID))
			return
		}
	}

	h.audit(r, actor, "profile.update", "profile", id, fmt.Sprintf(`{"name":%q}`, body.Name))
	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Re-apply policy to all devices in groups that use this profile
	go policy.ApplyProfile(h.db, id)

	p, _ := h.loadProfile(r, id)
	slog.Info("profile updated", "profile_id", id, "actor", actor)
	respondOK(w, p)
}

// HandleDeleteProfile deletes a profile, removing all settings and group assignments.
// DELETE /api/profiles/{id}
func (h *Handler) HandleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	// Capture devices governed by this profile BEFORE deleting, so its settings
	// can be retracted from them afterwards.
	affected := h.queryDeviceIDs(r, `
		SELECT DISTINCT dgm.device_id
		FROM device_group_members dgm
		JOIN group_profiles gp ON gp.group_id = dgm.group_id
		WHERE gp.profile_id = ?`, id)

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM profiles WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete profile")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "profile not found")
		return
	}

	// Retract the now-removed settings from affected devices.
	go policy.ResyncDevices(h.db, affected)

	h.audit(r, actor, "profile.delete", "profile", id, "")
	slog.Info("profile deleted", "profile_id", id, "actor", actor, "affected_devices", len(affected))
	respondOK(w, map[string]string{"status": "deleted"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) loadProfile(r *http.Request, id string) (*Profile, error) {
	var p Profile
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, name, COALESCE(description,''), COALESCE(created_by,''), created_at, updated_at
		FROM profiles WHERE id = ?
	`), id).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}

	// Load settings
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT ps.catalog_id, pc.oma_uri, COALESCE(pc.display_name,''), COALESCE(pc.description,''), pc.data_type, ps.desired_value, pc.allowed_values
		FROM profile_settings ps
		JOIN policy_catalog pc ON pc.id = ps.catalog_id
		WHERE ps.profile_id = ?
		ORDER BY pc.oma_uri
	`), id)
	if err != nil {
		return &p, nil
	}
	defer rows.Close()

	for rows.Next() {
		var s PolicySetting
		var allowedJSON sql.NullString
		if err := rows.Scan(&s.CatalogID, &s.OMAURI, &s.DisplayName, &s.Description, &s.DataType, &s.DesiredValue, &allowedJSON); err != nil {
			continue
		}
		if allowedJSON.Valid && allowedJSON.String != "" {
			var parsed interface{}
			if err := json.Unmarshal([]byte(allowedJSON.String), &parsed); err == nil {
				s.AllowedValues = parsed
			}
		}
		p.Settings = append(p.Settings, s)
	}
	return &p, nil
}
