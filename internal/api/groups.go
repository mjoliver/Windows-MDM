package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/policy"
)

// Group is the JSON representation of a device group (static or Dynamic Smart Group).
type Group struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	Description  string                    `json:"description"`
	IsDynamic    bool                      `json:"is_dynamic"`
	MatchMode    string                    `json:"match_mode"`
	DynamicRules []policy.DynamicGroupRule `json:"dynamic_rules"`
	CreatedAt    time.Time                 `json:"created_at"`
	DeviceCount  int                       `json:"device_count"`
	ProfileCount int                       `json:"profile_count"`
}

// HandleListGroups returns all device groups with member and profile counts.
// GET /api/groups
func (h *Handler) HandleListGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), db.Rebind(`
		SELECT g.id, g.name, COALESCE(g.description,''),
		       COALESCE(g.is_dynamic, 0), COALESCE(g.match_mode, 'all'), COALESCE(g.dynamic_rules_json, '[]'),
		       g.created_at,
		       COUNT(DISTINCT dgm.device_id) as device_count,
		       COUNT(DISTINCT gp.profile_id) as profile_count
		FROM device_groups g
		LEFT JOIN device_group_members dgm ON dgm.group_id = g.id
		LEFT JOIN group_profiles gp ON gp.group_id = g.id
		GROUP BY g.id, g.name, g.description, g.is_dynamic, g.match_mode, g.dynamic_rules_json, g.created_at
		ORDER BY g.name ASC
	`))
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		var isDyn int
		var rulesJSON string
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description,
			&isDyn, &g.MatchMode, &rulesJSON,
			&g.CreatedAt, &g.DeviceCount, &g.ProfileCount,
		); err != nil {
			continue
		}
		g.IsDynamic = isDyn == 1
		if g.MatchMode == "" {
			g.MatchMode = "all"
		}
		if err := json.Unmarshal([]byte(rulesJSON), &g.DynamicRules); err != nil || g.DynamicRules == nil {
			g.DynamicRules = []policy.DynamicGroupRule{}
		}
		groups = append(groups, g)
	}
	if groups == nil {
		groups = []Group{}
	}
	respondOK(w, groups)
}

// HandleCreateGroup creates a new static or Dynamic Smart Group.
// POST /api/groups
func (h *Handler) HandleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string                    `json:"name"`
		Description  string                    `json:"description"`
		IsDynamic    bool                      `json:"is_dynamic"`
		MatchMode    string                    `json:"match_mode"`
		DynamicRules []policy.DynamicGroupRule `json:"dynamic_rules"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}

	matchMode := "all"
	cleanedRules := []policy.DynamicGroupRule{}
	if body.IsDynamic {
		var err error
		matchMode, cleanedRules, err = policy.ValidateDynamicGroupConfig(body.MatchMode, body.DynamicRules)
		if err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	rulesBytes, _ := json.Marshal(cleanedRules)

	actor := emailFromCtx(r)
	id := uuid.New().String()

	isDynInt := 0
	if body.IsDynamic {
		isDynInt = 1
	}

	_, err := h.db.ExecContext(r.Context(),
		db.Rebind(`INSERT INTO device_groups (id, name, description, is_dynamic, match_mode, dynamic_rules_json) VALUES (?, ?, ?, ?, ?, ?)`),
		id, body.Name, body.Description, isDynInt, matchMode, string(rulesBytes),
	)
	if err != nil {
		slog.Error("api: creating group", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	devCount := 0
	if body.IsDynamic {
		devCount, _ = policyOps.ReconcileDynamicGroup(h.db, id)
	}

	h.audit(r, actor, "group.create", "group", id, fmt.Sprintf(`{"name":%q,"is_dynamic":%t}`, body.Name, body.IsDynamic))
	slog.Info("group created", "group_id", id, "name", body.Name, "is_dynamic", body.IsDynamic, "actor", actor)
	respondCreated(w, Group{
		ID:           id,
		Name:         body.Name,
		Description:  body.Description,
		IsDynamic:    body.IsDynamic,
		MatchMode:    matchMode,
		DynamicRules: cleanedRules,
		CreatedAt:    time.Now().UTC(),
		DeviceCount:  devCount,
	})
}

// HandleUpdateGroup renames/redescribes a group and optionally updates Dynamic Smart Group rules.
// PUT /api/groups/{id}
func (h *Handler) HandleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		Name         string                    `json:"name"`
		Description  string                    `json:"description"`
		IsDynamic    *bool                     `json:"is_dynamic"`
		MatchMode    string                    `json:"match_mode"`
		DynamicRules []policy.DynamicGroupRule `json:"dynamic_rules"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}

	var res sql.Result
	var err error
	if body.IsDynamic == nil {
		res, err = h.db.ExecContext(r.Context(),
			db.Rebind(`UPDATE device_groups SET name = ?, description = ? WHERE id = ?`),
			body.Name, body.Description, id,
		)
	} else {
		matchMode := "all"
		cleanedRules := []policy.DynamicGroupRule{}
		if *body.IsDynamic {
			matchMode, cleanedRules, err = policy.ValidateDynamicGroupConfig(body.MatchMode, body.DynamicRules)
			if err != nil {
				respondErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		rulesBytes, _ := json.Marshal(cleanedRules)
		isDynInt := 0
		if *body.IsDynamic {
			isDynInt = 1
		}
		res, err = h.db.ExecContext(r.Context(),
			db.Rebind(`UPDATE device_groups SET name = ?, description = ?, is_dynamic = ?, match_mode = ?, dynamic_rules_json = ? WHERE id = ?`),
			body.Name, body.Description, isDynInt, matchMode, string(rulesBytes), id,
		)
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update group")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "group not found")
		return
	}

	if body.IsDynamic != nil && *body.IsDynamic {
		policyOps.ReconcileDynamicGroup(h.db, id)
	}

	h.audit(r, actor, "group.update", "group", id, fmt.Sprintf(`{"name":%q}`, body.Name))
	respondOK(w, map[string]string{"status": "updated"})
}

// HandleReconcileGroup forces immediate re-evaluation of a Dynamic Smart Group's rules.
// POST /api/groups/{id}/reconcile
func (h *Handler) HandleReconcileGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var isDyn int
	err := h.db.QueryRowContext(r.Context(),
		db.Rebind(`SELECT COALESCE(is_dynamic, 0) FROM device_groups WHERE id = ?`), id,
	).Scan(&isDyn)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to query group")
		return
	}
	if isDyn == 0 {
		respondErr(w, http.StatusBadRequest, "group is static, not a dynamic smart group")
		return
	}

	added, removed := policyOps.ReconcileDynamicGroup(h.db, id)
	var memberCount int
	_ = h.db.QueryRowContext(r.Context(), db.Rebind(`SELECT COUNT(*) FROM device_group_members WHERE group_id = ?`), id).Scan(&memberCount)

	h.audit(r, actor, "group.reconcile", "group", id, fmt.Sprintf(`{"added":%d,"removed":%d}`, added, removed))
	respondOK(w, map[string]interface{}{
		"status":       "reconciled",
		"added":        added,
		"removed":      removed,
		"device_count": memberCount,
	})
}

// HandlePreviewDynamicGroupRules previews which active devices match a set of rules.
// POST /api/groups/preview-rules
func (h *Handler) HandlePreviewDynamicGroupRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MatchMode    string                    `json:"match_mode"`
		DynamicRules []policy.DynamicGroupRule `json:"dynamic_rules"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	matched, err := policy.PreviewDynamicGroupRules(h.db, body.MatchMode, body.DynamicRules)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	type previewDevice struct {
		ID         string `json:"id"`
		DeviceName string `json:"device_name"`
		OSVersion  string `json:"os_version"`
		Model      string `json:"model"`
	}
	out := make([]previewDevice, 0, len(matched))
	for _, m := range matched {
		out = append(out, previewDevice{
			ID:         m.DeviceID,
			DeviceName: m.Hostname,
			OSVersion:  m.OSVersion,
			Model:      strings.TrimSpace(m.Manufacturer + " " + m.Model),
		})
	}
	respondOK(w, map[string]interface{}{
		"match_count": len(out),
		"devices":     out,
	})
}

// HandleDeleteGroup removes a group (devices are not deleted, just ungrouped).
// DELETE /api/groups/{id}
func (h *Handler) HandleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	// Capture members BEFORE deletion so their now-removed policies are retracted.
	affected := h.queryDeviceIDs(r, `SELECT device_id FROM device_group_members WHERE group_id = ?`, id)

	res, err := h.db.ExecContext(r.Context(), db.Rebind(`DELETE FROM device_groups WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete group")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "group not found")
		return
	}

	go policyOps.ResyncDevices(h.db, affected)

	h.audit(r, actor, "group.delete", "group", id, "")
	slog.Info("group deleted", "group_id", id, "actor", actor, "affected_devices", len(affected))
	respondOK(w, map[string]string{"status": "deleted"})
}

// HandleAssignDeviceToGroup adds or removes devices from a static group.
// PUT /api/groups/{id}/devices
// Body: {"device_ids": ["id1","id2"], "action": "add"|"remove"}
func (h *Handler) HandleAssignDeviceToGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		DeviceIDs []string `json:"device_ids"`
		Action    string   `json:"action"` // "add" or "remove"
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Action != "add" && body.Action != "remove" {
		respondErr(w, http.StatusBadRequest, `action must be "add" or "remove"`)
		return
	}

	// Verify group exists and is static (not rule-managed)
	var isDyn int
	err := h.db.QueryRowContext(r.Context(),
		db.Rebind(`SELECT COALESCE(is_dynamic, 0) FROM device_groups WHERE id = ?`), groupID,
	).Scan(&isDyn)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to verify group")
		return
	}
	if isDyn == 1 {
		respondErr(w, http.StatusConflict, "dynamic smart group membership is managed automatically by rules")
		return
	}

	var affected int
	for _, deviceID := range body.DeviceIDs {
		var err error
		if body.Action == "add" {
			_, err = h.db.ExecContext(r.Context(),
				db.Rebind(`INSERT INTO device_group_members (device_id, group_id) VALUES (?, ?) ON CONFLICT (device_id, group_id) DO NOTHING`),
				deviceID, groupID,
			)
		} else {
			_, err = h.db.ExecContext(r.Context(),
				db.Rebind(`DELETE FROM device_group_members WHERE device_id = ? AND group_id = ?`),
				deviceID, groupID,
			)
		}
		if err != nil {
			slog.Error("api: modifying group membership", "device_id", deviceID, "err", err)
			continue
		}
		affected++
	}

	h.audit(r, actor, "group.members."+body.Action, "group", groupID,
		fmt.Sprintf(`{"device_count":%d}`, affected))

	// Adding devices applies the group's profiles; removing them retracts those
	// settings from the removed devices.
	if body.Action == "add" {
		go policyOps.ApplyGroup(h.db, groupID)
	} else {
		go policyOps.ResyncDevices(h.db, body.DeviceIDs)
	}

	respondOK(w, map[string]interface{}{"status": "ok", "affected": affected})
}

// HandleAssignProfileToGroup links or unlinks profiles from a group.
// PUT /api/groups/{id}/profiles
// Body: {"profile_ids": ["id1"], "action": "add"|"remove"}
func (h *Handler) HandleAssignProfileToGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		ProfileIDs []string `json:"profile_ids"`
		Action     string   `json:"action"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Action != "add" && body.Action != "remove" {
		respondErr(w, http.StatusBadRequest, `action must be "add" or "remove"`)
		return
	}

	for _, profileID := range body.ProfileIDs {
		var err error
		if body.Action == "add" {
			_, err = h.db.ExecContext(r.Context(),
				db.Rebind(`INSERT INTO group_profiles (group_id, profile_id) VALUES (?, ?) ON CONFLICT (group_id, profile_id) DO NOTHING`),
				groupID, profileID,
			)
		} else {
			_, err = h.db.ExecContext(r.Context(),
				db.Rebind(`DELETE FROM group_profiles WHERE group_id = ? AND profile_id = ?`),
				groupID, profileID,
			)
		}
		if err != nil {
			slog.Error("api: modifying group profiles", "profile_id", profileID, "err", err)
		}
	}

	h.audit(r, actor, "group.profiles."+body.Action, "group", groupID,
		fmt.Sprintf(`{"profile_count":%d}`, len(body.ProfileIDs)))

	// Re-apply (or retract on removal) policies for all devices in this group.
	// ApplyGroup re-resolves each device, which both applies new settings and
	// retracts ones no longer governed.
	go policyOps.ApplyGroup(h.db, groupID)

	respondOK(w, map[string]string{"status": "ok"})
}
