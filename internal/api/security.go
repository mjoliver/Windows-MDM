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
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/policy"
)

const defaultEndpointSecurityPolicyID = "default"

// EndpointSecurityPolicy represents fleet-wide Microsoft Defender Antivirus +
// Windows Defender Firewall baseline enforcement.
type EndpointSecurityPolicy struct {
	Enabled                 bool       `json:"enabled"`
	AllowRealtimeMonitoring bool       `json:"allow_realtime_monitoring"`
	AllowBehaviorMonitoring bool       `json:"allow_behavior_monitoring"`
	AllowCloudProtection    bool       `json:"allow_cloud_protection"`
	CloudBlockLevel         int        `json:"cloud_block_level"`
	PUAProtection           int        `json:"pua_protection"`
	EnableNetworkProtection int        `json:"enable_network_protection"`
	CheckSigsBeforeScan     bool       `json:"check_sigs_before_scan"`
	FirewallDomainEnabled   bool       `json:"firewall_domain_enabled"`
	FirewallPrivateEnabled  bool       `json:"firewall_private_enabled"`
	FirewallPublicEnabled   bool       `json:"firewall_public_enabled"`
	BlockInboundDomain      bool       `json:"block_inbound_domain"`
	BlockInboundPrivate     bool       `json:"block_inbound_private"`
	BlockInboundPublic      bool       `json:"block_inbound_public"`
	TargetAllDevices        bool       `json:"target_all_devices"`
	GroupIDs                []string   `json:"group_ids"`
	EnforcedDevices         int        `json:"enforced_devices"`
	CommandsQueued          int        `json:"commands_queued,omitempty"`
	UpdatedBy               string     `json:"updated_by"`
	UpdatedAt               *time.Time `json:"updated_at"`
}

// FirewallRule represents a custom Windows Firewall CSP rule provisioned via SyncML <Atomic>.
type FirewallRule struct {
	ID               string    `json:"id"`
	RuleKey          string    `json:"rule_key"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Direction        string    `json:"direction"`
	Action           int       `json:"action"`
	Protocol         int       `json:"protocol"`
	LocalPortRanges  string    `json:"local_port_ranges"`
	RemotePortRanges string    `json:"remote_port_ranges"`
	Profiles         int       `json:"profiles"`
	Enabled          bool      `json:"enabled"`
	TargetAllDevices bool      `json:"target_all_devices"`
	GroupIDs         []string  `json:"group_ids"`
	DeployedDevices  int       `json:"deployed_devices"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	CommandsQueued   int       `json:"commands_queued,omitempty"`
}

// DeviceSecurityState exposes per-device Defender/Firewall baseline & rule deployment status.
type DeviceSecurityState struct {
	DeviceID             string     `json:"device_id"`
	BaselineEnforced     bool       `json:"baseline_enforced"`
	LastDefenderAction   string     `json:"last_defender_action"`
	LastDefenderActionAt *time.Time `json:"last_defender_action_at"`
	DeployedRuleKeys     []string   `json:"deployed_rule_keys"`
	UpdatedAt            *time.Time `json:"updated_at"`
}

func (h *Handler) loadEndpointSecurityPolicy(r *http.Request) (EndpointSecurityPolicy, error) {
	pol := EndpointSecurityPolicy{
		Enabled:                 false,
		AllowRealtimeMonitoring: true,
		AllowBehaviorMonitoring: true,
		AllowCloudProtection:    true,
		CloudBlockLevel:         2,
		PUAProtection:           1,
		EnableNetworkProtection: 1,
		CheckSigsBeforeScan:     true,
		FirewallDomainEnabled:   true,
		FirewallPrivateEnabled:  true,
		FirewallPublicEnabled:   true,
		BlockInboundDomain:      true,
		BlockInboundPrivate:     true,
		BlockInboundPublic:      true,
		TargetAllDevices:        true,
		GroupIDs:                []string{},
	}

	var (
		enabled, rt, beh, cloud, sigs                 int
		fwDom, fwPriv, fwPub, blkDom, blkPriv, blkPub int
		targetAll                                     int
		updatedAt                                     time.Time
	)
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enabled,
		       allow_realtime_monitoring, allow_behavior_monitoring, allow_cloud_protection,
		       cloud_block_level, pua_protection, enable_network_protection, check_sigs_before_scan,
		       firewall_domain_enabled, firewall_private_enabled, firewall_public_enabled,
		       block_inbound_domain, block_inbound_private, block_inbound_public,
		       target_all_devices, updated_by, updated_at
		FROM endpoint_security_policies
		WHERE id = ?
	`), defaultEndpointSecurityPolicyID).Scan(
		&enabled,
		&rt, &beh, &cloud,
		&pol.CloudBlockLevel, &pol.PUAProtection, &pol.EnableNetworkProtection, &sigs,
		&fwDom, &fwPriv, &fwPub,
		&blkDom, &blkPriv, &blkPub,
		&targetAll, &pol.UpdatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pol, err
	}
	if err == nil {
		pol.Enabled = enabled != 0
		pol.AllowRealtimeMonitoring = rt != 0
		pol.AllowBehaviorMonitoring = beh != 0
		pol.AllowCloudProtection = cloud != 0
		pol.CheckSigsBeforeScan = sigs != 0
		pol.FirewallDomainEnabled = fwDom != 0
		pol.FirewallPrivateEnabled = fwPriv != 0
		pol.FirewallPublicEnabled = fwPub != 0
		pol.BlockInboundDomain = blkDom != 0
		pol.BlockInboundPrivate = blkPriv != 0
		pol.BlockInboundPublic = blkPub != 0
		pol.TargetAllDevices = targetAll != 0
		t := updatedAt
		pol.UpdatedAt = &t
	}

	gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_endpoint_security_policies WHERE policy_id = ? ORDER BY group_id ASC
	`), defaultEndpointSecurityPolicyID)
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
		FROM device_security_baseline_state ds
		JOIN devices d ON d.id = ds.device_id
		WHERE d.is_active = 1 AND ds.enforced = 1
	`).Scan(&pol.EnforcedDevices)

	return pol, nil
}

// HandleGetEndpointSecurityPolicy returns the fleet Defender + Firewall baseline policy.
// GET /api/security/policy
func (h *Handler) HandleGetEndpointSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.loadEndpointSecurityPolicy(r)
	if err != nil {
		slog.Error("api: loading endpoint security policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load endpoint security policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateEndpointSecurityPolicy saves the Defender + Firewall baseline policy
// and immediately reconciles all governed devices.
// PUT /api/security/policy
func (h *Handler) HandleUpdateEndpointSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Enabled                 bool     `json:"enabled"`
		AllowRealtimeMonitoring bool     `json:"allow_realtime_monitoring"`
		AllowBehaviorMonitoring bool     `json:"allow_behavior_monitoring"`
		AllowCloudProtection    bool     `json:"allow_cloud_protection"`
		CloudBlockLevel         int      `json:"cloud_block_level"`
		PUAProtection           int      `json:"pua_protection"`
		EnableNetworkProtection int      `json:"enable_network_protection"`
		CheckSigsBeforeScan     bool     `json:"check_sigs_before_scan"`
		FirewallDomainEnabled   bool     `json:"firewall_domain_enabled"`
		FirewallPrivateEnabled  bool     `json:"firewall_private_enabled"`
		FirewallPublicEnabled   bool     `json:"firewall_public_enabled"`
		BlockInboundDomain      bool     `json:"block_inbound_domain"`
		BlockInboundPrivate     bool     `json:"block_inbound_private"`
		BlockInboundPublic      bool     `json:"block_inbound_public"`
		TargetAllDevices        bool     `json:"target_all_devices"`
		GroupIDs                []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	if !mdm.ValidCloudBlockLevel(body.CloudBlockLevel) {
		respondErr(w, http.StatusBadRequest, "cloud_block_level must be 0, 2, 4, or 6")
		return
	}
	if body.PUAProtection < 0 || body.PUAProtection > 2 {
		respondErr(w, http.StatusBadRequest, "pua_protection must be 0, 1, or 2")
		return
	}
	if body.EnableNetworkProtection < 0 || body.EnableNetworkProtection > 2 {
		respondErr(w, http.StatusBadRequest, "enable_network_protection must be 0, 1, or 2")
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
		INSERT INTO endpoint_security_policies (
			id, enabled,
			allow_realtime_monitoring, allow_behavior_monitoring, allow_cloud_protection,
			cloud_block_level, pua_protection, enable_network_protection, check_sigs_before_scan,
			firewall_domain_enabled, firewall_private_enabled, firewall_public_enabled,
			block_inbound_domain, block_inbound_private, block_inbound_public,
			target_all_devices, updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			enabled                   = EXCLUDED.enabled,
			allow_realtime_monitoring = EXCLUDED.allow_realtime_monitoring,
			allow_behavior_monitoring = EXCLUDED.allow_behavior_monitoring,
			allow_cloud_protection    = EXCLUDED.allow_cloud_protection,
			cloud_block_level         = EXCLUDED.cloud_block_level,
			pua_protection            = EXCLUDED.pua_protection,
			enable_network_protection = EXCLUDED.enable_network_protection,
			check_sigs_before_scan    = EXCLUDED.check_sigs_before_scan,
			firewall_domain_enabled   = EXCLUDED.firewall_domain_enabled,
			firewall_private_enabled  = EXCLUDED.firewall_private_enabled,
			firewall_public_enabled   = EXCLUDED.firewall_public_enabled,
			block_inbound_domain      = EXCLUDED.block_inbound_domain,
			block_inbound_private     = EXCLUDED.block_inbound_private,
			block_inbound_public      = EXCLUDED.block_inbound_public,
			target_all_devices        = EXCLUDED.target_all_devices,
			updated_by                = EXCLUDED.updated_by,
			updated_at                = EXCLUDED.updated_at
	`),
		defaultEndpointSecurityPolicyID, boolToSQLInt(body.Enabled),
		boolToSQLInt(body.AllowRealtimeMonitoring), boolToSQLInt(body.AllowBehaviorMonitoring), boolToSQLInt(body.AllowCloudProtection),
		body.CloudBlockLevel, body.PUAProtection, body.EnableNetworkProtection, boolToSQLInt(body.CheckSigsBeforeScan),
		boolToSQLInt(body.FirewallDomainEnabled), boolToSQLInt(body.FirewallPrivateEnabled), boolToSQLInt(body.FirewallPublicEnabled),
		boolToSQLInt(body.BlockInboundDomain), boolToSQLInt(body.BlockInboundPrivate), boolToSQLInt(body.BlockInboundPublic),
		boolToSQLInt(body.TargetAllDevices), actor, now,
	)
	if err != nil {
		slog.Error("api: saving endpoint security policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save endpoint security policy")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM group_endpoint_security_policies WHERE policy_id = ?
	`), defaultEndpointSecurityPolicyID); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update security group assignments")
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
			INSERT INTO group_endpoint_security_policies (group_id, policy_id) VALUES (?, ?)
		`), gid, defaultEndpointSecurityPolicyID); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit endpoint security policy")
		return
	}

	enforced, queued := policy.ReconcileEndpointSecurityFleet(h.db)

	h.audit(r, actor, "security.update_policy", "endpoint_security_policy", defaultEndpointSecurityPolicyID,
		fmt.Sprintf(`{"enabled":%t,"cloud_block_level":%d,"enforced_devices":%d,"commands_queued":%d}`,
			body.Enabled, body.CloudBlockLevel, enforced, queued))

	pol, err := h.loadEndpointSecurityPolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload endpoint security policy")
		return
	}
	pol.CommandsQueued = queued
	respondOK(w, pol)
}

// HandleListFirewallRules returns all configured custom Firewall CSP rules.
// GET /api/security/firewall-rules
func (h *Handler) HandleListFirewallRules(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT
			fr.id, fr.rule_key, fr.name, fr.description, fr.direction, fr.action,
			fr.protocol, fr.local_port_ranges, fr.remote_port_ranges, fr.profiles,
			fr.enabled, fr.target_all_devices, fr.created_by, fr.created_at, fr.updated_at,
			(SELECT COUNT(*) FROM device_firewall_rule_state dfrs
			 JOIN devices d ON d.id = dfrs.device_id
			 WHERE dfrs.rule_key = fr.rule_key AND d.is_active = 1) AS deployed_devices
		FROM firewall_rules fr
		ORDER BY fr.created_at DESC
	`)
	if err != nil {
		slog.Error("api: listing firewall rules", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list firewall rules")
		return
	}
	defer rows.Close()

	rules := []FirewallRule{}
	for rows.Next() {
		var fr FirewallRule
		var en, targetAll int
		if err := rows.Scan(
			&fr.ID, &fr.RuleKey, &fr.Name, &fr.Description, &fr.Direction, &fr.Action,
			&fr.Protocol, &fr.LocalPortRanges, &fr.RemotePortRanges, &fr.Profiles,
			&en, &targetAll, &fr.CreatedBy, &fr.CreatedAt, &fr.UpdatedAt, &fr.DeployedDevices,
		); err != nil {
			continue
		}
		fr.Enabled = en != 0
		fr.TargetAllDevices = targetAll != 0
		fr.GroupIDs = []string{}
		rules = append(rules, fr)
	}

	for i := range rules {
		gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
			SELECT group_id FROM group_firewall_rules WHERE rule_id = ? ORDER BY group_id ASC
		`), rules[i].ID)
		if err == nil {
			for gRows.Next() {
				var gid string
				if gRows.Scan(&gid) == nil {
					rules[i].GroupIDs = append(rules[i].GroupIDs, gid)
				}
			}
			gRows.Close()
		}
	}

	respondOK(w, rules)
}

// HandleCreateFirewallRule creates a custom inbound/outbound Windows Firewall CSP rule
// and deploys it atomically (<Atomic>) to assigned devices.
// POST /api/security/firewall-rules
func (h *Handler) HandleCreateFirewallRule(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Name             string   `json:"name"`
		RuleKey          string   `json:"rule_key"`
		Description      string   `json:"description"`
		Direction        string   `json:"direction"`
		Action           int      `json:"action"`
		Protocol         int      `json:"protocol"`
		LocalPortRanges  string   `json:"local_port_ranges"`
		RemotePortRanges string   `json:"remote_port_ranges"`
		Profiles         int      `json:"profiles"`
		Enabled          *bool    `json:"enabled"`
		TargetAllDevices *bool    `json:"target_all_devices"`
		GroupIDs         []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}
	ruleKey := strings.TrimSpace(body.RuleKey)
	if ruleKey == "" {
		ruleKey = mdm.SanitizeFirewallRuleKey(name)
	}
	dir := strings.ToUpper(strings.TrimSpace(body.Direction))
	if dir == "" {
		dir = "IN"
	}
	if dir != "IN" && dir != "OUT" {
		respondErr(w, http.StatusBadRequest, "direction must be IN or OUT")
		return
	}
	if body.Action != 0 && body.Action != 1 {
		respondErr(w, http.StatusBadRequest, "action must be 0 (Block) or 1 (Allow)")
		return
	}
	proto := body.Protocol
	if proto == 0 {
		proto = 256 // Any
	}
	if proto != 6 && proto != 17 && proto != 1 && proto != 256 {
		respondErr(w, http.StatusBadRequest, "protocol must be 6 (TCP), 17 (UDP), 1 (ICMPv4), or 256 (Any)")
		return
	}
	profiles := body.Profiles
	if profiles == 0 {
		profiles = 7
	}
	if profiles < 1 || profiles > 7 {
		respondErr(w, http.StatusBadRequest, "profiles bitmask must be between 1 and 7")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	targetAll := true
	if body.TargetAllDevices != nil {
		targetAll = *body.TargetAllDevices
	}

	spec := mdm.FirewallRuleSpec{
		RuleKey:          ruleKey,
		Name:             name,
		Description:      strings.TrimSpace(body.Description),
		Direction:        dir,
		Action:           body.Action,
		Protocol:         proto,
		LocalPortRanges:  strings.TrimSpace(body.LocalPortRanges),
		RemotePortRanges: strings.TrimSpace(body.RemotePortRanges),
		Profiles:         profiles,
		Enabled:          enabled,
	}
	if _, err := mdm.BuildFirewallRuleAtomicOps(spec); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var dup int
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT COUNT(*) FROM firewall_rules WHERE rule_key = ?`), ruleKey).Scan(&dup)
	if dup > 0 {
		ruleKey = ruleKey + "-" + uuid.NewString()[:6]
		spec.RuleKey = ruleKey
	}

	id := uuid.NewString()
	now := time.Now().UTC()

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO firewall_rules (
			id, rule_key, name, description, direction, action, protocol,
			local_port_ranges, remote_port_ranges, profiles, enabled, target_all_devices,
			created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		id, spec.RuleKey, spec.Name, spec.Description, spec.Direction, spec.Action, spec.Protocol,
		spec.LocalPortRanges, spec.RemotePortRanges, spec.Profiles, boolToSQLInt(spec.Enabled),
		boolToSQLInt(targetAll), actor, now, now,
	)
	if err != nil {
		slog.Error("api: inserting firewall rule", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create firewall rule")
		return
	}

	seen := make(map[string]bool)
	groupIDs := []string{}
	for _, rawGID := range body.GroupIDs {
		gid := strings.TrimSpace(rawGID)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_firewall_rules (group_id, rule_id) VALUES (?, ?)
		`), gid, id); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
		groupIDs = append(groupIDs, gid)
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit firewall rule")
		return
	}

	_, queued := policy.ReconcileEndpointSecurityFleet(h.db)

	h.audit(r, actor, "security.firewall_rule_create", "firewall_rule", id,
		fmt.Sprintf(`{"rule_key":%q,"direction":%q,"action":%d,"commands_queued":%d}`,
			spec.RuleKey, spec.Direction, spec.Action, queued))

	respondCreated(w, FirewallRule{
		ID:               id,
		RuleKey:          spec.RuleKey,
		Name:             spec.Name,
		Description:      spec.Description,
		Direction:        spec.Direction,
		Action:           spec.Action,
		Protocol:         spec.Protocol,
		LocalPortRanges:  spec.LocalPortRanges,
		RemotePortRanges: spec.RemotePortRanges,
		Profiles:         spec.Profiles,
		Enabled:          spec.Enabled,
		TargetAllDevices: targetAll,
		GroupIDs:         groupIDs,
		CreatedBy:        actor,
		CreatedAt:        now,
		UpdatedAt:        now,
		CommandsQueued:   queued,
	})
}

// HandleDeleteFirewallRule deletes a custom firewall rule and queues <Delete>
// on ./Vendor/MSFT/Firewall/MdmStore/FirewallRules/{RuleKey} for every device that received it.
// DELETE /api/security/firewall-rules/{id}
func (h *Handler) HandleDeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var ruleKey string
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT rule_key FROM firewall_rules WHERE id = ?`), id).Scan(&ruleKey)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "firewall rule not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}

	if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM firewall_rules WHERE id = ?`), id); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete firewall rule")
		return
	}

	_, queued := policy.ReconcileEndpointSecurityFleet(h.db)

	h.audit(r, actor, "security.firewall_rule_delete", "firewall_rule", id,
		fmt.Sprintf(`{"rule_key":%q,"commands_queued":%d}`, ruleKey, queued))

	respondOK(w, map[string]interface{}{
		"deleted":         true,
		"rule_key":        ruleKey,
		"commands_queued": queued,
	})
}

// HandleGetDeviceSecurity returns Defender/Firewall baseline & custom rule state for one device.
// GET /api/devices/{id}/security
func (h *Handler) HandleGetDeviceSecurity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	state := DeviceSecurityState{
		DeviceID:         id,
		DeployedRuleKeys: []string{},
	}

	var enforced int
	var lastActionAt, updatedAt sql.NullTime
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enforced, last_defender_action, last_defender_action_at, updated_at
		FROM device_security_baseline_state
		WHERE device_id = ?
	`), id).Scan(&enforced, &state.LastDefenderAction, &lastActionAt, &updatedAt)
	if err == nil {
		state.BaselineEnforced = enforced != 0
		if lastActionAt.Valid {
			t := lastActionAt.Time
			state.LastDefenderActionAt = &t
		}
		if updatedAt.Valid {
			t := updatedAt.Time
			state.UpdatedAt = &t
		}
	}

	rRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT rule_key FROM device_firewall_rule_state WHERE device_id = ? ORDER BY rule_key ASC
	`), id)
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var rk string
			if rRows.Scan(&rk) == nil {
				state.DeployedRuleKeys = append(state.DeployedRuleKeys, rk)
			}
		}
	}

	respondOK(w, state)
}

// HandleDefenderScanDevice queues an immediate Microsoft Defender Quick or Full scan on a device.
// POST /api/devices/{id}/defender/scan
func (h *Handler) HandleDefenderScanDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		ScanType string `json:"scan_type"`
	}
	if r.ContentLength > 0 {
		if !decodeBody(w, r, &body) {
			return
		}
	}
	scanType := strings.ToLower(strings.TrimSpace(body.ScanType))
	if scanType == "" {
		scanType = "quick"
	}
	if scanType != "quick" && scanType != "full" {
		respondErr(w, http.StatusBadRequest, "scan_type must be 'quick' or 'full'")
		return
	}

	queued, err := mdm.EnqueueDefenderScan(h.db, id, scanType)
	if err != nil {
		slog.Error("api: queueing defender scan", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue Defender scan")
		return
	}

	actionLabel := "quick_scan"
	if scanType == "full" {
		actionLabel = "full_scan"
	}
	_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO device_security_baseline_state (device_id, enforced, last_defender_action, last_defender_action_at, updated_at)
		VALUES (?, 0, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (device_id) DO UPDATE SET
			last_defender_action    = EXCLUDED.last_defender_action,
			last_defender_action_at = CURRENT_TIMESTAMP,
			updated_at              = CURRENT_TIMESTAMP
	`), id, actionLabel)

	h.wakeDevice(id)
	h.audit(r, actor, "device.defender_scan", "device", id, fmt.Sprintf(`{"scan_type":%q}`, scanType))

	respondOK(w, map[string]interface{}{
		"status":          "queued",
		"scan_type":       scanType,
		"commands_queued": queued,
	})
}

// HandleDefenderUpdateSignatures queues an immediate Microsoft Defender security intelligence update.
// POST /api/devices/{id}/defender/update-signatures
func (h *Handler) HandleDefenderUpdateSignatures(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queued, err := mdm.EnqueueDefenderSignatureUpdate(h.db, id)
	if err != nil {
		slog.Error("api: queueing defender signature update", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue Defender signature update")
		return
	}

	_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO device_security_baseline_state (device_id, enforced, last_defender_action, last_defender_action_at, updated_at)
		VALUES (?, 0, 'update_signatures', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (device_id) DO UPDATE SET
			last_defender_action    = 'update_signatures',
			last_defender_action_at = CURRENT_TIMESTAMP,
			updated_at              = CURRENT_TIMESTAMP
	`), id)

	h.wakeDevice(id)
	h.audit(r, actor, "device.defender_update_signatures", "device", id, "")

	respondOK(w, map[string]interface{}{
		"status":          "queued",
		"commands_queued": queued,
	})
}
