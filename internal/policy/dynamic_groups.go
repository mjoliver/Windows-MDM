package policy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// DynamicGroupRule defines a single attribute predicate for a Dynamic Smart Group.
type DynamicGroupRule struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// DeviceRuleSnapshot holds the telemetry & posture fields evaluated against
// Dynamic Smart Group rules.
type DeviceRuleSnapshot struct {
	DeviceID         string
	Hostname         string
	OSVersion        string
	OSBuild          string
	Manufacturer     string
	Model            string
	SerialNumber     string
	ComplianceStatus string
	SecureBoot       string // "true", "false", "unknown"
	BitLocker        string // "true", "false", "unknown"
}

var allowedRuleFields = map[string]bool{
	"hostname":          true,
	"os_version":        true,
	"os_build":          true,
	"manufacturer":      true,
	"model":             true,
	"serial_number":     true,
	"compliance_status": true,
	"secure_boot":       true,
	"bitlocker":         true,
}

var allowedRuleOperators = map[string]bool{
	"equals":      true,
	"not_equals":  true,
	"contains":    true,
	"starts_with": true,
	"ends_with":   true,
}

// ValidateDynamicGroupConfig normalizes and validates match_mode and dynamic rules.
func ValidateDynamicGroupConfig(matchMode string, rules []DynamicGroupRule) (string, []DynamicGroupRule, error) {
	mode := strings.ToLower(strings.TrimSpace(matchMode))
	if mode == "" {
		mode = "all"
	}
	if mode != "all" && mode != "any" {
		return "", nil, errors.New(`match_mode must be "all" or "any"`)
	}
	if len(rules) == 0 {
		return "", nil, errors.New("dynamic smart groups require at least one rule")
	}
	if len(rules) > 25 {
		return "", nil, errors.New("dynamic smart groups support at most 25 rules")
	}

	cleaned := make([]DynamicGroupRule, 0, len(rules))
	for i, r := range rules {
		f := strings.ToLower(strings.TrimSpace(r.Field))
		if f == "device_name" {
			f = "hostname"
		}
		op := strings.ToLower(strings.TrimSpace(r.Operator))
		val := strings.TrimSpace(r.Value)

		if !allowedRuleFields[f] {
			return "", nil, fmt.Errorf("rule %d: unsupported field %q", i+1, r.Field)
		}
		if !allowedRuleOperators[op] {
			return "", nil, fmt.Errorf("rule %d: unsupported operator %q", i+1, r.Operator)
		}
		if val == "" {
			return "", nil, fmt.Errorf("rule %d: value is required", i+1)
		}
		cleaned = append(cleaned, DynamicGroupRule{
			Field:    f,
			Operator: op,
			Value:    val,
		})
	}
	return mode, cleaned, nil
}

func fieldValue(snap DeviceRuleSnapshot, field string) string {
	switch field {
	case "hostname":
		return snap.Hostname
	case "os_version":
		return snap.OSVersion
	case "os_build":
		return snap.OSBuild
	case "manufacturer":
		return snap.Manufacturer
	case "model":
		return snap.Model
	case "serial_number":
		return snap.SerialNumber
	case "compliance_status":
		return snap.ComplianceStatus
	case "secure_boot":
		return snap.SecureBoot
	case "bitlocker":
		return snap.BitLocker
	default:
		return ""
	}
}

func canonicalBoolToken(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "enabled", "on":
		return "true"
	case "0", "false", "no", "disabled", "off":
		return "false"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func evalSingleRule(snap DeviceRuleSnapshot, r DynamicGroupRule) bool {
	actual := strings.ToLower(strings.TrimSpace(fieldValue(snap, r.Field)))
	target := strings.ToLower(strings.TrimSpace(r.Value))
	if r.Field == "secure_boot" || r.Field == "bitlocker" {
		target = canonicalBoolToken(target)
	}

	switch r.Operator {
	case "equals":
		return actual == target
	case "not_equals":
		return actual != target
	case "contains":
		return target != "" && strings.Contains(actual, target)
	case "starts_with":
		return target != "" && strings.HasPrefix(actual, target)
	case "ends_with":
		return target != "" && strings.HasSuffix(actual, target)
	default:
		return false
	}
}

// EvaluateDynamicGroupRules returns true when snap satisfies rules under matchMode ("all" or "any").
func EvaluateDynamicGroupRules(snap DeviceRuleSnapshot, matchMode string, rules []DynamicGroupRule) bool {
	if len(rules) == 0 {
		return false
	}
	isAny := strings.EqualFold(strings.TrimSpace(matchMode), "any")
	for _, r := range rules {
		matched := evalSingleRule(snap, r)
		if isAny && matched {
			return true
		}
		if !isAny && !matched {
			return false
		}
	}
	return !isAny
}

func loadDeviceRuleSnapshots(db *sql.DB, onlyDeviceID string) ([]DeviceRuleSnapshot, error) {
	query := `
		SELECT d.id, COALESCE(d.device_name,''), COALESCE(d.os_version,''),
		       COALESCE(d.os_build,''), COALESCE(d.manufacturer,''), COALESCE(d.model,''),
		       COALESCE(d.serial_number,''), COALESCE(d.compliance_status,'unknown'),
		       dp.secure_boot_state, dp.encryption_status
		FROM devices d
		LEFT JOIN device_posture dp ON dp.device_id = d.id
		WHERE d.is_active = 1
	`
	var args []interface{}
	if onlyDeviceID != "" {
		query += ` AND d.id = ?`
		args = append(args, onlyDeviceID)
	}
	query += ` ORDER BY d.device_name ASC`

	rows, err := db.Query(dbpkg.Rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeviceRuleSnapshot
	for rows.Next() {
		var s DeviceRuleSnapshot
		var sb, enc sql.NullInt64
		if err := rows.Scan(
			&s.DeviceID, &s.Hostname, &s.OSVersion,
			&s.OSBuild, &s.Manufacturer, &s.Model,
			&s.SerialNumber, &s.ComplianceStatus,
			&sb, &enc,
		); err != nil {
			continue
		}
		s.SecureBoot = postureBoolState(sb, true)
		s.BitLocker = postureBoolState(enc, false)
		out = append(out, s)
	}
	return out, rows.Err()
}

func postureBoolState(v sql.NullInt64, isSecureBoot bool) string {
	if !v.Valid {
		return "unknown"
	}
	if isSecureBoot {
		if v.Int64 == 1 {
			return "true"
		}
		return "false"
	}
	// BitLocker/Status/DeviceEncryptionStatus: 0 = Compliant/Encrypted, non-zero = Violation bitmask.
	if v.Int64 == 0 {
		return "true"
	}
	return "false"
}

// PreviewDynamicGroupRules evaluates candidate rules against all active devices
// without mutating database state.
func PreviewDynamicGroupRules(db *sql.DB, matchMode string, rules []DynamicGroupRule) ([]DeviceRuleSnapshot, error) {
	mode, cleaned, err := ValidateDynamicGroupConfig(matchMode, rules)
	if err != nil {
		return nil, err
	}
	snaps, err := loadDeviceRuleSnapshots(db, "")
	if err != nil {
		return nil, err
	}
	var matched []DeviceRuleSnapshot
	for _, s := range snaps {
		if EvaluateDynamicGroupRules(s, mode, cleaned) {
			matched = append(matched, s)
		}
	}
	return matched, nil
}

// ReconcileDynamicGroup evaluates a single dynamic group's rules against all
// active devices, updates device_group_members, and reconciles policies for any
// newly-added or removed devices.
func ReconcileDynamicGroup(db *sql.DB, groupID string) (added int, removed int) {
	var isDyn int
	var matchMode, rulesJSON string
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT COALESCE(is_dynamic, 0), COALESCE(match_mode, 'all'), COALESCE(dynamic_rules_json, '[]')
		FROM device_groups WHERE id = ?
	`), groupID).Scan(&isDyn, &matchMode, &rulesJSON)
	if err != nil || isDyn == 0 {
		return 0, 0
	}

	var rules []DynamicGroupRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil || len(rules) == 0 {
		return 0, 0
	}

	snaps, err := loadDeviceRuleSnapshots(db, "")
	if err != nil {
		slog.Error("policy: loading devices for dynamic group", "group_id", groupID, "err", err)
		return 0, 0
	}

	current := make(map[string]bool)
	mRows, err := db.Query(dbpkg.Rebind(`SELECT device_id FROM device_group_members WHERE group_id = ?`), groupID)
	if err == nil {
		for mRows.Next() {
			var devID string
			if mRows.Scan(&devID) == nil {
				current[devID] = true
			}
		}
		mRows.Close()
	}

	desired := make(map[string]bool)
	for _, s := range snaps {
		if EvaluateDynamicGroupRules(s, matchMode, rules) {
			desired[s.DeviceID] = true
		}
	}

	var affected []string
	for devID := range desired {
		if !current[devID] {
			if _, err := db.Exec(dbpkg.Rebind(`
				INSERT INTO device_group_members (device_id, group_id) VALUES (?, ?)
				ON CONFLICT (device_id, group_id) DO NOTHING
			`), devID, groupID); err == nil {
				added++
				affected = append(affected, devID)
			}
		}
	}
	for devID := range current {
		if !desired[devID] {
			if _, err := db.Exec(dbpkg.Rebind(`
				DELETE FROM device_group_members WHERE device_id = ? AND group_id = ?
			`), devID, groupID); err == nil {
				removed++
				affected = append(affected, devID)
			}
		}
	}

	for _, devID := range affected {
		ApplyDevice(db, devID)
	}
	if added > 0 || removed > 0 {
		slog.Info("policy: reconciled dynamic smart group", "group_id", groupID, "added", added, "removed", removed)
	}
	return added, removed
}

// ReconcileDynamicGroupsForDevice evaluates a single device against all Dynamic
// Smart Groups and reconciles its policies if any group membership changed.
func ReconcileDynamicGroupsForDevice(db *sql.DB, deviceID string) int {
	snaps, err := loadDeviceRuleSnapshots(db, deviceID)
	if err != nil || len(snaps) == 0 {
		return 0
	}
	snap := snaps[0]

	rows, err := db.Query(dbpkg.Rebind(`
		SELECT id, COALESCE(match_mode, 'all'), COALESCE(dynamic_rules_json, '[]')
		FROM device_groups
		WHERE is_dynamic = 1
	`))
	if err != nil {
		return 0
	}
	type dynGroup struct {
		id        string
		matchMode string
		rules     []DynamicGroupRule
	}
	var groups []dynGroup
	for rows.Next() {
		var g dynGroup
		var raw string
		if rows.Scan(&g.id, &g.matchMode, &raw) == nil {
			if json.Unmarshal([]byte(raw), &g.rules) == nil && len(g.rules) > 0 {
				groups = append(groups, g)
			}
		}
	}
	rows.Close()

	if len(groups) == 0 {
		return 0
	}

	current := make(map[string]bool)
	mRows, err := db.Query(dbpkg.Rebind(`SELECT group_id FROM device_group_members WHERE device_id = ?`), deviceID)
	if err == nil {
		for mRows.Next() {
			var gid string
			if mRows.Scan(&gid) == nil {
				current[gid] = true
			}
		}
		mRows.Close()
	}

	changed := 0
	for _, g := range groups {
		want := EvaluateDynamicGroupRules(snap, g.matchMode, g.rules)
		has := current[g.id]
		if want && !has {
			if _, err := db.Exec(dbpkg.Rebind(`
				INSERT INTO device_group_members (device_id, group_id) VALUES (?, ?)
				ON CONFLICT (device_id, group_id) DO NOTHING
			`), deviceID, g.id); err == nil {
				changed++
			}
		} else if !want && has {
			if _, err := db.Exec(dbpkg.Rebind(`
				DELETE FROM device_group_members WHERE device_id = ? AND group_id = ?
			`), deviceID, g.id); err == nil {
				changed++
			}
		}
	}

	if changed > 0 {
		ApplyDevice(db, deviceID)
		slog.Info("policy: dynamic smart group membership updated on check-in", "device_id", deviceID, "groups_changed", changed)
	}
	return changed
}
