package policy

import (
	"database/sql"
	"errors"
	"log/slog"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

const defaultEndpointSecurityPolicyID = "default"

type storedEndpointSecurityPolicy struct {
	enabled          bool
	targetAllDevices bool
	spec             mdm.EndpointSecuritySpec
}

func loadStoredEndpointSecurityPolicy(db *sql.DB) (*storedEndpointSecurityPolicy, error) {
	var (
		enabled, rt, beh, cloud, sigs                 int
		fwDom, fwPriv, fwPub, blkDom, blkPriv, blkPub int
		targetAll                                     int
		cbl, pua, netProt                             int
	)
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT enabled,
		       allow_realtime_monitoring, allow_behavior_monitoring, allow_cloud_protection,
		       cloud_block_level, pua_protection, enable_network_protection, check_sigs_before_scan,
		       firewall_domain_enabled, firewall_private_enabled, firewall_public_enabled,
		       block_inbound_domain, block_inbound_private, block_inbound_public,
		       target_all_devices
		FROM endpoint_security_policies
		WHERE id = ?
	`), defaultEndpointSecurityPolicyID).Scan(
		&enabled,
		&rt, &beh, &cloud,
		&cbl, &pua, &netProt, &sigs,
		&fwDom, &fwPriv, &fwPub,
		&blkDom, &blkPriv, &blkPub,
		&targetAll,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &storedEndpointSecurityPolicy{
		enabled:          enabled != 0,
		targetAllDevices: targetAll != 0,
		spec: mdm.EndpointSecuritySpec{
			AllowRealtimeMonitoring: rt != 0,
			AllowBehaviorMonitoring: beh != 0,
			AllowCloudProtection:    cloud != 0,
			CloudBlockLevel:         cbl,
			PUAProtection:           pua,
			EnableNetworkProtection: netProt,
			CheckSigsBeforeScan:     sigs != 0,
			FirewallDomainEnabled:   fwDom != 0,
			FirewallPrivateEnabled:  fwPriv != 0,
			FirewallPublicEnabled:   fwPub != 0,
			BlockInboundDomain:      blkDom != 0,
			BlockInboundPrivate:     blkPriv != 0,
			BlockInboundPublic:      blkPub != 0,
		},
	}, nil
}

func deviceGovernedByEndpointSecurity(db *sql.DB, deviceID string, pol *storedEndpointSecurityPolicy) bool {
	if pol == nil || !pol.enabled {
		return false
	}
	if pol.targetAllDevices {
		return true
	}
	var matched int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT COUNT(*)
		FROM device_group_members dgm
		JOIN group_endpoint_security_policies ges ON ges.group_id = dgm.group_id
		WHERE dgm.device_id = ? AND ges.policy_id = ?
	`), deviceID, defaultEndpointSecurityPolicyID).Scan(&matched)
	return err == nil && matched > 0
}

// ReconcileEndpointSecurityDevice applies or retracts Microsoft Defender + Firewall
// security baseline CSPs and custom FirewallRules for a single device.
func ReconcileEndpointSecurityDevice(db *sql.DB, deviceID string) int {
	var totalQueued int

	pol, err := loadStoredEndpointSecurityPolicy(db)
	if err == nil {
		var prevEnforced int
		_ = db.QueryRow(dbpkg.Rebind(`
			SELECT enforced FROM device_security_baseline_state WHERE device_id = ?
		`), deviceID).Scan(&prevEnforced)

		if deviceGovernedByEndpointSecurity(db, deviceID, pol) {
			q, qerr := mdm.EnqueueEndpointSecurityBaseline(db, deviceID, pol.spec)
			if qerr != nil {
				slog.Error("policy: queueing endpoint security baseline", "device_id", deviceID, "err", qerr)
			}
			totalQueued += q
			_, _ = db.Exec(dbpkg.Rebind(`
				INSERT INTO device_security_baseline_state (device_id, enforced, updated_at)
				VALUES (?, 1, CURRENT_TIMESTAMP)
				ON CONFLICT (device_id) DO UPDATE SET enforced = 1, updated_at = CURRENT_TIMESTAMP
			`), deviceID)
		} else if prevEnforced != 0 {
			q, qerr := mdm.RetractEndpointSecurityBaseline(db, deviceID)
			if qerr != nil {
				slog.Error("policy: retracting endpoint security baseline", "device_id", deviceID, "err", qerr)
			}
			totalQueued += q
			_, _ = db.Exec(dbpkg.Rebind(`
				UPDATE device_security_baseline_state SET enforced = 0, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?
			`), deviceID)
		}
	}

	totalQueued += ReconcileFirewallRulesDevice(db, deviceID, false)
	return totalQueued
}

// ReconcileFirewallRulesDevice ensures custom FirewallRules assigned to deviceID
// are deployed via <Atomic> SyncML and any unassigned rules are deleted.
func ReconcileFirewallRulesDevice(db *sql.DB, deviceID string, forceReplace bool) int {
	deployed := make(map[string]bool)
	dRows, err := db.Query(dbpkg.Rebind(`SELECT rule_key FROM device_firewall_rule_state WHERE device_id = ?`), deviceID)
	if err == nil {
		for dRows.Next() {
			var rk string
			if dRows.Scan(&rk) == nil && rk != "" {
				deployed[rk] = true
			}
		}
		dRows.Close()
	}

	rRows, err := db.Query(dbpkg.Rebind(`
		SELECT DISTINCT
			fr.rule_key, fr.name, fr.description, fr.direction, fr.action,
			fr.protocol, fr.local_port_ranges, fr.remote_port_ranges, fr.profiles, fr.enabled
		FROM firewall_rules fr
		LEFT JOIN group_firewall_rules gfr ON gfr.rule_id = fr.id
		LEFT JOIN device_group_members dgm ON dgm.group_id = gfr.group_id AND dgm.device_id = ?
		WHERE fr.target_all_devices = 1 OR dgm.device_id IS NOT NULL
	`), deviceID)
	if err != nil {
		return 0
	}
	var desiredSpecs []mdm.FirewallRuleSpec
	desiredMap := make(map[string]bool)
	for rRows.Next() {
		var sp mdm.FirewallRuleSpec
		var en int
		if rRows.Scan(
			&sp.RuleKey, &sp.Name, &sp.Description, &sp.Direction, &sp.Action,
			&sp.Protocol, &sp.LocalPortRanges, &sp.RemotePortRanges, &sp.Profiles, &en,
		) == nil {
			sp.Enabled = en != 0
			desiredSpecs = append(desiredSpecs, sp)
			desiredMap[sp.RuleKey] = true
		}
	}
	rRows.Close()

	var queued int
	for _, sp := range desiredSpecs {
		already := deployed[sp.RuleKey]
		if already && !forceReplace {
			continue
		}
		q, qerr := mdm.EnqueueFirewallRule(db, deviceID, sp, already)
		if qerr != nil {
			slog.Error("policy: queueing firewall rule", "device_id", deviceID, "rule_key", sp.RuleKey, "err", qerr)
			continue
		}
		queued += q
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_firewall_rule_state (device_id, rule_key, updated_at)
			VALUES (?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id, rule_key) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
		`), deviceID, sp.RuleKey)
	}

	for rk := range deployed {
		if !desiredMap[rk] {
			if q, qerr := mdm.RetractFirewallRule(db, deviceID, rk); qerr == nil {
				queued += q
			}
			_, _ = db.Exec(dbpkg.Rebind(`
				DELETE FROM device_firewall_rule_state WHERE device_id = ? AND rule_key = ?
			`), deviceID, rk)
		}
	}
	return queued
}

// ReconcileEndpointSecurityFleet reconciles Defender/Firewall baselines and custom
// firewall rules across all active devices and triggers WNS wake-ups where needed.
func ReconcileEndpointSecurityFleet(db *sql.DB) (enforcedDevices int, commandsQueued int) {
	rows, err := db.Query(`SELECT id FROM devices WHERE is_active = 1`)
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

	pol, _ := loadStoredEndpointSecurityPolicy(db)
	for _, devID := range devIDs {
		if deviceGovernedByEndpointSecurity(db, devID, pol) {
			enforcedDevices++
		}
		q := ReconcileEndpointSecurityDevice(db, devID)
		if q > 0 {
			commandsQueued += q
			notifyWake(devID)
		}
	}
	return enforcedDevices, commandsQueued
}
