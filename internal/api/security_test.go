package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestEndpointSecurityPolicyFirewallRulesAndDefenderActions(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-SEC-API-1")
	h := NewHandler(database.DB)

	// 1. Enable Defender + Firewall baseline across fleet
	wPut := httptest.NewRecorder()
	h.HandleUpdateEndpointSecurityPolicy(wPut, withDeviceAndKeyRoute("PUT", "/api/security/policy", `{
		"enabled": true,
		"allow_realtime_monitoring": true,
		"allow_behavior_monitoring": true,
		"allow_cloud_protection": true,
		"cloud_block_level": 2,
		"pua_protection": 1,
		"enable_network_protection": 1,
		"check_sigs_before_scan": true,
		"firewall_domain_enabled": true,
		"firewall_private_enabled": true,
		"firewall_public_enabled": true,
		"block_inbound_domain": true,
		"block_inbound_private": true,
		"block_inbound_public": true,
		"target_all_devices": true,
		"group_ids": []
	}`, "", "", "admin@lab.local"))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/security/policy: want 200, got %d body=%s", wPut.Code, wPut.Body.String())
	}
	var pol EndpointSecurityPolicy
	if err := json.Unmarshal(wPut.Body.Bytes(), &pol); err != nil {
		t.Fatal(err)
	}
	if !pol.Enabled || pol.EnforcedDevices != 1 || pol.CommandsQueued == 0 {
		t.Fatalf("unexpected security policy response: %+v", pol)
	}

	// 2. Create custom inbound Firewall CSP rule (Block TCP 3389)
	wCreate := httptest.NewRecorder()
	h.HandleCreateFirewallRule(wCreate, withDeviceAndKeyRoute("POST", "/api/security/firewall-rules", `{
		"name": "Block RDP Public",
		"direction": "IN",
		"action": 0,
		"protocol": 6,
		"local_port_ranges": "3389",
		"profiles": 4
	}`, "", "", "admin@lab.local"))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("POST /api/security/firewall-rules: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var rule FirewallRule
	if err := json.Unmarshal(wCreate.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.RuleKey != "Block-RDP-Public" || rule.CommandsQueued == 0 {
		t.Fatalf("unexpected created firewall rule: %+v", rule)
	}

	// 3. Trigger Microsoft Defender Quick Scan & Signature Update on device
	wScan := httptest.NewRecorder()
	h.HandleDefenderScanDevice(wScan, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/defender/scan", `{"scan_type":"quick"}`, devID, "", "admin@lab.local"))
	if wScan.Code != http.StatusOK {
		t.Fatalf("POST defender/scan: want 200, got %d body=%s", wScan.Code, wScan.Body.String())
	}

	wSig := httptest.NewRecorder()
	h.HandleDefenderUpdateSignatures(wSig, withDeviceAndKeyRoute("POST", "/api/devices/"+devID+"/defender/update-signatures", "", devID, "", "admin@lab.local"))
	if wSig.Code != http.StatusOK {
		t.Fatalf("POST defender/update-signatures: want 200, got %d body=%s", wSig.Code, wSig.Body.String())
	}

	// 4. Inspect per-device security state
	wDevSec := httptest.NewRecorder()
	h.HandleGetDeviceSecurity(wDevSec, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/security", "", devID, "", "admin@lab.local"))
	if wDevSec.Code != http.StatusOK {
		t.Fatalf("GET device security: want 200, got %d", wDevSec.Code)
	}
	var devSec DeviceSecurityState
	if err := json.Unmarshal(wDevSec.Body.Bytes(), &devSec); err != nil {
		t.Fatal(err)
	}
	if !devSec.BaselineEnforced || len(devSec.DeployedRuleKeys) != 1 || devSec.LastDefenderAction != "update_signatures" {
		t.Fatalf("unexpected device security state: %+v", devSec)
	}

	// 5. Delete custom firewall rule -> verify <Delete> queued & state cleaned up
	wDel := httptest.NewRecorder()
	h.HandleDeleteFirewallRule(wDel, withDeviceAndKeyRoute("DELETE", "/api/security/firewall-rules/"+rule.ID, "", rule.ID, "", "admin@lab.local"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("DELETE firewall rule: want 200, got %d body=%s", wDel.Code, wDel.Body.String())
	}

	var auditCount int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE user_email = 'admin@lab.local' AND action LIKE 'security.%'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount < 3 {
		t.Fatalf("expected >=3 security audit_log entries, got %d", auditCount)
	}
}
