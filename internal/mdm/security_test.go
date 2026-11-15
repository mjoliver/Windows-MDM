package mdm

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestFirewallRuleAtomicSyncMLAndFormats(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-SEC-1")

	spec := FirewallRuleSpec{
		RuleKey:         SanitizeFirewallRuleKey("Allow HTTPS 8443 Inbound"),
		Name:            "Allow HTTPS 8443 Inbound",
		Description:     "Managed inbound HTTPS rule",
		Direction:       "IN",
		Action:          1, // Allow
		Protocol:        6, // TCP
		LocalPortRanges: "8443",
		Profiles:        7,
		Enabled:         true,
	}
	if spec.RuleKey != "Allow-HTTPS-8443-Inbound" {
		t.Fatalf("unexpected sanitized rule_key: %q", spec.RuleKey)
	}

	q, err := EnqueueFirewallRule(database.DB, devID, spec, false)
	if err != nil {
		t.Fatalf("EnqueueFirewallRule: %v", err)
	}
	if q != 1 {
		t.Fatalf("want 1 command queued, got %d", q)
	}

	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("loadPendingCommands: len=%d err=%v", len(pending), err)
	}
	if pending[0].CommandType != "Atomic" {
		t.Fatalf("want command_type=Atomic, got %q", pending[0].CommandType)
	}

	sess := &Session{NextCmdID: 1, CmdMap: map[string]int{}}
	cmds := buildSyncMLCommands(sess, pending)
	if len(cmds) != 1 {
		t.Fatalf("want 1 SyncML command, got %d", len(cmds))
	}

	doc := SyncML{
		SyncBody: SyncBody{
			Commands: cmds,
			Final:    &struct{}{},
		},
	}
	rawXML, err := xml.Marshal(doc)
	if err != nil {
		t.Fatalf("xml.Marshal SyncML Atomic: %v", err)
	}
	s := string(rawXML)

	if !strings.Contains(s, "<Atomic>") || !strings.Contains(s, "</Atomic>") {
		t.Fatalf("expected <Atomic> block in SyncML: %s", s)
	}
	// Verify LocalPortRanges "8443" uses <Format>chr</Format>, NOT int!
	if !strings.Contains(s, "LocalPortRanges</LocURI></Target><Meta><Format xmlns=\"syncml:metinf\">chr</Format>") {
		t.Fatalf("expected LocalPortRanges to use Format=chr, got: %s", s)
	}
	// Verify Enabled uses <Format>bool</Format>
	if !strings.Contains(s, "Enabled</LocURI></Target><Meta><Format xmlns=\"syncml:metinf\">bool</Format>") {
		t.Fatalf("expected Enabled to use Format=bool, got: %s", s)
	}
	// Verify Action/Type uses <Format>int</Format> and Data=1
	if !strings.Contains(s, "Action/Type</LocURI></Target><Meta><Format xmlns=\"syncml:metinf\">int</Format><Type>text/plain</Type></Meta><Data>1</Data>") {
		t.Fatalf("expected Action/Type Format=int Data=1, got: %s", s)
	}
}

func TestDefenderScanSignatureAndBaselineQueueing(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-SEC-2")

	n, err := EnqueueEndpointSecurityBaseline(database.DB, devID, EndpointSecuritySpec{
		AllowRealtimeMonitoring: true,
		AllowBehaviorMonitoring: true,
		AllowCloudProtection:    true,
		CloudBlockLevel:         4,
		PUAProtection:           1,
		EnableNetworkProtection: 1,
		CheckSigsBeforeScan:     true,
		FirewallDomainEnabled:   true,
		FirewallPrivateEnabled:  true,
		FirewallPublicEnabled:   true,
		BlockInboundDomain:      true,
		BlockInboundPrivate:     true,
		BlockInboundPublic:      true,
	})
	if err != nil || n < 13 {
		t.Fatalf("EnqueueEndpointSecurityBaseline: n=%d err=%v", n, err)
	}

	if q, err := EnqueueDefenderScan(database.DB, devID, "full"); err != nil || q == 0 {
		t.Fatalf("EnqueueDefenderScan(full): q=%d err=%v", q, err)
	}
	if q, err := EnqueueDefenderSignatureUpdate(database.DB, devID); err != nil || q == 0 {
		t.Fatalf("EnqueueDefenderSignatureUpdate: q=%d err=%v", q, err)
	}

	var scanPayload string
	if err := database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMADefenderExecScan).Scan(&scanPayload); err != nil {
		t.Fatalf("query scan command: %v", err)
	}
	if scanPayload != "2" {
		t.Fatalf("want full scan payload '2', got %q", scanPayload)
	}

	// Verify Defender/Scan uses <Format>chr</Format> (not int!) in SyncML
	sess := &Session{NextCmdID: 1, CmdMap: map[string]int{}}
	rawScanXML, err := xml.Marshal(SyncML{
		SyncBody: SyncBody{
			Commands: buildSyncMLCommands(sess, []PendingCommand{{
				ID:          99,
				CommandType: "Exec",
				OMAURI:      OMADefenderExecScan,
				Payload:     "1",
			}}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawScanXML), `Defender/Scan</LocURI></Target><Meta><Format xmlns="syncml:metinf">chr</Format>`) {
		t.Fatalf("Defender/Scan must use <Format>chr</Format>, got: %s", string(rawScanXML))
	}
}
