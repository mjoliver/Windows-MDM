package mdm

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestASRRulePipeSerializationAndHardeningSyncML(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-ASR-1")

	rules, active, err := ValidateAndNormalizeASRRules(map[string]int{
		"BE9BA2D9-53EA-4CDC-84E5-9B1FEED46555": 1,
		"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 2,
		"5beb7efe-fd9a-4556-801d-275e5ffc04cc": 0, // disabled -> omitted
	})
	if err != nil || active != 2 {
		t.Fatalf("ValidateAndNormalizeASRRules: active=%d err=%v", active, err)
	}
	pipe := BuildASRRulesPipeString(rules)
	want := "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=2|be9ba2d9-53ea-4cdc-84e5-9b1feed46555=1"
	if pipe != want {
		t.Fatalf("BuildASRRulesPipeString = %q, want %q", pipe, want)
	}

	if _, _, err := ValidateAndNormalizeASRRules(map[string]int{"not-a-guid": 1}); err == nil {
		t.Fatal("expected error for invalid ASR GUID")
	}
	if _, _, err := ValidateAndNormalizeASRRules(map[string]int{"be9ba2d9-53ea-4cdc-84e5-9b1feed46555": 9}); err == nil {
		t.Fatal("expected error for invalid ASR mode 9")
	}

	q, err := EnqueueEndpointHardening(database.DB, devID, EndpointHardeningSpec{
		ASRRules:                   rules,
		EnableSmartScreenShell:     true,
		PreventSmartScreenOverride: true,
		AppInstallControl:          3,
		SubmitSamplesConsent:       1,
		DisableLocalAdminMerge:     true,
	})
	if err != nil || q != 6 {
		t.Fatalf("EnqueueEndpointHardening: q=%d err=%v", q, err)
	}

	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil || len(pending) != 6 {
		t.Fatalf("loadPendingCommands: len=%d err=%v", len(pending), err)
	}

	sess := &Session{NextCmdID: 1, CmdMap: map[string]int{}}
	doc := SyncML{
		SyncBody: SyncBody{
			Commands: buildSyncMLCommands(sess, pending),
			Final:    &struct{}{},
		},
	}
	raw, err := xml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)

	if !strings.Contains(out, OMADefenderASRRules) || !strings.Contains(out, want) {
		t.Fatalf("expected ASR rules pipe string in SyncML: %s", out)
	}
	if !strings.Contains(out, OMADefenderASRRules+`</LocURI></Target><Meta><Format xmlns="syncml:metinf">chr</Format>`) {
		t.Fatalf("expected explicit <Format>chr</Format> on AttackSurfaceReductionRules: %s", out)
	}
	if !strings.Contains(out, OMASmartScreenEnableInShell) || !strings.Contains(out, OMASmartScreenPreventOverride) {
		t.Fatalf("expected SmartScreen CSP URIs in SyncML: %s", out)
	}

	// Retract hardening -> 6 <Delete> commands
	rq, err := RetractEndpointHardening(database.DB, devID)
	if err != nil || rq != 6 {
		t.Fatalf("RetractEndpointHardening: rq=%d err=%v", rq, err)
	}
}
