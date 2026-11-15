package mdm

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestValidateHostnameTemplate(t *testing.T) {
	valid := map[string]string{
		"DESKTOP-H4S6B82":   "DESKTOP-H4S6B82",
		"corp-%serial%":     "corp-%SERIAL%",
		"LZ-%rand:6%-WIN11": "LZ-%RAND:6%-WIN11",
		"1234-%RAND:4%":     "1234-%RAND:4%",
	}
	for in, want := range valid {
		got, err := ValidateHostnameTemplate(in)
		if err != nil {
			t.Fatalf("ValidateHostnameTemplate(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ValidateHostnameTemplate(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"",
		"-badstart",
		"badend-",
		"123456", // purely numeric without macro
		"has space",
		"bad_underscore",
		"CORP-%UNKNOWN%",
		"CORP-%RAND:0%",
		"CORP-%RAND:99%",
		strings.Repeat("A", 64),
	}
	for _, in := range invalid {
		if _, err := ValidateHostnameTemplate(in); err == nil {
			t.Errorf("ValidateHostnameTemplate(%q) succeeded, expected error", in)
		}
	}
}

func TestEnqueueRenameAndRetireSyncMLFormatting(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-LIFECYCLE")

	if _, err := EnqueueRenameDevice(database.DB, devID, "CORP-%RAND:4%"); err != nil {
		t.Fatalf("EnqueueRenameDevice: %v", err)
	}

	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected Replace + Get (2 cmds), got %d", len(pending))
	}

	sess := &Session{NextMsgID: 1, NextCmdID: 2, CmdMap: make(map[string]int)}
	cmds := buildSyncMLCommands(sess, pending)
	rawRename, err := xml.Marshal(cmds[0])
	if err != nil {
		t.Fatal(err)
	}
	xmlStr := string(rawRename)
	if !strings.Contains(xmlStr, "<LocURI>./DevDetail/Ext/Microsoft/DNSComputerName</LocURI>") ||
		!strings.Contains(xmlStr, `<Format xmlns="syncml:metinf">chr</Format>`) ||
		!strings.Contains(xmlStr, "<Data>CORP-%RAND:4%</Data>") {
		t.Fatalf("unexpected rename SyncML: %s", xmlStr)
	}

	// Queue clean Retire — should cancel pending rename/get and queue DMClient Unenroll Exec with chr format
	if _, err := EnqueueRetireDevice(database.DB, devID); err != nil {
		t.Fatalf("EnqueueRetireDevice: %v", err)
	}
	pendingAfterRetire, err := loadPendingCommands(database.DB, devID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingAfterRetire) != 1 {
		t.Fatalf("expected only 1 pending command (Unenroll) after retire, got %d", len(pendingAfterRetire))
	}
	cmdsRetire := buildSyncMLCommands(sess, pendingAfterRetire)
	rawRetire, err := xml.Marshal(cmdsRetire[0])
	if err != nil {
		t.Fatal(err)
	}
	retireXML := string(rawRetire)
	if !strings.Contains(retireXML, "<Exec>") ||
		!strings.Contains(retireXML, "<LocURI>./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Unenroll</LocURI>") ||
		!strings.Contains(retireXML, `<Format xmlns="syncml:metinf">chr</Format>`) ||
		!strings.Contains(retireXML, "<Data>LatchzMDM</Data>") {
		t.Fatalf("unexpected retire SyncML: %s", retireXML)
	}
}
