package mdm

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestHandleOMADM_FirstCheckIn(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-OMADM")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")

	syncml := `<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-OMADM</LocURI></Source>
    <Target><LocURI>https://mdm.example.com/omadm</LocURI></Target>
  </SyncHdr>
  <SyncBody>
    <Alert><CmdID>1</CmdID><Data>1200</Data></Alert>
    <Final/>
  </SyncBody>
</SyncML>`
	req := httptest.NewRequest("POST", "/omadm", strings.NewReader(syncml))
	req.TLS = testutil.ClientTLSState(cert)
	w := httptest.NewRecorder()
	h.HandleOMADM(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	out := w.Body.String()
	if !strings.Contains(out, "<SyncML") || !strings.Contains(out, "Status") {
		t.Fatalf("unexpected SyncML response: %s", out)
	}
	// First session → device-info interrogation Gets are issued.
	if !strings.Contains(out, "<Get>") {
		t.Fatalf("expected interrogation Get commands on first check-in: %s", out)
	}

	// last_checkin is recorded.
	var lastCheckin *string
	if err := database.QueryRow(`SELECT last_checkin FROM devices WHERE id = ?`, deviceID).Scan(&lastCheckin); err != nil {
		t.Fatal(err)
	}
	if lastCheckin == nil {
		t.Fatal("last_checkin not updated")
	}
}

func TestHandleOMADM_RejectsUnauthenticated(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")

	req := httptest.NewRequest("POST", "/omadm?hwid=HW-OMADM", strings.NewReader("<SyncML/>"))
	w := httptest.NewRecorder()
	h.HandleOMADM(w, req)
	if w.Code != 401 {
		t.Fatalf("want 401 without a client cert, got %d", w.Code)
	}
}
