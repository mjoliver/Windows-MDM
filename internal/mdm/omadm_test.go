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
	cert := testutil.IssueClientCert(t, ca, deviceID, "LatchzMDMClient")
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

func TestHandleOMADM_WipeFinalizesOnDelivery(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-WIPE2")
	cert := testutil.IssueClientCert(t, ca, deviceID, "LatchzMDMClient")
	if _, err := EnqueueWipe(database.DB, deviceID); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")

	syncml := `<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>9</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-WIPE2</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody><Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Final/></SyncBody>
</SyncML>`
	req := httptest.NewRequest("POST", "/omadm", strings.NewReader(syncml))
	req.TLS = testutil.ClientTLSState(cert)
	w := httptest.NewRecorder()
	h.HandleOMADM(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}

	// The wipe was delivered → device deactivated and cert revoked, without
	// waiting for an (often never-arriving) ACK.
	var active, revoked int
	database.QueryRow(`SELECT is_active FROM devices WHERE id = ?`, deviceID).Scan(&active)
	database.QueryRow(`SELECT revoked FROM certificates WHERE device_id = ?`, deviceID).Scan(&revoked)
	if active != 0 {
		t.Fatal("device should be deactivated after wipe delivery")
	}
	if revoked != 1 {
		t.Fatal("device cert should be revoked after wipe delivery")
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

func TestHandleOMADM_ReconcilesPollScheduleOnce(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-POLL")
	// Pre-populate OS version & build so interrogation Gets do not cloud the response.
	if _, err := database.Exec(`UPDATE devices SET os_version = '10.0.26100.1', os_build = '26100.1' WHERE id = ?`, deviceID); err != nil {
		t.Fatal(err)
	}
	cert := testutil.IssueClientCert(t, ca, deviceID, "LatchzMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")
	h.SetPollSchedule(15, true)

	checkIn := func(sessID string) string {
		syncml := `<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>` + sessID + `</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-POLL</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody><Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Final/></SyncBody>
</SyncML>`
		req := httptest.NewRequest("POST", "/omadm", strings.NewReader(syncml))
		req.TLS = testutil.ClientTLSState(cert)
		w := httptest.NewRecorder()
		h.HandleOMADM(w, req)
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		return w.Body.String()
	}

	first := checkIn("10")
	for _, want := range []string{
		OMADMClientPollNumRemaining,
		OMADMClientPollFrequency,
		`<Data>15</Data>`,
		OMADMClientPollOnLogin,
		`<Data>true</Data>`,
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("first check-in missing %q: %s", want, first)
		}
	}

	// Second check-in with unchanged schedule must NOT re-send Poll Replace commands.
	second := checkIn("11")
	if strings.Contains(second, OMADMClientPollFrequency) {
		t.Fatalf("expected Poll schedule not to be re-sent on subsequent check-in: %s", second)
	}

	// Updating the schedule triggers reconciliation on the next check-in.
	h.SetPollSchedule(30, false)
	third := checkIn("12")
	if !strings.Contains(third, `<Data>30</Data>`) || !strings.Contains(third, `<Data>false</Data>`) {
		t.Fatalf("expected updated Poll schedule on third check-in: %s", third)
	}
}

func TestHandleOMADM_WNSChannelRegistrationAndSSRFFilter(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-WNS-OMADM")
	if _, err := database.Exec(`UPDATE devices SET os_version = '10.0.26100.1', os_build = '26100.1' WHERE id = ?`, deviceID); err != nil {
		t.Fatal(err)
	}
	cert := testutil.IssueClientCert(t, ca, deviceID, "LatchzMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")
	h.SetWNSPFN("Latchz.MDM_8wekyb3d8bbwe")

	postSyncML := func(xmlBody string) string {
		req := httptest.NewRequest("POST", "/omadm", strings.NewReader(xmlBody))
		req.TLS = testutil.ClientTLSState(cert)
		w := httptest.NewRecorder()
		h.HandleOMADM(w, req)
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		return w.Body.String()
	}

	// Msg 1: server provisions Push/PFN and requests Push/ChannelURI
	resp1 := postSyncML(`<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>20</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-WNS-OMADM</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody><Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Final/></SyncBody>
</SyncML>`)
	for _, want := range []string{OMADMClientPushPFN, "Latchz.MDM_8wekyb3d8bbwe", OMADMClientPushChannelURI} {
		if !strings.Contains(resp1, want) {
			t.Fatalf("expected %q in WNS provisioning SyncML: %s", want, resp1)
		}
	}

	// Msg 2 (attacker/rogue URI): SSRF target must be rejected
	postSyncML(`<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>20</SessionID><MsgID>2</MsgID>
    <Source><LocURI>HW-WNS-OMADM</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody>
    <Results><CmdID>2</CmdID><CmdRef>3</CmdRef>
      <Item><Source><LocURI>` + OMADMClientPushChannelURI + `</LocURI></Source><Data>https://127.0.0.1/ssrf</Data></Item>
    </Results>
    <Final/>
  </SyncBody>
</SyncML>`)
	var cnt int
	_ = database.QueryRow(`SELECT COUNT(*) FROM device_wns_channels WHERE device_id = ?`, deviceID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("expected SSRF ChannelURI to be rejected, found %d rows", cnt)
	}

	// Msg 3 (valid WNS URI): persisted cleanly
	validURI := "https://wns2-bl2p.notify.windows.com/?token=AwYAAACValidToken"
	postSyncML(`<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>21</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-WNS-OMADM</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody>
    <Results><CmdID>2</CmdID><CmdRef>3</CmdRef>
      <Item><Source><LocURI>` + OMADMClientPushChannelURI + `</LocURI></Source><Data>` + validURI + `</Data></Item>
      <Item><Source><LocURI>` + OMADMClientPushStatus + `</LocURI></Source><Data>0</Data></Item>
    </Results>
    <Final/>
  </SyncBody>
</SyncML>`)
	var storedURI string
	if err := database.QueryRow(`SELECT channel_uri FROM device_wns_channels WHERE device_id = ?`, deviceID).Scan(&storedURI); err != nil {
		t.Fatalf("expected valid WNS ChannelURI to be stored: %v", err)
	}
	if storedURI != validURI {
		t.Fatalf("stored channel_uri = %q, want %q", storedURI, validURI)
	}

	// Next session: both PFN and ChannelURI are already satisfied, so neither is re-sent.
	respNext := postSyncML(`<?xml version="1.0"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>22</SessionID><MsgID>1</MsgID>
    <Source><LocURI>HW-WNS-OMADM</LocURI></Source><Target><LocURI>https://mdm.example.com/omadm</LocURI></Target></SyncHdr>
  <SyncBody><Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Final/></SyncBody>
</SyncML>`)
	if strings.Contains(respNext, OMADMClientPushPFN) || strings.Contains(respNext, OMADMClientPushChannelURI) {
		t.Fatalf("expected no redundant WNS commands once channel is active: %s", respNext)
	}
}
