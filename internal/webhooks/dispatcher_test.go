package webhooks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func TestHMACWebhookDeliveryFormatsAndAutoRemediation(t *testing.T) {
	database := testutil.DB(t)
	v, err := vault.NewFast("unit-test-master-secret-webhook-1234")
	if err != nil {
		t.Fatal(err)
	}
	disp := NewDispatcher(database.DB, v)

	const signingSecret = "whsec_latchz_test_secret_99"
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get(SignatureHeader)
		if !VerifyHMACSignature(signingSecret, sig, body) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		if r.Header.Get(EventHeader) == "" || r.Header.Get(DeliveryHeader) == "" {
			http.Error(w, "missing event headers", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	epID := "wh-test-1"
	encSecret, err := v.Encrypt(signingSecret, VaultAADPrefix+epID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = database.DB.Exec(`
		INSERT INTO webhook_endpoints (id, name, url, format, secret_encrypted, has_secret, events_csv, enabled)
		VALUES (?, 'SIEM Receiver', ?, 'slack', ?, 1, 'compliance.non_compliant,bitlocker.reveal_key', 1)
	`, epID, srv.URL, encSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Test Ping via DeliverOne
	pingRes, err := disp.DeliverOne(context.Background(), epID, Event{
		Type:    "webhook.test",
		Actor:   "admin@lab.local",
		Summary: "Test ping from Latchz",
	})
	if err != nil || !pingRes.Success || pingRes.StatusCode != http.StatusOK {
		t.Fatalf("DeliverOne test ping failed: res=%+v err=%v", pingRes, err)
	}

	// Emit subscribed event -> delivered
	sent := disp.Emit(context.Background(), Event{
		Type:     "bitlocker.reveal_key",
		Actor:    "admin@lab.local",
		TargetID: "dev-1",
		Summary:  "BitLocker key revealed",
	})
	if sent != 1 {
		t.Fatalf("expected 1 webhook sent, got %d", sent)
	}

	// Emit unsubscribed event -> skipped
	skipped := disp.Emit(context.Background(), Event{
		Type:    "device.enroll",
		Summary: "New device enrolled",
	})
	if skipped != 0 {
		t.Fatalf("expected 0 webhooks for unsubscribed event, got %d", skipped)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 total HTTP hits, got %d", got)
	}

	// Verify Teams & Discord payload formatting
	teamsRaw, err := FormatPayload("teams", "d1", pingRes.DeliveredAt, Event{Type: "device.wipe", Summary: "Wipe queued"})
	if err != nil || !strings.Contains(string(teamsRaw), `"MessageCard"`) {
		t.Fatalf("unexpected Teams payload: %s err=%v", string(teamsRaw), err)
	}
	discordRaw, err := FormatPayload("discord", "d2", pingRes.DeliveredAt, Event{Type: "device.retire", Summary: "Retire queued"})
	if err != nil || !strings.Contains(string(discordRaw), `"Latchz MDM"`) {
		t.Fatalf("unexpected Discord payload: %s err=%v", string(discordRaw), err)
	}

	// Verify Auto-Remediation helpers
	if IsAutoRemediateEnabled(database.DB) {
		t.Fatal("expected auto_remediate false by default")
	}
	_, _ = database.DB.Exec(`INSERT INTO compliance_automation_settings (id, auto_remediate) VALUES ('default', 1)`)
	if !IsAutoRemediateEnabled(database.DB) {
		t.Fatal("expected auto_remediate true")
	}
	RecordAutoRemediation(database.DB)
	var remCount int
	_ = database.DB.QueryRow(`SELECT remediation_count FROM compliance_automation_settings WHERE id = 'default'`).Scan(&remCount)
	if remCount != 1 {
		t.Fatalf("expected remediation_count=1, got %d", remCount)
	}
}
