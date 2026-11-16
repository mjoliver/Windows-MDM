package auth

import (
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestBulkEnrollmentTokenLifecycleAndLimits(t *testing.T) {
	database := testutil.DB(t)

	raw, prefix, hash, err := GenerateBulkToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(prefix) != 13 || HashBulkToken(raw) != hash {
		t.Fatalf("unexpected generated bulk token: raw=%q prefix=%q hash=%q", raw, prefix, hash)
	}

	exp := time.Now().UTC().Add(24 * time.Hour)
	_, err = database.DB.Exec(`
		INSERT INTO bulk_enrollment_tokens (
			id, name, token_prefix, token_hash, auto_group_id, max_uses, use_count, expires_at, revoked, created_by
		) VALUES ('bt-1', 'Staging Bench', ?, ?, 'grp-kiosk', 2, 0, ?, 0, 'admin@lab.local')
	`, prefix, hash, exp)
	if err != nil {
		t.Fatal(err)
	}

	// Unconsumed check leaves use_count at 0
	owner, err := VerifyBulkEnrollmentTokenUnconsumed(database.DB, raw)
	if err != nil || owner != "admin@lab.local" {
		t.Fatalf("VerifyBulkEnrollmentTokenUnconsumed: owner=%q err=%v", owner, err)
	}

	// Consume #1 (via validateEnrollmentToken) -> succeeds
	email1, err := validateEnrollmentToken(make([]byte, 32), database.DB, raw)
	if err != nil || email1 != "admin@lab.local" {
		t.Fatalf("consume #1 failed: email=%q err=%v", email1, err)
	}

	// Consume #2 -> succeeds (hits max_uses=2)
	_, autoGrp, tokID, err := ConsumeBulkEnrollmentToken(database.DB, raw)
	if err != nil || autoGrp != "grp-kiosk" || tokID != "bt-1" {
		t.Fatalf("consume #2 failed: grp=%q tokID=%q err=%v", autoGrp, tokID, err)
	}

	// Consume #3 -> rejected (max_uses exhausted!)
	if _, _, _, err := ConsumeBulkEnrollmentToken(database.DB, raw); err == nil {
		t.Fatal("expected error when max_uses=2 is exhausted")
	}
}
