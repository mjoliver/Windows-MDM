package enrollment

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	idb "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestVerifiedRenewalDevice(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-RENEW")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")

	// Valid client cert → maps to the device (renewal allowed).
	req := httptest.NewRequest("POST", "/wstep", nil)
	req.TLS = testutil.ClientTLSState(cert)
	if did, _, ok := verifiedRenewalDevice(req, ca, database.DB); !ok || did != deviceID {
		t.Fatalf("expected renewal device %q, got (%q, %v)", deviceID, did, ok)
	}

	// No client cert → not a renewal.
	if _, _, ok := verifiedRenewalDevice(httptest.NewRequest("POST", "/wstep", nil), ca, database.DB); ok {
		t.Fatal("renewal must require a client certificate")
	}

	// Revoked cert → not allowed.
	if _, err := database.Exec(idb.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := verifiedRenewalDevice(req, ca, database.DB); ok {
		t.Fatal("revoked certificate must not authenticate a renewal")
	}
}

func TestUpsertDevice_HijackPrevention(t *testing.T) {
	database := testutil.DB(t)
	ctx := context.Background()
	info := DeviceInfo{HardwareID: "HW-1", DeviceName: "Laptop"}

	id1, err := upsertDevice(ctx, database.DB, info, "alice@example.com")
	if err != nil {
		t.Fatalf("initial enroll: %v", err)
	}

	// Same user re-enrolls the same hardware_id → same device record.
	id1b, err := upsertDevice(ctx, database.DB, info, "alice@example.com")
	if err != nil {
		t.Fatalf("re-enroll same user: %v", err)
	}
	if id1b != id1 {
		t.Fatalf("re-enroll created a new device (%s != %s)", id1b, id1)
	}

	// Different user trying the same hardware_id must be rejected (no hijack).
	if _, err := upsertDevice(ctx, database.DB, info, "attacker@example.com"); !errors.Is(err, errHardwareIDTaken) {
		t.Fatalf("expected errHardwareIDTaken, got %v", err)
	}

	// Verify the original owner was NOT overwritten.
	var owner string
	if err := database.QueryRow(`SELECT enrolled_by FROM devices WHERE id = ?`, id1).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != "alice@example.com" {
		t.Fatalf("owner was overwritten to %q", owner)
	}

	// A genuinely new hardware_id creates a new device.
	id2, err := upsertDevice(ctx, database.DB, DeviceInfo{HardwareID: "HW-2"}, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id1 {
		t.Fatal("distinct hardware_id reused an existing device id")
	}
}
