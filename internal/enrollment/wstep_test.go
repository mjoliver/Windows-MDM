package enrollment

import (
	"context"
	"errors"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

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
