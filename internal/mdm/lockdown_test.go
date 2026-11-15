package mdm

import (
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDeviceLockdownInvertedPasswordAndUSBStorageModes(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-LOCK-1")

	q, kioskNow, err := EnqueueDeviceLockdown(database.DB, devID, DeviceLockdownSpec{
		USBStorageMode:       "read_only",
		RequirePassword:      true,
		MinPasswordLength:    10,
		AlphanumericRequired: true,
		MaxInactivityMinutes: 15,
		MaxFailedAttempts:    8,
		AllowCamera:          false,
		AllowBluetooth:       true,
		KioskMode:            "single_app",
		KioskAccount:         "KioskDesk",
		KioskAppAUMID:        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge",
	}, false)
	if err != nil {
		t.Fatalf("EnqueueDeviceLockdown: %v", err)
	}
	if q < 8 || !kioskNow {
		t.Fatalf("expected >=8 commands (6 Replace + 1 Atomic DeviceLock + 1 Kiosk) and kioskNow=true, got q=%d kioskNow=%t", q, kioskNow)
	}

	// Verify inverted DevicePasswordEnabled = "0" inside <Atomic> DeviceLock payload when RequirePassword == true!
	var atomicPayload string
	if err := database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND command_type = 'Atomic' AND oma_uri = ?`, devID, OMADeviceLockAtomicURI).Scan(&atomicPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(atomicPayload, `"oma_uri":"`+OMADeviceLockPasswordEnabled+`","payload":"0"`) {
		t.Fatalf("CRITICAL: Atomic DeviceLock must set DevicePasswordEnabled='0' (Enabled) when RequirePassword=true, got %s", atomicPayload)
	}

	// Verify read_only USB storage sets DenyWrite=1, DenyRead=0
	var denyWrite, denyRead string
	_ = database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMAStorageDenyWrite).Scan(&denyWrite)
	_ = database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMAStorageDenyRead).Scan(&denyRead)
	if denyWrite != "1" || denyRead != "0" {
		t.Fatalf("expected read_only USB storage DenyWrite=1 DenyRead=0, got %q/%q", denyWrite, denyRead)
	}

	// Verify AssignedAccess KioskModeApp JSON
	var kioskJSON string
	if err := database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMAAssignedAccessKioskApp).Scan(&kioskJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(kioskJSON, `"Account":"KioskDesk"`) {
		t.Fatalf("unexpected KioskModeApp JSON: %s", kioskJSON)
	}

	// Mark pending commands sent so retraction queues Delete cleanly
	_, _ = database.DB.Exec(`UPDATE command_queue SET status = 'success' WHERE device_id = ?`, devID)
	rq, err := RetractDeviceLockdown(database.DB, devID, true)
	if err != nil || rq < 11 {
		t.Fatalf("RetractDeviceLockdown: rq=%d err=%v", rq, err)
	}
}
