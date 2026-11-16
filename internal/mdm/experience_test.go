package mdm

import (
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestDesktopExperienceEnqueueAndRetract(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-EXP-1")

	if _, err := ValidateOptionalBrandingURL("ftp://bad.example.com/bg.jpg"); err == nil {
		t.Fatal("expected ftp:// branding URL to fail validation")
	}
	cleanURL, err := ValidateOptionalBrandingURL("https://cdn.lab.local/corp-bg.jpg")
	if err != nil || cleanURL != "https://cdn.lab.local/corp-bg.jpg" {
		t.Fatalf("ValidateOptionalBrandingURL: %q err=%v", cleanURL, err)
	}

	q, branding, err := EnqueueDesktopExperience(database.DB, devID, DesktopExperienceSpec{
		TelemetryLevel:           1,
		DisableAdvertisingID:     true,
		BlockTailoredExperiences: true,
		DisableWidgetsNews:       true,
		EdgeSmartScreenEnabled:   true,
		EdgePreventSSOverride:    true,
		EdgeSmartScreenPUA:       true,
		EdgeBlockPasswordManager: true,
		EdgeTyposquattingChecker: true,
		DesktopWallpaperURL:      cleanURL,
	}, false)
	if err != nil || q != 10 || !branding {
		t.Fatalf("EnqueueDesktopExperience: q=%d branding=%t err=%v", q, branding, err)
	}

	var widgetsVal, edgePwdVal string
	_ = database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMADshAllowNewsAndInterests).Scan(&widgetsVal)
	_ = database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri = ?`, devID, OMAEdgePasswordManagerEnabled).Scan(&edgePwdVal)
	if widgetsVal != "0" || edgePwdVal != "0" {
		t.Fatalf("unexpected payloads: widgets=%q edgePwd=%q", widgetsVal, edgePwdVal)
	}

	_, _ = database.DB.Exec(`UPDATE command_queue SET status = 'success' WHERE device_id = ?`, devID)
	rq, err := RetractDesktopExperience(database.DB, devID, true)
	if err != nil || rq != 11 {
		t.Fatalf("RetractDesktopExperience: rq=%d err=%v", rq, err)
	}
}
