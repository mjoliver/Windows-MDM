package mdm

import (
	"database/sql"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const (
	// Windows 10/11 Privacy & Consumer Debloat Policy CSPs (supported on Pro, Enterprise & Education)
	OMASystemAllowTelemetry     = "./Device/Vendor/MSFT/Policy/Config/System/AllowTelemetry"
	OMAPrivacyDisableAdvID      = "./Device/Vendor/MSFT/Policy/Config/Privacy/DisableAdvertisingId"
	OMAExperienceTailoredData   = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowTailoredExperiencesWithDiagnosticData"
	OMADshAllowNewsAndInterests = "./Device/Vendor/MSFT/Policy/Config/Dsh/AllowNewsAndInterests"

	// Microsoft Edge Inbox ADMX-Backed Policy CSPs (supported on Windows 10 21H2+ & Windows 11 Pro/Enterprise)
	OMAEdgeSmartScreenEnabled     = "./Device/Vendor/MSFT/Policy/Config/microsoft_edge~Policy~microsoft_edge/SmartScreenEnabled"
	OMAEdgePreventSSOverride      = "./Device/Vendor/MSFT/Policy/Config/microsoft_edge~Policy~microsoft_edge/PreventSmartScreenPromptOverride"
	OMAEdgeSmartScreenPUA         = "./Device/Vendor/MSFT/Policy/Config/microsoft_edge~Policy~microsoft_edge/SmartScreenPuaEnabled"
	OMAEdgePasswordManagerEnabled = "./Device/Vendor/MSFT/Policy/Config/microsoft_edge~Policy~microsoft_edge/PasswordManagerEnabled"
	OMAEdgeTyposquattingChecker   = "./Device/Vendor/MSFT/Policy/Config/microsoft_edge~Policy~microsoft_edge/TyposquattingCheckerEnabled"

	// Optional Corporate Branding Personalization CSPs (Windows Enterprise / Education SKUs)
	OMAPersonalizationDesktopImage    = "./Device/Vendor/MSFT/Policy/Config/Personalization/DesktopImageUrl"
	OMAPersonalizationLockScreenImage = "./Device/Vendor/MSFT/Policy/Config/Personalization/LockScreenImageUrl"
)

// DesktopExperienceSpec defines Windows 11 privacy/debloat, corporate branding, and Edge browser baseline settings.
type DesktopExperienceSpec struct {
	TelemetryLevel           int  // 0=Security(Ent), 1=Required/Basic, 3=Optional
	DisableAdvertisingID     bool // 1=Block Advertising ID
	BlockTailoredExperiences bool // 0 on AllowTailoredExperiencesWithDiagnosticData
	DisableWidgetsNews       bool // 0 on AllowNewsAndInterests
	EdgeSmartScreenEnabled   bool
	EdgePreventSSOverride    bool
	EdgeSmartScreenPUA       bool
	EdgeBlockPasswordManager bool
	EdgeTyposquattingChecker bool
	DesktopWallpaperURL      string
	LockScreenImageURL       string
}

func admxBoolPayload(enabled bool) string {
	if enabled {
		return "<enabled/>"
	}
	return "<disabled/>"
}

// ValidateOptionalBrandingURL validates an optional https:// or http:// image URL for Personalization CSP.
func ValidateOptionalBrandingURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > 512 {
		return "", errors.New("branding image URL must be 512 characters or fewer")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return "", errors.New("branding image URL must be a valid http:// or https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("branding image URL scheme must be https or http")
	}
	return u.String(), nil
}

// EnqueueDesktopExperience queues OMA-DM Replace/Delete commands for Windows 11 Privacy/Debloat,
// Microsoft Edge Security Baseline, and optional Corporate Branding URLs.
func EnqueueDesktopExperience(dbConn *sql.DB, deviceID string, spec DesktopExperienceSpec, prevBranding bool) (queued int, brandingNow bool, err error) {
	tel := spec.TelemetryLevel
	if tel != 0 && tel != 1 && tel != 3 {
		tel = 1
	}
	advVal := "0"
	if spec.DisableAdvertisingID {
		advVal = "1"
	}
	tailoredVal := "1"
	if spec.BlockTailoredExperiences {
		tailoredVal = "0"
	}
	widgetsVal := "1"
	if spec.DisableWidgetsNews {
		widgetsVal = "0"
	}

	items := []struct {
		uri string
		val string
	}{
		{OMASystemAllowTelemetry, strconv.Itoa(tel)},
		{OMAPrivacyDisableAdvID, advVal},
		{OMAExperienceTailoredData, tailoredVal},
		{OMADshAllowNewsAndInterests, widgetsVal},
		{OMAEdgeSmartScreenEnabled, admxBoolPayload(spec.EdgeSmartScreenEnabled)},
		{OMAEdgePreventSSOverride, admxBoolPayload(spec.EdgePreventSSOverride)},
		{OMAEdgeSmartScreenPUA, admxBoolPayload(spec.EdgeSmartScreenPUA)},
		{OMAEdgePasswordManagerEnabled, admxBoolPayload(!spec.EdgeBlockPasswordManager)},
		{OMAEdgeTyposquattingChecker, admxBoolPayload(spec.EdgeTyposquattingChecker)},
	}

	for _, it := range items {
		if _, qErr := EnqueueReplace(dbConn, deviceID, it.uri, it.val); qErr != nil {
			return queued, false, qErr
		}
		queued++
	}

	deskURL := strings.TrimSpace(spec.DesktopWallpaperURL)
	lockURL := strings.TrimSpace(spec.LockScreenImageURL)
	if deskURL != "" {
		if _, qErr := EnqueueReplace(dbConn, deviceID, OMAPersonalizationDesktopImage, deskURL); qErr != nil {
			return queued, false, qErr
		}
		queued++
		brandingNow = true
	} else if prevBranding {
		_, _ = EnqueueDelete(dbConn, deviceID, OMAPersonalizationDesktopImage)
		queued++
	}

	if lockURL != "" {
		if _, qErr := EnqueueReplace(dbConn, deviceID, OMAPersonalizationLockScreenImage, lockURL); qErr != nil {
			return queued, brandingNow, qErr
		}
		queued++
		brandingNow = true
	} else if prevBranding {
		_, _ = EnqueueDelete(dbConn, deviceID, OMAPersonalizationLockScreenImage)
		queued++
	}

	return queued, brandingNow, nil
}

// RetractDesktopExperience queues <Delete> commands to remove Windows Privacy/Debloat,
// Edge Browser Baseline, and optional Corporate Branding policies from a device.
func RetractDesktopExperience(dbConn *sql.DB, deviceID string, prevBranding bool) (int, error) {
	uris := []string{
		OMASystemAllowTelemetry,
		OMAPrivacyDisableAdvID,
		OMAExperienceTailoredData,
		OMADshAllowNewsAndInterests,
		OMAEdgeSmartScreenEnabled,
		OMAEdgePreventSSOverride,
		OMAEdgeSmartScreenPUA,
		OMAEdgePasswordManagerEnabled,
		OMAEdgeTyposquattingChecker,
	}
	if prevBranding {
		uris = append(uris, OMAPersonalizationDesktopImage, OMAPersonalizationLockScreenImage)
	}
	var queued int
	for _, u := range uris {
		if _, err := EnqueueDelete(dbConn, deviceID, u); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}
