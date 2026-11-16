package mdm

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

const (
	// Update CSP — lists update GUIDs waiting for a restart (empty when no reboot is pending).
	OMAUpdatePendingRebootUpdates = "./Device/Vendor/MSFT/Update/PendingRebootUpdates"
	OMARebootRequired             = OMAUpdatePendingRebootUpdates

	// WindowsLicensing CSP — reports Windows SKU edition integer and activation status.
	OMAWindowsLicensingEdition = "./Device/Vendor/MSFT/WindowsLicensing/Edition"
	OMAWindowsLicensingStatus  = "./Device/Vendor/MSFT/WindowsLicensing/Status"
)

// CSPPreset defines a curated 1-click read-only OMA-URI inspection preset for the Live CSP Explorer.
type CSPPreset struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Label       string `json:"label"`
	OMAURI      string `json:"oma_uri"`
	Description string `json:"description"`
}

// OfficialCSPPresets provides safe, agentless Windows 10/11 read-only OMA-URIs for live endpoint inspection.
var OfficialCSPPresets = []CSPPreset{
	{
		ID:          "reboot_required",
		Category:    "System",
		Label:       "Reboot Pending Status",
		OMAURI:      OMAUpdatePendingRebootUpdates,
		Description: "Checks Windows Update PendingRebootUpdates node (empty when no restart is required).",
	},
	{
		ID:          "windows_edition",
		Category:    "Licensing",
		Label:       "Windows SKU Edition",
		OMAURI:      OMAWindowsLicensingEdition,
		Description: "Reads OperatingSystemSKU (e.g. 48 = Windows Pro, 4 = Enterprise, 121 = Education).",
	},
	{
		ID:          "windows_license_status",
		Category:    "Licensing",
		Label:       "Windows Activation Status",
		OMAURI:      OMAWindowsLicensingStatus,
		Description: "Reads Windows licensing state (0 = Licensed, 1 = Grace, 2 = Unlicensed/Notification).",
	},
	{
		ID:          "dns_computer_name",
		Category:    "Identity",
		Label:       "DNS Computer Name",
		OMAURI:      OMADevDetailComputerName,
		Description: "Reads live endpoint hostname from DevDetail CSP.",
	},
	{
		ID:          "local_time",
		Category:    "System",
		Label:       "Endpoint Local Clock",
		OMAURI:      OMADevDetailLocalTime,
		Description: "Reads ISO-8601 local clock and timezone offset reported by Windows.",
	},
	{
		ID:          "os_platform",
		Category:    "System",
		Label:       "OS Platform String",
		OMAURI:      OMADevDetailOSPlatform,
		Description: "Reads full Windows edition & architecture string from DevDetail.",
	},
	{
		ID:          "secure_boot",
		Category:    "Security",
		Label:       "Secure Boot State",
		OMAURI:      OMADeviceStatusSecureBoot,
		Description: "Reads UEFI Secure Boot state (1 = Enabled, 2 = Disabled, 0 = Unsupported).",
	},
	{
		ID:          "tpm_version",
		Category:    "Security",
		Label:       "TPM Specification Version",
		OMAURI:      OMADeviceStatusTPMVersion,
		Description: "Reads Trusted Platform Module specification version (e.g. 2.0).",
	},
	{
		ID:          "bitlocker_status",
		Category:    "Security",
		Label:       "BitLocker Device Encryption Status",
		OMAURI:      OMABitLockerEncryptionStatus,
		Description: "Reads BitLocker compliance bitmask (0 = Fully Encrypted & Compliant).",
	},
	{
		ID:          "defender_av_status",
		Category:    "Security",
		Label:       "Defender Antivirus Status",
		OMAURI:      OMADeviceStatusAntivirus,
		Description: "Reads Windows Security Center AV bitmask (0 = Active & Monitoring).",
	},
	{
		ID:          "dmclient_poll_interval",
		Category:    "MDM",
		Label:       "DMClient Poll Interval (Minutes)",
		OMAURI:      OMADMClientPollFrequency,
		Description: "Reads configured LatchzMDM background check-in schedule interval.",
	},
	{
		ID:          "wu_last_scan",
		Category:    "Updates",
		Label:       "Windows Update Last Scan Time",
		OMAURI:      "./Device/Vendor/MSFT/Update/LastSuccessfulScanTime",
		Description: "Reads timestamp of the most recent Windows Update scan.",
	},
}

// WindowsEditionLabel translates a Microsoft WindowsLicensing/Edition (OperatingSystemSKU) integer into a friendly name.
func WindowsEditionLabel(code *int64) string {
	if code == nil {
		return "Unknown"
	}
	switch *code {
	case 4:
		return "Windows Enterprise"
	case 27:
		return "Windows Enterprise N"
	case 48:
		return "Windows Pro"
	case 49:
		return "Windows Pro N"
	case 70:
		return "Windows Enterprise E"
	case 72:
		return "Windows Enterprise Evaluation"
	case 98, 100, 101:
		return "Windows Home"
	case 121:
		return "Windows Education"
	case 122:
		return "Windows Education N"
	case 125:
		return "Windows Enterprise LTSC"
	case 129:
		return "Windows Enterprise LTSC Evaluation"
	case 161:
		return "Windows Pro for Workstations"
	case 162:
		return "Windows Pro for Workstations N"
	case 164:
		return "Windows Pro Education"
	case 175:
		return "Windows Enterprise multi-session"
	case 203:
		return "Windows 11 SE"
	default:
		return fmt.Sprintf("Windows (SKU %d)", *code)
	}
}

// ParseOptionalBoolInt parses OMA-DM boolean/int strings ("true"/"false"/"1"/"0") into sql.NullInt64 (1 or 0).
func ParseOptionalBoolInt(raw string) sql.NullInt64 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1":
		return sql.NullInt64{Int64: 1, Valid: true}
	case "false", "0":
		return sql.NullInt64{Int64: 0, Valid: true}
	default:
		return sql.NullInt64{}
	}
}

// ParsePendingRebootUpdates evaluates the Windows Update CSP PendingRebootUpdates node:
// an empty container ("") or explicit "false"/"0" means no reboot is pending (0);
// one or more slash-separated update GUIDs (or "true"/"1") means a reboot is pending (1).
func ParsePendingRebootUpdates(raw string) sql.NullInt64 {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "", "false", "0", "none":
		return sql.NullInt64{Int64: 0, Valid: true}
	default:
		return sql.NullInt64{Int64: 1, Valid: true}
	}
}

// ValidateCSPExplorerURI validates an ad-hoc read-only OMA-URI for Live CSP Explorer Get inspection.
func ValidateCSPExplorerURI(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", errors.New("oma_uri is required")
	}
	if len(u) > 512 {
		return "", errors.New("oma_uri must be 512 characters or fewer")
	}
	if !strings.HasPrefix(u, "./") {
		if strings.HasPrefix(u, "/") {
			u = "." + u
		} else {
			u = "./" + u
		}
	}
	for _, r := range u {
		if r <= 0x20 || r == 0x7f || r == '<' || r == '>' || r == '"' || r == '\'' {
			return "", errors.New("oma_uri contains invalid whitespace or XML characters")
		}
	}
	if strings.Contains(u, "..") {
		return "", errors.New("oma_uri cannot contain '..' path segments")
	}

	allowedPrefixes := []string{
		"./Device/Vendor/MSFT/",
		"./Vendor/MSFT/",
		"./User/Vendor/MSFT/",
		"./DevDetail/",
		"./DevInfo/",
	}
	validPrefix := false
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(u, p) {
			validPrefix = true
			break
		}
	}
	if !validPrefix {
		return "", errors.New("oma_uri must start with ./Device/Vendor/MSFT/, ./Vendor/MSFT/, ./User/Vendor/MSFT/, ./DevDetail/, or ./DevInfo/")
	}

	// Block secret-bearing write-only CSP subtrees as defence-in-depth.
	low := strings.ToLower(u)
	blockedSubstrings := []string{
		"/accounts/users/",
		"/pfxcertinstall/",
		"/remotewipe/",
	}
	for _, b := range blockedSubstrings {
		if strings.Contains(low, b) {
			return "", fmt.Errorf("oma_uri subtree %q is restricted in CSP Explorer", b)
		}
	}

	return formatDeviceURI(u), nil
}

// SyncCSPQueryStatus updates any Live CSP Explorer rows tied to queueID when SyncML Status arrives.
func SyncCSPQueryStatus(dbConn *sql.DB, queueID int, resultCode string) {
	if dbConn == nil || queueID <= 0 {
		return
	}
	status := "success"
	if resultCode != StatusOK &&
		resultCode != StatusCreated &&
		resultCode != StatusAccepted &&
		resultCode != StatusNoContent &&
		resultCode != StatusAlreadyExists {
		status = "failed"
	}
	_, _ = dbConn.Exec(dbpkg.Rebind(`
		UPDATE device_csp_queries
		SET status = ?, result_code = ?, completed_at = CURRENT_TIMESTAMP
		WHERE queue_id = ?
	`), status, resultCode, queueID)
}

// SyncCSPQueryResult stores the returned OMA-DM <Results> payload on any Live CSP Explorer rows tied to queueID.
func SyncCSPQueryResult(dbConn *sql.DB, queueID int, data string) {
	if dbConn == nil || queueID <= 0 {
		return
	}
	_, _ = dbConn.Exec(dbpkg.Rebind(`
		UPDATE device_csp_queries
		SET status = 'success',
		    result_code = CASE WHEN result_code = '' THEN '200' ELSE result_code END,
		    result_data = ?,
		    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP)
		WHERE queue_id = ?
	`), data, queueID)
}
