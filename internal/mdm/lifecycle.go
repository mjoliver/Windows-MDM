package mdm

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

const (
	// MDMProviderID is the OMA-DM management server ProviderID provisioned during WSTEP.
	MDMProviderID = "LatchzMDM"

	// OMADMClientUnenroll triggers clean, non-destructive MDM unenrollment (retire)
	// via Microsoft's DMClient CSP without factory-resetting user files or OS state.
	OMADMClientUnenroll = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Unenroll"
)

var randMacroRe = regexp.MustCompile(`(?i)%RAND:([0-9]{1,2})%`)
var serialMacroRe = regexp.MustCompile(`(?i)%SERIAL%`)

// ValidateHostnameTemplate validates and normalizes a Windows computer name or
// DevDetail/Ext/Microsoft/DNSComputerName template (supporting %SERIAL% and %RAND:x%).
func ValidateHostnameTemplate(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("hostname is required")
	}
	if len(s) > 63 {
		return "", errors.New("hostname must be 63 characters or fewer")
	}

	// Normalize supported Windows MDM macros to uppercase (%SERIAL%, %RAND:n%).
	hasMacro := false
	normalized := serialMacroRe.ReplaceAllStringFunc(s, func(_ string) string {
		hasMacro = true
		return "%SERIAL%"
	})

	var macroErr error
	normalized = randMacroRe.ReplaceAllStringFunc(normalized, func(m string) string {
		sub := randMacroRe.FindStringSubmatch(m)
		if len(sub) != 2 {
			macroErr = errors.New("invalid %RAND:x% macro")
			return m
		}
		n, err := strconv.Atoi(sub[1])
		if err != nil || n < 1 || n > 63 {
			macroErr = errors.New("%RAND:x% length must be between 1 and 63")
			return m
		}
		hasMacro = true
		return fmt.Sprintf("%%RAND:%d%%", n)
	})
	if macroErr != nil {
		return "", macroErr
	}

	// Strip validated macros to inspect literal characters.
	literal := strings.ReplaceAll(normalized, "%SERIAL%", "X")
	literal = randMacroRe.ReplaceAllString(literal, "X")
	if strings.Contains(literal, "%") {
		return "", errors.New("unsupported macro in hostname (only %SERIAL% and %RAND:x% are supported)")
	}
	if strings.HasPrefix(literal, "-") || strings.HasSuffix(literal, "-") {
		return "", errors.New("hostname cannot start or end with a hyphen")
	}

	allDigits := true
	for _, r := range literal {
		switch {
		case r >= '0' && r <= '9':
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			allDigits = false
		case r == '-':
			allDigits = false
		default:
			return "", fmt.Errorf("hostname contains invalid character %q (allowed: A-Z, 0-9, '-', %%SERIAL%%, %%RAND:x%%)", r)
		}
	}
	if !hasMacro && allDigits {
		return "", errors.New("hostname cannot consist solely of digits")
	}
	return normalized, nil
}

// EnqueueRenameDevice queues a Replace command on ./DevDetail/Ext/Microsoft/DNSComputerName
// followed by a Get command to refresh the reported hostname.
func EnqueueRenameDevice(dbConn *sql.DB, deviceID, hostname string) (int64, error) {
	norm, err := ValidateHostnameTemplate(hostname)
	if err != nil {
		return 0, err
	}
	qID, err := EnqueueReplace(dbConn, deviceID, OMADevDetailComputerName, norm)
	if err != nil {
		return 0, err
	}
	_, _ = EnqueueGet(dbConn, deviceID, OMADevDetailComputerName)
	return qID, nil
}

// EnqueueRetireDevice cancels pending configuration commands and queues a clean,
// non-destructive DMClient Unenroll Exec command for LatchzMDM.
func EnqueueRetireDevice(dbConn *sql.DB, deviceID string) (int64, error) {
	_, _ = dbConn.Exec(dbpkg.Rebind(`
		UPDATE command_queue
		SET status = 'cancelled'
		WHERE device_id = ? AND status = 'pending' AND oma_uri <> ?
	`), deviceID, OMADMClientUnenroll)

	return EnqueueExec(dbConn, deviceID, OMADMClientUnenroll, MDMProviderID)
}
