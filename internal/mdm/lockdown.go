package mdm

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const (
	// Removable USB storage Policy CSP nodes (<Format>int</Format>, 0=Allowed, 1=Denied)
	OMAStorageDenyWrite   = "./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess"
	OMAStorageDenyRead    = "./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyReadAccess"
	OMAStorageDenyExecute = "./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyExecuteAccess"
	OMASystemStorageCard  = "./Device/Vendor/MSFT/Policy/Config/System/AllowStorageCard" // 0=Block, 1=Allow

	// DeviceLock Policy CSP nodes (NOTE: DevicePasswordEnabled is INVERTED: 0=Enabled, 1=Disabled!)
	OMADeviceLockPasswordEnabled = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordEnabled"
	OMADeviceLockMinLength       = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength"
	OMADeviceLockAlphanumeric    = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/AlphanumericDevicePasswordRequired"
	OMADeviceLockMaxInactivity   = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock"
	OMADeviceLockMaxFailed       = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxDevicePasswordFailedAttempts"

	// Hardware privacy Policy CSP nodes
	OMACameraAllow       = "./Device/Vendor/MSFT/Policy/Config/Camera/AllowCamera"          // 0=Block, 1=Allow
	OMAConnectivityAllow = "./Device/Vendor/MSFT/Policy/Config/Connectivity/AllowBluetooth" // 0=Disallow, 2=Allow

	// Single-app kiosk AssignedAccess CSP node (<Format>chr</Format> JSON)
	OMAAssignedAccessKioskApp = "./Device/Vendor/MSFT/AssignedAccess/KioskModeApp"
)

// DeviceLockdownSpec describes USB removable storage, DeviceLock password/PIN/screen
// timeout, hardware peripheral privacy, and single-app AssignedAccess kiosk policies.
type DeviceLockdownSpec struct {
	USBStorageMode       string // "allow" | "read_only" | "block_all"
	RequirePassword      bool
	MinPasswordLength    int // 4..16
	AlphanumericRequired bool
	MaxInactivityMinutes int // 0..999
	MaxFailedAttempts    int // 0 or 4..16
	AllowCamera          bool
	AllowBluetooth       bool
	KioskMode            string // "none" | "single_app"
	KioskAccount         string
	KioskAppAUMID        string
}

type kioskAppJSON struct {
	Account string `json:"Account"`
	AUMID   string `json:"AUMID"`
}

// ValidUSBStorageMode validates removable USB storage modes.
func ValidUSBStorageMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "allow", "read_only", "block_all":
		return true
	default:
		return false
	}
}

// BuildKioskModeAppJSON builds the JSON payload expected by ./Device/Vendor/MSFT/AssignedAccess/KioskModeApp.
func BuildKioskModeAppJSON(account, aumid string) (string, error) {
	acct := strings.TrimSpace(account)
	if acct == "" {
		acct = "KioskUser"
	}
	app := strings.TrimSpace(aumid)
	if app == "" {
		return "", errors.New("kiosk_app_aumid is required when kiosk_mode is 'single_app'")
	}
	raw, err := json.Marshal(kioskAppJSON{Account: acct, AUMID: app})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// EnqueueDeviceLockdown queues OMA-DM Replace/Delete commands for Storage, DeviceLock,
// Camera/Bluetooth, and AssignedAccess CSPs.
func EnqueueDeviceLockdown(dbConn *sql.DB, deviceID string, spec DeviceLockdownSpec, prevKioskEnforced bool) (queued int, kioskNow bool, err error) {
	denyWrite, denyRead, denyExec, allowCard := "0", "0", "0", "1"
	switch strings.ToLower(strings.TrimSpace(spec.USBStorageMode)) {
	case "read_only":
		denyWrite, denyRead, denyExec, allowCard = "1", "0", "1", "1"
	case "block_all":
		denyWrite, denyRead, denyExec, allowCard = "1", "1", "1", "0"
	}

	items := []struct {
		uri string
		val string
	}{
		{OMAStorageDenyWrite, denyWrite},
		{OMAStorageDenyRead, denyRead},
		{OMAStorageDenyExecute, denyExec},
		{OMASystemStorageCard, allowCard},
	}

	if spec.RequirePassword {
		minLen := spec.MinPasswordLength
		if minLen < 4 {
			minLen = 8
		}
		if minLen > 16 {
			minLen = 16
		}
		alpha := "0"
		if spec.AlphanumericRequired {
			alpha = "1"
		}
		inact := spec.MaxInactivityMinutes
		if inact < 0 {
			inact = 0
		}
		if inact > 999 {
			inact = 999
		}
		failed := spec.MaxFailedAttempts
		if failed < 0 || (failed > 0 && failed < 4) {
			failed = 0
		}
		if failed > 16 {
			failed = 16
		}
		// CRITICAL: DevicePasswordEnabled = 0 means ENABLED (password required)!
		items = append(items,
			struct{ uri, val string }{OMADeviceLockPasswordEnabled, "0"},
			struct{ uri, val string }{OMADeviceLockMinLength, strconv.Itoa(minLen)},
			struct{ uri, val string }{OMADeviceLockAlphanumeric, alpha},
			struct{ uri, val string }{OMADeviceLockMaxInactivity, strconv.Itoa(inact)},
			struct{ uri, val string }{OMADeviceLockMaxFailed, strconv.Itoa(failed)},
		)
	} else {
		items = append(items, struct{ uri, val string }{OMADeviceLockPasswordEnabled, "1"})
	}

	camVal := "0"
	if spec.AllowCamera {
		camVal = "1"
	}
	btVal := "0"
	if spec.AllowBluetooth {
		btVal = "2"
	}
	items = append(items,
		struct{ uri, val string }{OMACameraAllow, camVal},
		struct{ uri, val string }{OMAConnectivityAllow, btVal},
	)

	for _, it := range items {
		if _, qerr := EnqueueReplace(dbConn, deviceID, it.uri, it.val); qerr != nil {
			return queued, false, qerr
		}
		queued++
	}

	if strings.EqualFold(strings.TrimSpace(spec.KioskMode), "single_app") {
		payload, jerr := BuildKioskModeAppJSON(spec.KioskAccount, spec.KioskAppAUMID)
		if jerr != nil {
			return queued, false, jerr
		}
		if _, qerr := EnqueueReplace(dbConn, deviceID, OMAAssignedAccessKioskApp, payload); qerr != nil {
			return queued, false, qerr
		}
		queued++
		kioskNow = true
	} else if prevKioskEnforced {
		if _, qerr := EnqueueDelete(dbConn, deviceID, OMAAssignedAccessKioskApp); qerr == nil {
			queued++
		}
	}

	return queued, kioskNow, nil
}

// RetractDeviceLockdown queues <Delete> commands to remove MDM Storage, DeviceLock,
// hardware peripheral, and AssignedAccess kiosk overrides from a device.
func RetractDeviceLockdown(dbConn *sql.DB, deviceID string, prevKioskEnforced bool) (int, error) {
	uris := []string{
		OMAStorageDenyWrite,
		OMAStorageDenyRead,
		OMAStorageDenyExecute,
		OMASystemStorageCard,
		OMADeviceLockMinLength,
		OMADeviceLockAlphanumeric,
		OMADeviceLockMaxInactivity,
		OMADeviceLockMaxFailed,
		OMADeviceLockPasswordEnabled,
		OMACameraAllow,
		OMAConnectivityAllow,
	}
	if prevKioskEnforced {
		uris = append(uris, OMAAssignedAccessKioskApp)
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
