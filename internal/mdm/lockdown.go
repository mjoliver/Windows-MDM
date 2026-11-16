package mdm

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const (
	// Removable USB storage Policy CSP nodes:
	//   - Storage/RemovableDiskDenyWriteAccess is <Format>int</Format> (0=Allowed, 1=Denied)
	//   - ADMX_RemovableStorage/RemovableDisks_Deny{Read,Execute}_Access_2 are ADMX-backed <Format>chr</Format> ("<disabled/>" | "<enabled/>")
	OMAStorageDenyWrite   = "./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess"
	OMAStorageDenyRead    = "./Device/Vendor/MSFT/Policy/Config/ADMX_RemovableStorage/RemovableDisks_DenyRead_Access_2"
	OMAStorageDenyExecute = "./Device/Vendor/MSFT/Policy/Config/ADMX_RemovableStorage/RemovableDisks_DenyExecute_Access_2"
	OMASystemStorageCard  = "./Device/Vendor/MSFT/Policy/Config/System/AllowStorageCard" // 0=Block, 1=Allow

	// DeviceLock Policy CSP nodes (NOTE: DevicePasswordEnabled is INVERTED: 0=Enabled, 1=Disabled,
	// and Windows desktop Policy CSP mandates wrapping DeviceLock Replace operations in <Atomic>!)
	OMADeviceLockAtomicURI       = "./Device/Vendor/MSFT/Policy/Config/DeviceLock"
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
	denyWrite, denyRead, denyExec, allowCard := "0", "<disabled/>", "<disabled/>", "1"
	switch strings.ToLower(strings.TrimSpace(spec.USBStorageMode)) {
	case "read_only":
		denyWrite, denyRead, denyExec, allowCard = "1", "<disabled/>", "<enabled/>", "1"
	case "block_all":
		denyWrite, denyRead, denyExec, allowCard = "1", "<enabled/>", "<enabled/>", "0"
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

	var deviceLockOps []AtomicSubCommand
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
		// CRITICAL: DevicePasswordEnabled = 0 means ENABLED (password required), and Windows desktop
		// Policy CSP requires DeviceLock Replace operations to be wrapped inside an <Atomic> block!
		deviceLockOps = []AtomicSubCommand{
			{CommandType: "Replace", OMAURI: OMADeviceLockPasswordEnabled, Payload: "0", Format: "int"},
			{CommandType: "Replace", OMAURI: OMADeviceLockMinLength, Payload: strconv.Itoa(minLen), Format: "int"},
			{CommandType: "Replace", OMAURI: OMADeviceLockAlphanumeric, Payload: alpha, Format: "int"},
			{CommandType: "Replace", OMAURI: OMADeviceLockMaxInactivity, Payload: strconv.Itoa(inact), Format: "int"},
			{CommandType: "Replace", OMAURI: OMADeviceLockMaxFailed, Payload: strconv.Itoa(failed), Format: "int"},
		}
	} else {
		// Per Microsoft DeviceLock CSP docs, when disabling DevicePasswordEnabled (1), it must be
		// the only policy set from the DeviceLock group, wrapped in <Atomic>.
		deviceLockOps = []AtomicSubCommand{
			{CommandType: "Replace", OMAURI: OMADeviceLockPasswordEnabled, Payload: "1", Format: "int"},
		}
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
	if _, qerr := EnqueueAtomic(dbConn, deviceID, OMADeviceLockAtomicURI, deviceLockOps); qerr != nil {
		return queued, false, qerr
	}
	queued++

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
	directDeletes := []string{
		OMAStorageDenyWrite,
		OMAStorageDenyRead,
		OMAStorageDenyExecute,
		OMASystemStorageCard,
		OMACameraAllow,
		OMAConnectivityAllow,
	}
	if prevKioskEnforced {
		directDeletes = append(directDeletes, OMAAssignedAccessKioskApp)
	}
	var queued int
	for _, u := range directDeletes {
		if _, err := EnqueueDelete(dbConn, deviceID, u); err != nil {
			return queued, err
		}
		queued++
	}

	// Windows desktop Policy CSP requires DeviceLock operations (including Delete)
	// to be wrapped in <Atomic>. Delete dependent child policies first, then explicitly
	// disable DevicePasswordEnabled (1 = Disabled) so Windows's EAS engine clears
	// HKLM\SYSTEM\CurrentControlSet\Control\EAS\Policies without tattooing local SAM
	// accounts, and finally Delete DevicePasswordEnabled from PolicyManager.
	deviceLockChildDeletes := []string{
		OMADeviceLockMinLength,
		OMADeviceLockAlphanumeric,
		OMADeviceLockMaxInactivity,
		OMADeviceLockMaxFailed,
	}
	for _, u := range deviceLockChildDeletes {
		if _, err := EnqueueAtomic(dbConn, deviceID, u+"#delete", []AtomicSubCommand{
			{CommandType: "Delete", OMAURI: u},
		}); err != nil {
			return queued, err
		}
		queued++
	}
	if _, err := EnqueueAtomic(dbConn, deviceID, OMADeviceLockPasswordEnabled+"#disable", []AtomicSubCommand{
		{CommandType: "Replace", OMAURI: OMADeviceLockPasswordEnabled, Payload: "1", Format: "int"},
	}); err != nil {
		return queued, err
	}
	queued++
	if _, err := EnqueueAtomic(dbConn, deviceID, OMADeviceLockPasswordEnabled+"#delete", []AtomicSubCommand{
		{CommandType: "Delete", OMAURI: OMADeviceLockPasswordEnabled},
	}); err != nil {
		return queued, err
	}
	queued++
	return queued, nil
}
