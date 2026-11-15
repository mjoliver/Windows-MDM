package mdm

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

const (
	OMABitLockerRequireDeviceEncryption = "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption"
	OMABitLockerAllowWarningOtherDisk   = "./Device/Vendor/MSFT/BitLocker/AllowWarningForOtherDiskEncryption"
	OMABitLockerAllowStandardUser       = "./Device/Vendor/MSFT/BitLocker/AllowStandardUserEncryption"
	OMABitLockerEncryptionMethod        = "./Device/Vendor/MSFT/BitLocker/EncryptionMethodByDriveType"
	OMABitLockerRotateRecoveryPasswords = "./Device/Vendor/MSFT/BitLocker/RotateRecoveryPasswords"
	OMABitLockerRotateRecoveryStatus    = "./Device/Vendor/MSFT/BitLocker/Status/RotateRecoveryPasswordsStatus"
)

// BitLocker cipher constants defined by Microsoft's EncryptionMethodByDriveType ADMX CSP.
const (
	BitLockerCipherAESCBC128 = 3
	BitLockerCipherAESCBC256 = 4
	BitLockerCipherXTSAES128 = 6
	BitLockerCipherXTSAES256 = 7
)

// BitLockerPolicySpec describes desired BitLocker CSP enforcement on a Windows 10/11 device.
type BitLockerPolicySpec struct {
	RequireDeviceEncryption bool
	SilentEncryption        bool
	AllowStandardUser       bool
	OSDriveCipher           int
	FixedDriveCipher        int
	RemovableDriveCipher    int
}

// ValidBitLockerCipher returns true if code is a supported EncryptionMethodByDriveType cipher enum.
func ValidBitLockerCipher(code int) bool {
	switch code {
	case BitLockerCipherAESCBC128, BitLockerCipherAESCBC256, BitLockerCipherXTSAES128, BitLockerCipherXTSAES256:
		return true
	default:
		return false
	}
}

// BitLockerCipherLabel returns the display name for a BitLocker cipher enum.
func BitLockerCipherLabel(code int) string {
	switch code {
	case BitLockerCipherAESCBC128:
		return "AES-CBC 128-bit"
	case BitLockerCipherAESCBC256:
		return "AES-CBC 256-bit"
	case BitLockerCipherXTSAES128:
		return "XTS-AES 128-bit"
	case BitLockerCipherXTSAES256:
		return "XTS-AES 256-bit"
	default:
		return fmt.Sprintf("Cipher (%d)", code)
	}
}

// BuildBitLockerEncryptionMethodXML builds the ADMX-backed EncryptionMethodByDriveType
// payload. Microsoft's BitLocker CSP requires all three drive dropdown values to be
// present whenever <enabled/> is configured (omitting one causes SyncML 500).
func BuildBitLockerEncryptionMethodXML(osCipher, fixedCipher, removableCipher int) string {
	if !ValidBitLockerCipher(osCipher) {
		osCipher = BitLockerCipherXTSAES256
	}
	if !ValidBitLockerCipher(fixedCipher) {
		fixedCipher = BitLockerCipherXTSAES256
	}
	if !ValidBitLockerCipher(removableCipher) {
		removableCipher = BitLockerCipherAESCBC256
	}
	return fmt.Sprintf(
		`<enabled/><data id="EncryptionMethodWithXtsOsDropDown_Name" value="%d"/><data id="EncryptionMethodWithXtsFdvDropDown_Name" value="%d"/><data id="EncryptionMethodWithXtsRdvDropDown_Name" value="%d"/>`,
		osCipher, fixedCipher, removableCipher,
	)
}

// EnqueueBitLockerPolicy queues OMA-DM Replace + status Get commands to enforce
// BitLocker CSP settings on a target Windows device.
func EnqueueBitLockerPolicy(dbConn *sql.DB, deviceID string, spec BitLockerPolicySpec) (int, error) {
	reqEnc := "0"
	if spec.RequireDeviceEncryption {
		reqEnc = "1"
	}
	// In BitLocker CSP, AllowWarningForOtherDiskEncryption = 0 disables prompts (silent encryption).
	allowWarn := "1"
	if spec.SilentEncryption {
		allowWarn = "0"
	}
	allowStd := "0"
	if spec.AllowStandardUser {
		allowStd = "1"
	}

	items := []struct {
		uri string
		val string
	}{
		{OMABitLockerEncryptionMethod, BuildBitLockerEncryptionMethodXML(spec.OSDriveCipher, spec.FixedDriveCipher, spec.RemovableDriveCipher)},
		{OMABitLockerAllowWarningOtherDisk, allowWarn},
		{OMABitLockerAllowStandardUser, allowStd},
		{OMABitLockerRequireDeviceEncryption, reqEnc},
	}

	var queued int
	for _, it := range items {
		if _, err := EnqueueReplace(dbConn, deviceID, it.uri, it.val); err != nil {
			return queued, err
		}
		queued++
	}
	if _, err := EnqueueGet(dbConn, deviceID, OMABitLockerEncryptionStatus); err != nil {
		return queued, err
	}
	queued++
	return queued, nil
}

// RetractBitLockerPolicy resets BitLocker CSP enforcement settings on a device
// back to unconfigured defaults (without decrypting an already-encrypted drive).
func RetractBitLockerPolicy(dbConn *sql.DB, deviceID string) (int, error) {
	items := []struct {
		uri string
		val string
	}{
		{OMABitLockerRequireDeviceEncryption, "0"},
		{OMABitLockerAllowWarningOtherDisk, "1"},
		{OMABitLockerAllowStandardUser, "0"},
		{OMABitLockerEncryptionMethod, "<disabled/>"},
	}
	var queued int
	for _, it := range items {
		if _, err := EnqueueReplace(dbConn, deviceID, it.uri, it.val); err != nil {
			return queued, err
		}
		queued++
	}
	if _, err := EnqueueGet(dbConn, deviceID, OMABitLockerEncryptionStatus); err == nil {
		queued++
	}
	return queued, nil
}

// EnqueueBitLockerRotatePasswords queues a RotateRecoveryPasswords request on
// the device's BitLocker CSP along with a status query.
func EnqueueBitLockerRotatePasswords(dbConn *sql.DB, deviceID string) (string, int, error) {
	reqID := uuid.New().String()
	if _, err := EnqueueReplace(dbConn, deviceID, OMABitLockerRotateRecoveryPasswords, reqID); err != nil {
		return "", 0, err
	}
	if _, err := EnqueueGet(dbConn, deviceID, OMABitLockerRotateRecoveryStatus); err != nil {
		return reqID, 1, err
	}
	return reqID, 2, nil
}

var bitLockerStatusBits = []struct {
	bit    uint
	reason string
}{
	{0, "User consent required to launch BitLocker Drive Encryption Wizard"},
	{1, "OS volume encryption cipher does not match policy"},
	{2, "OS volume is currently unprotected"},
	{3, "TPM-only protector required on OS volume but not active"},
	{4, "TPM + PIN protector required on OS volume but not active"},
	{5, "TPM + startup key protector required on OS volume but not active"},
	{6, "TPM + PIN + startup key protector required on OS volume but not active"},
	{7, "TPM protector required on OS volume"},
	{8, "Recovery key backup to cloud/directory has not completed"},
	{9, "One or more fixed data drives are unprotected"},
	{10, "Fixed data drive encryption cipher does not match policy"},
	{11, "Standard user logged in without AllowStandardUserEncryption enabled"},
	{12, "Windows Recovery Environment (WinRE) is not configured"},
	{13, "Compatible TPM 2.0 is not available or not present"},
	{14, "TPM is not ready for BitLocker"},
	{15, "Network unavailable for mandatory recovery key backup"},
	{16, "OS volume encryption type (full vs. used-space) mismatches policy"},
	{17, "Fixed drive encryption type (full vs. used-space) mismatches policy"},
}

// DecodeBitLockerStatus translates Microsoft's BitLocker Status/DeviceEncryptionStatus
// integer bitmask into human-readable compliance diagnostic strings.
func DecodeBitLockerStatus(status int64) []string {
	if status == 0 {
		return nil
	}
	var reasons []string
	u := uint64(status)
	for _, b := range bitLockerStatusBits {
		if (u & (1 << b.bit)) != 0 {
			reasons = append(reasons, b.reason)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("Non-compliant BitLocker status bitmask (0x%X)", status))
	}
	return reasons
}
