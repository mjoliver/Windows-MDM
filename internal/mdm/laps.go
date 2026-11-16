package mdm

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/vault"
)

const (
	// OMAAccountsUsersPrefix is the native Windows 10/11 Accounts CSP root for
	// creating local accounts (supports <Add> only; username <= 20 characters).
	OMAAccountsUsersPrefix = "./Device/Vendor/MSFT/Accounts/Users"

	// OMAPolicyLocalUsersAndGroups is the Policy CSP node used to incrementally
	// add the active ephemeral local admin to BUILTIN\Administrators (S-1-5-32-544)
	// and strip all previously rotated ephemeral accounts without touching
	// existing human or built-in administrators.
	OMAPolicyLocalUsersAndGroups = "./Device/Vendor/MSFT/Policy/Config/LocalUsersAndGroups/Configure"

	// BuiltinAdministratorsSID is the locale-independent well-known Windows SID
	// for BUILTIN\Administrators.
	BuiltinAdministratorsSID = "S-1-5-32-544"

	// VaultLAPSSentinel is stored in command_queue.payload instead of the
	// plaintext password; HandleOMADM decrypts pending_password_encrypted in
	// memory strictly when serializing SyncML over mTLS to the target device.
	VaultLAPSSentinel = "[VAULT:laps_pending]"

	// LAPSVaultAADPrefix binds every LAPS ciphertext to its owning device ID.
	LAPSVaultAADPrefix = "laps:"
)

const (
	lapsUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	lapsLower   = "abcdefghijkmnopqrstuvwxyz"
	lapsDigits  = "23456789"
	lapsSymbols = "!@#%*+-_="
	lapsAll     = lapsUpper + lapsLower + lapsDigits + lapsSymbols
)

// NormalizeLAPSPrefix validates and normalizes the ephemeral admin username
// prefix so `<prefix>-<4hex>` is guaranteed <= 20 characters for Accounts CSP.
func NormalizeLAPSPrefix(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		p = "lzadm"
	}
	if len(p) < 2 || len(p) > 12 {
		return "", errors.New("account_prefix must be between 2 and 12 characters")
	}
	for i, r := range p {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if i == 0 && !isLetter {
			return "", errors.New("account_prefix must start with an ASCII letter")
		}
		if !isLetter && !isDigit && r != '-' && r != '_' {
			return "", errors.New("account_prefix may only contain ASCII letters, digits, '-' or '_'")
		}
	}
	return p, nil
}

// GenerateLAPSCredentials generates a fresh <=20-char local username
// (`<prefix>-<4hex>`) avoiding any previously provisioned usernames in avoid,
// paired with a high-entropy password satisfying all 4 Windows complexity classes.
func GenerateLAPSCredentials(prefix string, length int, avoid map[string]bool) (username, password string, err error) {
	normPrefix, err := NormalizeLAPSPrefix(prefix)
	if err != nil {
		return "", "", err
	}
	if length == 0 {
		length = 20
	}
	if length < 14 || length > 32 {
		return "", "", errors.New("password_length must be between 14 and 32")
	}

	for attempt := 0; attempt < 64; attempt++ {
		var suffixBytes [2]byte
		if _, err := rand.Read(suffixBytes[:]); err != nil {
			return "", "", fmt.Errorf("laps: generating random suffix: %w", err)
		}
		candidate := fmt.Sprintf("%s-%s", normPrefix, hex.EncodeToString(suffixBytes[:]))
		if !avoid[strings.ToLower(candidate)] {
			username = candidate
			break
		}
	}
	if username == "" {
		var suffixBytes [3]byte
		if _, err := rand.Read(suffixBytes[:]); err != nil {
			return "", "", fmt.Errorf("laps: generating fallback suffix: %w", err)
		}
		username = fmt.Sprintf("%s-%s", normPrefix, hex.EncodeToString(suffixBytes[:]))
	}

	pwdBytes := make([]byte, length)
	requiredPools := []string{lapsUpper, lapsLower, lapsDigits, lapsSymbols}
	for i, pool := range requiredPools {
		ch, err := randChar(pool)
		if err != nil {
			return "", "", err
		}
		pwdBytes[i] = ch
	}
	for i := len(requiredPools); i < length; i++ {
		ch, err := randChar(lapsAll)
		if err != nil {
			return "", "", err
		}
		pwdBytes[i] = ch
	}
	// Cryptographic Fisher-Yates shuffle
	for i := length - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", "", fmt.Errorf("laps: shuffling password: %w", err)
		}
		j := int(jBig.Int64())
		pwdBytes[i], pwdBytes[j] = pwdBytes[j], pwdBytes[i]
	}

	return username, string(pwdBytes), nil
}

func randChar(pool string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		return 0, fmt.Errorf("laps: reading CSPRNG: %w", err)
	}
	return pool[idx.Int64()], nil
}

func xmlAttrEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// BuildLAPSGroupConfigXML builds the Policy/Config/LocalUsersAndGroups/Configure
// XML payload (`action="U"` on S-1-5-32-544) that adds activeAccount (if non-empty)
// and removes every retired ephemeral account from BUILTIN\Administrators.
func BuildLAPSGroupConfigXML(activeAccount string, removeAccounts []string) string {
	active := strings.TrimSpace(activeAccount)
	var b strings.Builder
	b.WriteString(`<GroupConfiguration><accessgroup desc="`)
	b.WriteString(BuiltinAdministratorsSID)
	b.WriteString(`"><group action="U"/>`)
	if active != "" {
		b.WriteString(`<add member="`)
		b.WriteString(xmlAttrEscape(active))
		b.WriteString(`"/>`)
	}
	seen := make(map[string]bool)
	if active != "" {
		seen[strings.ToLower(active)] = true
	}
	for _, raw := range removeAccounts {
		acct := strings.TrimSpace(raw)
		if acct == "" {
			continue
		}
		low := strings.ToLower(acct)
		if seen[low] {
			continue
		}
		seen[low] = true
		b.WriteString(`<remove member="`)
		b.WriteString(xmlAttrEscape(acct))
		b.WriteString(`"/>`)
	}
	b.WriteString(`</accessgroup></GroupConfiguration>`)
	return b.String()
}

func parseAccountList(csv string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if !seen[low] {
			seen[low] = true
			out = append(out, p)
		}
	}
	return out
}

func joinAccountList(accounts []string) string {
	var clean []string
	seen := make(map[string]bool)
	for _, raw := range accounts {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if !seen[low] {
			seen[low] = true
			clean = append(clean, p)
		}
	}
	// Cap historical list to the 25 most recent retired accounts so SyncML stays tiny
	if len(clean) > 25 {
		clean = clean[len(clean)-25:]
	}
	return strings.Join(clean, ",")
}

// EnqueueLAPSRotation provisions a new ephemeral local administrator account
// (`Accounts/Users/<new>/Password` + `LocalUserGroup=2`), seals its password in
// the AES-256-GCM vault, and queues an incremental `LocalUsersAndGroups/Configure`
// policy update stripping any prior ephemeral accounts from BUILTIN\Administrators.
func EnqueueLAPSRotation(dbConn *sql.DB, v *vault.Vault, deviceID, prefix string, pwdLen int) (string, int, error) {
	if v == nil {
		return "", 0, errors.New("secret vault is not configured (set server.master_secret)")
	}

	var activeAcct, prevAcct, pendingAcct, retiredCSV string
	_ = dbConn.QueryRow(dbpkg.Rebind(`
		SELECT active_account, previous_account, pending_account, retired_accounts
		FROM device_local_admins
		WHERE device_id = ?
	`), deviceID).Scan(&activeAcct, &prevAcct, &pendingAcct, &retiredCSV)

	avoid := make(map[string]bool)
	var priorToStrip []string
	for _, a := range append([]string{activeAcct, prevAcct, pendingAcct}, parseAccountList(retiredCSV)...) {
		trimmed := strings.TrimSpace(a)
		if trimmed != "" {
			avoid[strings.ToLower(trimmed)] = true
			priorToStrip = append(priorToStrip, trimmed)
		}
	}

	newUser, newPwd, err := GenerateLAPSCredentials(prefix, pwdLen, avoid)
	if err != nil {
		return "", 0, err
	}

	encPwd, err := v.Encrypt(newPwd, LAPSVaultAADPrefix+deviceID)
	if err != nil {
		return "", 0, fmt.Errorf("encrypting LAPS password: %w", err)
	}

	// Cancel any superseded pending Accounts/Users or LocalUsersAndGroups commands
	// for this device so the new rotation executes cleanly in strict FIFO order.
	_, _ = dbConn.Exec(dbpkg.Rebind(`
		DELETE FROM command_queue
		WHERE device_id = ? AND status = 'pending'
		  AND (oma_uri LIKE './Device/Vendor/MSFT/Accounts/Users/%' OR oma_uri = ?)
	`), deviceID, OMAPolicyLocalUsersAndGroups)

	pwdURI := fmt.Sprintf("%s/%s/Password", OMAAccountsUsersPrefix, newUser)
	grpURI := fmt.Sprintf("%s/%s/LocalUserGroup", OMAAccountsUsersPrefix, newUser)

	pwdQueueID, err := EnqueueAdd(dbConn, deviceID, pwdURI, VaultLAPSSentinel)
	if err != nil {
		return "", 0, err
	}
	if _, err := EnqueueAdd(dbConn, deviceID, grpURI, "2"); err != nil {
		return "", 1, err
	}
	queued := 2

	groupXML := BuildLAPSGroupConfigXML(newUser, priorToStrip)
	if groupXML != "" {
		if _, err := EnqueueReplace(dbConn, deviceID, OMAPolicyLocalUsersAndGroups, groupXML); err != nil {
			return "", queued, err
		}
		queued++
	}

	nextStatus := "provisioning"
	if strings.TrimSpace(activeAcct) != "" {
		nextStatus = "rotating"
	}

	// Preserve any un-ACKed pending account in retired_accounts so it is also stripped
	retiredNext := parseAccountList(retiredCSV)
	if pendingAcct != "" && !strings.EqualFold(pendingAcct, activeAcct) {
		retiredNext = append(retiredNext, pendingAcct)
	}

	_, err = dbConn.Exec(dbpkg.Rebind(`
		INSERT INTO device_local_admins (
			device_id, pending_account, pending_password_encrypted, pending_queue_id,
			retired_accounts, status, last_error, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, '', CURRENT_TIMESTAMP)
		ON CONFLICT (device_id) DO UPDATE SET
			pending_account            = EXCLUDED.pending_account,
			pending_password_encrypted = EXCLUDED.pending_password_encrypted,
			pending_queue_id           = EXCLUDED.pending_queue_id,
			retired_accounts           = EXCLUDED.retired_accounts,
			status                     = EXCLUDED.status,
			last_error                 = '',
			updated_at                 = CURRENT_TIMESTAMP
	`), deviceID, newUser, encPwd, pwdQueueID, joinAccountList(retiredNext), nextStatus)
	if err != nil {
		return "", queued, fmt.Errorf("saving pending LAPS state: %w", err)
	}

	return newUser, queued, nil
}

// EnqueueLAPSRevocation strips all Latchz-provisioned ephemeral local admin
// accounts from BUILTIN\Administrators when LAPS governance is disabled or a
// device leaves the governed group scope.
func EnqueueLAPSRevocation(dbConn *sql.DB, deviceID string) (int, error) {
	var activeAcct, activeEnc, prevAcct, prevEnc, pendingAcct, retiredCSV, status string
	err := dbConn.QueryRow(dbpkg.Rebind(`
		SELECT active_account, active_password_encrypted,
		       previous_account, previous_password_encrypted,
		       pending_account, retired_accounts, status
		FROM device_local_admins
		WHERE device_id = ?
	`), deviceID).Scan(&activeAcct, &activeEnc, &prevAcct, &prevEnc, &pendingAcct, &retiredCSV, &status)
	if errors.Is(err, sql.ErrNoRows) || status == "unconfigured" || status == "revoked" {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	_, _ = dbConn.Exec(dbpkg.Rebind(`
		DELETE FROM command_queue
		WHERE device_id = ? AND status = 'pending'
		  AND (oma_uri LIKE './Device/Vendor/MSFT/Accounts/Users/%' OR oma_uri = ?)
	`), deviceID, OMAPolicyLocalUsersAndGroups)

	retired := parseAccountList(retiredCSV)
	if activeAcct != "" {
		retired = append(retired, activeAcct)
	}
	if pendingAcct != "" {
		retired = append(retired, pendingAcct)
	}

	queued := 0
	if len(retired) > 0 {
		xmlPayload := BuildLAPSGroupConfigXML("", retired)
		if _, err := EnqueueReplace(dbConn, deviceID, OMAPolicyLocalUsersAndGroups, xmlPayload); err != nil {
			return 0, err
		}
		queued = 1
	}

	nextPrevAcct := prevAcct
	nextPrevEnc := prevEnc
	if activeAcct != "" {
		nextPrevAcct = activeAcct
		nextPrevEnc = activeEnc
	}

	_, err = dbConn.Exec(dbpkg.Rebind(`
		UPDATE device_local_admins
		SET active_account = '',
		    active_password_encrypted = '',
		    previous_account = ?,
		    previous_password_encrypted = ?,
		    pending_account = '',
		    pending_password_encrypted = '',
		    pending_queue_id = 0,
		    retired_accounts = ?,
		    status = 'revoked',
		    last_error = '',
		    expires_at = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE device_id = ?
	`), nextPrevAcct, nextPrevEnc, joinAccountList(retired), deviceID)
	return queued, err
}

func (h *Handler) resolveVaultPayloads(deviceID string, pending []PendingCommand) {
	if h.vault == nil {
		return
	}
	for i := range pending {
		if pending[i].Payload == VaultLAPSSentinel {
			var encPwd string
			err := h.db.QueryRow(dbpkg.Rebind(`
				SELECT pending_password_encrypted FROM device_local_admins WHERE device_id = ?
			`), deviceID).Scan(&encPwd)
			if err != nil || encPwd == "" {
				slog.Error("mdm: missing encrypted pending LAPS password", "device_id", deviceID, "err", err)
				continue
			}
			plain, err := h.vault.Decrypt(encPwd, LAPSVaultAADPrefix+deviceID)
			if err != nil {
				slog.Error("mdm: decrypting pending LAPS password for SyncML delivery", "device_id", deviceID, "err", err)
				continue
			}
			pending[i].Payload = plain
			continue
		}

		if idx := strings.Index(pending[i].Payload, VaultWiFiSentinelPrefix); idx >= 0 {
			rest := pending[i].Payload[idx+len(VaultWiFiSentinelPrefix):]
			if end := strings.IndexByte(rest, ']'); end > 0 {
				profID := rest[:end]
				sentinel := VaultWiFiSentinelPrefix + profID + "]"
				var encPSK string
				err := h.db.QueryRow(dbpkg.Rebind(`
					SELECT wifi_psk_encrypted FROM network_pki_profiles WHERE id = ?
				`), profID).Scan(&encPSK)
				if err != nil || encPSK == "" {
					slog.Error("mdm: missing encrypted Wi-Fi PSK", "profile_id", profID, "err", err)
					continue
				}
				plainPSK, err := h.vault.Decrypt(encPSK, WiFiVaultAADPrefix+profID)
				if err != nil {
					slog.Error("mdm: decrypting Wi-Fi PSK for SyncML delivery", "profile_id", profID, "err", err)
					continue
				}
				pending[i].Payload = strings.ReplaceAll(pending[i].Payload, sentinel, xmlEscapeText(plainPSK))
			}
		}

		if strings.Contains(pending[i].Payload, VaultPFXPwdSentinelPrefix) {
			if idx := strings.Index(pending[i].Payload, VaultPFXPwdSentinelPrefix); idx >= 0 {
				rest := pending[i].Payload[idx+len(VaultPFXPwdSentinelPrefix):]
				if end := strings.IndexByte(rest, ']'); end > 0 {
					tokenBody := rest[:end]
					devPart, profID, ok := strings.Cut(tokenBody, ":")
					if ok && devPart == deviceID && profID != "" {
						var encPwd, encBlob string
						err := h.db.QueryRow(dbpkg.Rebind(`
							SELECT pfx_password_encrypted, pfx_b64_encrypted
							FROM device_issued_client_certs
							WHERE device_id = ? AND profile_id = ?
						`), deviceID, profID).Scan(&encPwd, &encBlob)
						if err != nil {
							slog.Error("mdm: missing encrypted client PFX material", "device_id", deviceID, "profile_id", profID, "err", err)
							continue
						}
						plainPwd, err := h.vault.Decrypt(encPwd, PFXVaultPwdAAD(deviceID, profID))
						if err != nil {
							slog.Error("mdm: decrypting client PFX password for SyncML delivery", "device_id", deviceID, "profile_id", profID, "err", err)
							continue
						}
						plainBlob, err := h.vault.Decrypt(encBlob, PFXVaultBlobAAD(deviceID, profID))
						if err != nil {
							slog.Error("mdm: decrypting client PFX blob for SyncML delivery", "device_id", deviceID, "profile_id", profID, "err", err)
							continue
						}
						pending[i].Payload = strings.ReplaceAll(pending[i].Payload, PFXPwdVaultSentinel(deviceID, profID), plainPwd)
						pending[i].Payload = strings.ReplaceAll(pending[i].Payload, PFXBlobVaultSentinel(deviceID, profID), plainBlob)
					}
				}
			}
		}
	}
}

func (h *Handler) handleLAPSCommandStatus(deviceID string, queueID int, statusData string) {
	var pendingQueueID int
	var activeAcct, activeEnc, pendingAcct, pendingEnc, retiredCSV string
	err := h.db.QueryRow(dbpkg.Rebind(`
		SELECT pending_queue_id, active_account, active_password_encrypted,
		       pending_account, pending_password_encrypted, retired_accounts
		FROM device_local_admins
		WHERE device_id = ?
	`), deviceID).Scan(&pendingQueueID, &activeAcct, &activeEnc, &pendingAcct, &pendingEnc, &retiredCSV)
	if err != nil || pendingQueueID == 0 || pendingQueueID != queueID {
		return
	}

	ok := statusData == StatusOK ||
		statusData == StatusCreated ||
		statusData == StatusAccepted ||
		statusData == StatusNoContent ||
		statusData == StatusAlreadyExists

	if !ok {
		_, _ = h.db.Exec(dbpkg.Rebind(`
			UPDATE device_local_admins
			SET status = 'failed',
			    last_error = ?,
			    pending_queue_id = 0,
			    updated_at = CURRENT_TIMESTAMP
			WHERE device_id = ?
		`), "Accounts CSP returned SyncML status "+statusData, deviceID)
		return
	}

	var rotDays int
	if err := h.db.QueryRow(dbpkg.Rebind(`
		SELECT rotation_days FROM laps_policies WHERE id = 'default'
	`)).Scan(&rotDays); err != nil || rotDays <= 0 {
		rotDays = 14
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(rotDays) * 24 * time.Hour)

	retired := parseAccountList(retiredCSV)
	nextPrevAcct := ""
	nextPrevEnc := ""
	if activeAcct != "" {
		nextPrevAcct = activeAcct
		nextPrevEnc = activeEnc
		retired = append(retired, activeAcct)
	}

	if _, err := h.db.Exec(dbpkg.Rebind(`
		UPDATE device_local_admins
		SET active_account = ?,
		    active_password_encrypted = ?,
		    previous_account = CASE WHEN ? <> '' THEN ? ELSE previous_account END,
		    previous_password_encrypted = CASE WHEN ? <> '' THEN ? ELSE previous_password_encrypted END,
		    retired_accounts = ?,
		    pending_account = '',
		    pending_password_encrypted = '',
		    pending_queue_id = 0,
		    status = 'active',
		    last_error = '',
		    last_rotated_at = ?,
		    expires_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE device_id = ?
	`),
		pendingAcct, pendingEnc,
		nextPrevAcct, nextPrevAcct,
		nextPrevEnc, nextPrevEnc,
		joinAccountList(retired),
		now, expiresAt, deviceID,
	); err != nil {
		slog.Error("mdm: promoting pending LAPS account to active", "device_id", deviceID, "err", err)
		return
	}

	slog.Info("mdm: Cloud LAPS ephemeral admin active",
		"device_id", deviceID,
		"account", pendingAcct,
		"retired_previous", nextPrevAcct,
		"expires_at", expiresAt.Format(time.RFC3339),
	)
}

// IsDeviceLAPSGoverned reports whether Cloud LAPS is enabled and applies to deviceID.
func IsDeviceLAPSGoverned(dbConn *sql.DB, deviceID string) (governed bool, prefix string, pwdLen int, rotDays int) {
	var enabled, targetAll int
	err := dbConn.QueryRow(dbpkg.Rebind(`
		SELECT enabled, account_prefix, password_length, rotation_days, target_all_devices
		FROM laps_policies
		WHERE id = 'default'
	`)).Scan(&enabled, &prefix, &pwdLen, &rotDays, &targetAll)
	if err != nil || enabled == 0 {
		return false, "lzadm", 20, 14
	}
	if targetAll != 0 {
		return true, prefix, pwdLen, rotDays
	}
	var match int
	_ = dbConn.QueryRow(dbpkg.Rebind(`
		SELECT COUNT(*)
		FROM group_laps_policies glp
		JOIN device_group_members dgm ON dgm.group_id = glp.group_id
		WHERE glp.policy_id = 'default' AND dgm.device_id = ?
	`), deviceID).Scan(&match)
	return match > 0, prefix, pwdLen, rotDays
}

// ensureLAPSQueued automatically enqueues initial provisioning or expired-password
// rotation before pending commands are loaded during an OMA-DM check-in.
func (h *Handler) ensureLAPSQueued(deviceID string) {
	if h.vault == nil {
		return
	}
	governed, prefix, pwdLen, _ := IsDeviceLAPSGoverned(h.db, deviceID)
	if !governed {
		return
	}

	var status, activeAcct string
	var pendingQueueID int
	var expiresAt sql.NullTime
	err := h.db.QueryRow(dbpkg.Rebind(`
		SELECT status, active_account, pending_queue_id, expires_at
		FROM device_local_admins
		WHERE device_id = ?
	`), deviceID).Scan(&status, &activeAcct, &pendingQueueID, &expiresAt)

	if pendingQueueID > 0 {
		return // rotation already in flight
	}

	needsRotation := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		needsRotation = true
	case err != nil:
		return
	case status == "unconfigured" || status == "revoked" || activeAcct == "":
		needsRotation = true
	case status == "active" && expiresAt.Valid && time.Now().UTC().After(expiresAt.Time):
		needsRotation = true
	}

	if !needsRotation {
		return
	}

	if _, _, err := EnqueueLAPSRotation(h.db, h.vault, deviceID, prefix, pwdLen); err != nil {
		slog.Error("mdm: auto-reconciling LAPS rotation", "device_id", deviceID, "err", err)
	}
}
