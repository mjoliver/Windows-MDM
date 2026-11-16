package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/devauth"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/policy"
)

const bitLockerPolicySingletonID = "default"

// BitLockerPolicyResponse represents fleet/group BitLocker configuration and vault telemetry.
type BitLockerPolicyResponse struct {
	Enabled                 bool       `json:"enabled"`
	RequireDeviceEncryption bool       `json:"require_device_encryption"`
	SilentEncryption        bool       `json:"silent_encryption"`
	AllowStandardUser       bool       `json:"allow_standard_user"`
	OSDriveCipher           int        `json:"os_drive_cipher"`
	OSDriveCipherLabel      string     `json:"os_drive_cipher_label"`
	FixedDriveCipher        int        `json:"fixed_drive_cipher"`
	FixedDriveCipherLabel   string     `json:"fixed_drive_cipher_label"`
	RemovableDriveCipher    int        `json:"removable_drive_cipher"`
	RemovableCipherLabel    string     `json:"removable_drive_cipher_label"`
	TargetAllDevices        bool       `json:"target_all_devices"`
	GroupIDs                []string   `json:"group_ids"`
	EscrowedDevices         int        `json:"escrowed_devices"`
	TotalEscrowedKeys       int        `json:"total_escrowed_keys"`
	UpdatedBy               string     `json:"updated_by"`
	UpdatedAt               *time.Time `json:"updated_at"`
	EnforcedDevices         int        `json:"enforced_devices,omitempty"`
	CommandsQueued          int        `json:"commands_queued,omitempty"`
}

// RecoveryKeyMeta exposes non-sensitive metadata for an escrowed BitLocker recovery key.
type RecoveryKeyMeta struct {
	ID           string    `json:"id"`
	DeviceID     string    `json:"device_id"`
	VolumeLetter string    `json:"volume_letter"`
	ProtectorID  string    `json:"protector_id"`
	KeyHint      string    `json:"key_hint"`
	Source       string    `json:"source"`
	EscrowedBy   string    `json:"escrowed_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DeviceBitLockerResponse summarizes BitLocker enforcement, decoded status bitmask
// diagnostics, and escrowed recovery key metadata for a single device.
type DeviceBitLockerResponse struct {
	DeviceID         string            `json:"device_id"`
	Enforced         bool              `json:"enforced"`
	EncryptionStatus *int64            `json:"encryption_status"`
	EncryptionLabel  string            `json:"encryption_label"`
	StatusReasons    []string          `json:"status_reasons"`
	RecoveryKeys     []RecoveryKeyMeta `json:"recovery_keys"`
}

func bitLockerAAD(deviceID string) string {
	return "bitlocker:" + deviceID
}

// normalizeRecoveryPassword validates a 48-digit BitLocker numerical recovery
// password and returns its canonical 8x6 hyphenated form plus a masked hint.
func normalizeRecoveryPassword(raw string) (canonical string, hint string, err error) {
	var digits []byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			continue
		default:
			return "", "", errors.New("recovery password must contain only digits and hyphens (48 digits total)")
		}
	}
	if len(digits) != 48 {
		return "", "", fmt.Errorf("recovery password must be exactly 48 digits (got %d)", len(digits))
	}
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = string(digits[i*6 : (i+1)*6])
	}
	return strings.Join(parts, "-"), "••••••-" + parts[7], nil
}

func normalizeProtectorID(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "{" + strings.ToUpper(uuid.New().String()) + "}"
	}
	s = strings.Trim(s, "{}")
	return "{" + strings.ToUpper(s) + "}"
}

func normalizeVolumeLetter(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimRight(s, `\`)
	if s == "" {
		return "C:"
	}
	if len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' {
		return s + ":"
	}
	if len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] == ':' {
		return s
	}
	return s
}

func (h *Handler) readBitLockerPolicy(r *http.Request) (BitLockerPolicyResponse, error) {
	resp := BitLockerPolicyResponse{
		Enabled:                 false,
		RequireDeviceEncryption: true,
		SilentEncryption:        true,
		AllowStandardUser:       true,
		OSDriveCipher:           mdm.BitLockerCipherXTSAES256,
		FixedDriveCipher:        mdm.BitLockerCipherXTSAES256,
		RemovableDriveCipher:    mdm.BitLockerCipherAESCBC256,
		TargetAllDevices:        true,
		GroupIDs:                []string{},
	}

	var (
		enabled, reqEnc, silent, stdUser, targetAll int
		updatedBy                                   string
		updatedAt                                   time.Time
	)
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enabled, require_device_encryption, silent_encryption, allow_standard_user,
		       os_drive_cipher, fixed_drive_cipher, removable_drive_cipher, target_all_devices,
		       COALESCE(updated_by, ''), updated_at
		FROM bitlocker_policies
		WHERE id = ?
	`), bitLockerPolicySingletonID).Scan(
		&enabled, &reqEnc, &silent, &stdUser,
		&resp.OSDriveCipher, &resp.FixedDriveCipher, &resp.RemovableDriveCipher, &targetAll,
		&updatedBy, &updatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return resp, err
	}
	if err == nil {
		resp.Enabled = enabled != 0
		resp.RequireDeviceEncryption = reqEnc != 0
		resp.SilentEncryption = silent != 0
		resp.AllowStandardUser = stdUser != 0
		resp.TargetAllDevices = targetAll != 0
		resp.UpdatedBy = updatedBy
		t := updatedAt
		resp.UpdatedAt = &t
	}

	resp.OSDriveCipherLabel = mdm.BitLockerCipherLabel(resp.OSDriveCipher)
	resp.FixedDriveCipherLabel = mdm.BitLockerCipherLabel(resp.FixedDriveCipher)
	resp.RemovableCipherLabel = mdm.BitLockerCipherLabel(resp.RemovableDriveCipher)

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT group_id FROM group_bitlocker_policies WHERE policy_id = ? ORDER BY group_id
	`), bitLockerPolicySingletonID)
	if err == nil {
		for rows.Next() {
			var gid string
			if rows.Scan(&gid) == nil {
				resp.GroupIDs = append(resp.GroupIDs, gid)
			}
		}
		rows.Close()
	}

	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COUNT(DISTINCT device_id), COUNT(*) FROM device_recovery_keys
	`)).Scan(&resp.EscrowedDevices, &resp.TotalEscrowedKeys)

	return resp, nil
}

// HandleGetBitLockerPolicy returns the current BitLocker CSP policy and vault summary.
// GET /api/bitlocker/policy
func (h *Handler) HandleGetBitLockerPolicy(w http.ResponseWriter, r *http.Request) {
	pol, err := h.readBitLockerPolicy(r)
	if err != nil {
		slog.Error("api: reading bitlocker policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load BitLocker policy")
		return
	}
	respondOK(w, pol)
}

// HandleUpdateBitLockerPolicy saves BitLocker CSP policy settings and reconciles
// OMA-DM enforcement/retraction across active devices.
// PUT /api/bitlocker/policy
func (h *Handler) HandleUpdateBitLockerPolicy(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Enabled                 bool     `json:"enabled"`
		RequireDeviceEncryption bool     `json:"require_device_encryption"`
		SilentEncryption        bool     `json:"silent_encryption"`
		AllowStandardUser       bool     `json:"allow_standard_user"`
		OSDriveCipher           int      `json:"os_drive_cipher"`
		FixedDriveCipher        int      `json:"fixed_drive_cipher"`
		RemovableDriveCipher    int      `json:"removable_drive_cipher"`
		TargetAllDevices        bool     `json:"target_all_devices"`
		GroupIDs                []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.OSDriveCipher == 0 {
		body.OSDriveCipher = mdm.BitLockerCipherXTSAES256
	}
	if body.FixedDriveCipher == 0 {
		body.FixedDriveCipher = mdm.BitLockerCipherXTSAES256
	}
	if body.RemovableDriveCipher == 0 {
		body.RemovableDriveCipher = mdm.BitLockerCipherAESCBC256
	}
	if !mdm.ValidBitLockerCipher(body.OSDriveCipher) ||
		!mdm.ValidBitLockerCipher(body.FixedDriveCipher) ||
		!mdm.ValidBitLockerCipher(body.RemovableDriveCipher) {
		respondErr(w, http.StatusBadRequest, "drive cipher must be 3 (AES-CBC-128), 4 (AES-CBC-256), 6 (XTS-AES-128), or 7 (XTS-AES-256)")
		return
	}

	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO bitlocker_policies (
			id, enabled, require_device_encryption, silent_encryption, allow_standard_user,
			os_drive_cipher, fixed_drive_cipher, removable_drive_cipher, target_all_devices,
			updated_by, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			require_device_encryption = EXCLUDED.require_device_encryption,
			silent_encryption = EXCLUDED.silent_encryption,
			allow_standard_user = EXCLUDED.allow_standard_user,
			os_drive_cipher = EXCLUDED.os_drive_cipher,
			fixed_drive_cipher = EXCLUDED.fixed_drive_cipher,
			removable_drive_cipher = EXCLUDED.removable_drive_cipher,
			target_all_devices = EXCLUDED.target_all_devices,
			updated_by = EXCLUDED.updated_by,
			updated_at = CURRENT_TIMESTAMP
	`),
		bitLockerPolicySingletonID,
		b2i(body.Enabled),
		b2i(body.RequireDeviceEncryption),
		b2i(body.SilentEncryption),
		b2i(body.AllowStandardUser),
		body.OSDriveCipher,
		body.FixedDriveCipher,
		body.RemovableDriveCipher,
		b2i(body.TargetAllDevices),
		actor,
	)
	if err != nil {
		slog.Error("api: saving bitlocker policy", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save BitLocker policy")
		return
	}

	if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM group_bitlocker_policies WHERE policy_id = ?
	`), bitLockerPolicySingletonID); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to update BitLocker groups")
		return
	}
	seenGroups := make(map[string]bool)
	for _, gid := range body.GroupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" || seenGroups[gid] {
			continue
		}
		seenGroups[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_bitlocker_policies (group_id, policy_id) VALUES (?, ?)
		`), gid, bitLockerPolicySingletonID); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit BitLocker policy")
		return
	}

	enforced, queued := policy.ReconcileBitLockerFleet(h.db)
	h.audit(r, actor, "bitlocker.policy_update", "bitlocker_policy", bitLockerPolicySingletonID,
		fmt.Sprintf(`{"enabled":%t,"os_cipher":%d,"enforced_devices":%d,"commands_queued":%d}`,
			body.Enabled, body.OSDriveCipher, enforced, queued))

	resp, err := h.readBitLockerPolicy(r)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload BitLocker policy")
		return
	}
	resp.EnforcedDevices = enforced
	resp.CommandsQueued = queued
	respondOK(w, resp)
}

func (h *Handler) storeRecoveryKey(r *http.Request, deviceID, volumeLetter, protectorID, rawPassword, source, actor string) (RecoveryKeyMeta, error) {
	if h.vault == nil {
		return RecoveryKeyMeta{}, errors.New("encryption vault is not initialized")
	}
	canonPwd, hint, err := normalizeRecoveryPassword(rawPassword)
	if err != nil {
		return RecoveryKeyMeta{}, err
	}
	vol := normalizeVolumeLetter(volumeLetter)
	prot := normalizeProtectorID(protectorID)
	enc, err := h.vault.Encrypt(canonPwd, bitLockerAAD(deviceID))
	if err != nil {
		return RecoveryKeyMeta{}, fmt.Errorf("encrypting recovery key: %w", err)
	}

	newID := uuid.New().String()
	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO device_recovery_keys (
			id, device_id, volume_letter, protector_id, key_encrypted, key_hint, source, escrowed_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (device_id, protector_id) DO UPDATE SET
			volume_letter = EXCLUDED.volume_letter,
			key_encrypted = EXCLUDED.key_encrypted,
			key_hint = EXCLUDED.key_hint,
			source = EXCLUDED.source,
			escrowed_by = EXCLUDED.escrowed_by,
			updated_at = CURRENT_TIMESTAMP
	`), newID, deviceID, vol, prot, enc, hint, source, actor)
	if err != nil {
		return RecoveryKeyMeta{}, err
	}

	var meta RecoveryKeyMeta
	err = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, device_id, volume_letter, protector_id, key_hint, source, escrowed_by, created_at, updated_at
		FROM device_recovery_keys
		WHERE device_id = ? AND protector_id = ?
	`), deviceID, prot).Scan(
		&meta.ID, &meta.DeviceID, &meta.VolumeLetter, &meta.ProtectorID,
		&meta.KeyHint, &meta.Source, &meta.EscrowedBy, &meta.CreatedAt, &meta.UpdatedAt,
	)
	return meta, err
}

// HandleDeviceEscrowBitLocker accepts 48-digit BitLocker recovery passwords directly
// from an enrolled Windows device authenticated via its mTLS X.509 client certificate.
// POST /mdm/bitlocker/escrow
func (h *Handler) HandleDeviceEscrowBitLocker(w http.ResponseWriter, r *http.Request) {
	ident, err := devauth.Resolve(h.db, h.deviceCAPool, r, h.proxyCertHeader)
	if err != nil {
		respondErr(w, http.StatusUnauthorized, "valid device client certificate required")
		return
	}

	type volumeInput struct {
		VolumeLetter     string `json:"volume_letter"`
		ProtectorID      string `json:"protector_id"`
		RecoveryPassword string `json:"recovery_password"`
	}
	var body struct {
		VolumeLetter     string        `json:"volume_letter"`
		ProtectorID      string        `json:"protector_id"`
		RecoveryPassword string        `json:"recovery_password"`
		Volumes          []volumeInput `json:"volumes"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	inputs := body.Volumes
	if len(inputs) == 0 && strings.TrimSpace(body.RecoveryPassword) != "" {
		inputs = []volumeInput{{
			VolumeLetter:     body.VolumeLetter,
			ProtectorID:      body.ProtectorID,
			RecoveryPassword: body.RecoveryPassword,
		}}
	}
	if len(inputs) == 0 {
		respondErr(w, http.StatusBadRequest, "at least one recovery_password is required")
		return
	}

	stored := make([]RecoveryKeyMeta, 0, len(inputs))
	for _, in := range inputs {
		meta, err := h.storeRecoveryKey(r, ident.DeviceID, in.VolumeLetter, in.ProtectorID, in.RecoveryPassword, "device_mtls", "device:"+ident.DeviceID)
		if err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
		stored = append(stored, meta)
	}

	h.audit(r, "device:"+ident.DeviceID, "bitlocker.device_escrow", "device", ident.DeviceID,
		fmt.Sprintf(`{"escrowed_count":%d}`, len(stored)))
	respondCreated(w, map[string]interface{}{
		"status":        "escrowed",
		"device_id":     ident.DeviceID,
		"recovery_keys": stored,
	})
}

// HandleGetDeviceBitLocker returns BitLocker enforcement state, decoded compliance
// bitmask diagnostics, and escrowed recovery key metadata (never plaintext keys).
// GET /api/devices/{id}/bitlocker
func (h *Handler) HandleGetDeviceBitLocker(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var enforced int
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT enforced FROM device_bitlocker_state WHERE device_id = ?
	`), id).Scan(&enforced)

	var encStatus sql.NullInt64
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT encryption_status FROM device_posture WHERE device_id = ?
	`), id).Scan(&encStatus)

	var statusPtr *int64
	reasons := []string{}
	if encStatus.Valid {
		v := encStatus.Int64
		statusPtr = &v
		if decoded := mdm.DecodeBitLockerStatus(v); len(decoded) > 0 {
			reasons = decoded
		}
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id, device_id, volume_letter, protector_id, key_hint, source, escrowed_by, created_at, updated_at
		FROM device_recovery_keys
		WHERE device_id = ?
		ORDER BY volume_letter ASC, updated_at DESC
	`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load recovery keys")
		return
	}
	defer rows.Close()

	keys := []RecoveryKeyMeta{}
	for rows.Next() {
		var k RecoveryKeyMeta
		if err := rows.Scan(&k.ID, &k.DeviceID, &k.VolumeLetter, &k.ProtectorID, &k.KeyHint, &k.Source, &k.EscrowedBy, &k.CreatedAt, &k.UpdatedAt); err == nil {
			keys = append(keys, k)
		}
	}

	respondOK(w, DeviceBitLockerResponse{
		DeviceID:         id,
		Enforced:         enforced != 0,
		EncryptionStatus: statusPtr,
		EncryptionLabel:  encryptionLabel(statusPtr),
		StatusReasons:    reasons,
		RecoveryKeys:     keys,
	})
}

// HandleAdminEscrowBitLockerKey allows an administrator to escrow or import a
// 48-digit BitLocker recovery password into the AES-256-GCM vault for a device.
// POST /api/devices/{id}/bitlocker/escrow
func (h *Handler) HandleAdminEscrowBitLockerKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		VolumeLetter     string `json:"volume_letter"`
		ProtectorID      string `json:"protector_id"`
		RecoveryPassword string `json:"recovery_password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	meta, err := h.storeRecoveryKey(r, id, body.VolumeLetter, body.ProtectorID, body.RecoveryPassword, "admin_escrow", actor)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit(r, actor, "bitlocker.admin_escrow", "device", id,
		fmt.Sprintf(`{"volume":%q,"protector_id":%q}`, meta.VolumeLetter, meta.ProtectorID))
	respondCreated(w, meta)
}

// HandleRevealBitLockerKey decrypts a single escrowed 48-digit BitLocker recovery
// password and writes a mandatory audit_log entry recording the reveal event.
// POST /api/devices/{id}/bitlocker/keys/{keyId}/reveal
func (h *Handler) HandleRevealBitLockerKey(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	keyID := chi.URLParam(r, "keyId")
	actor := emailFromCtx(r)

	if h.vault == nil {
		respondErr(w, http.StatusInternalServerError, "encryption vault is not initialized")
		return
	}
	reason, ok := h.extractAndValidateRevealReason(w, r)
	if !ok {
		return
	}

	var (
		vol, prot, enc string
	)
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT volume_letter, protector_id, key_encrypted
		FROM device_recovery_keys
		WHERE id = ? AND device_id = ?
	`), keyID, deviceID).Scan(&vol, &prot, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "recovery key not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	plain, err := h.vault.Decrypt(enc, bitLockerAAD(deviceID))
	if err != nil {
		slog.Error("api: decrypting bitlocker recovery key", "device_id", deviceID, "key_id", keyID, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to decrypt recovery key")
		return
	}

	h.audit(r, actor, "bitlocker.reveal_key", "device", deviceID,
		fmt.Sprintf(`{"key_id":%q,"volume":%q,"protector_id":%q,"reason":%q}`, keyID, vol, prot, reason))
	slog.Info("bitlocker recovery key revealed", "device_id", deviceID, "protector_id", prot, "actor", actor)

	respondOK(w, map[string]string{
		"id":                keyID,
		"device_id":         deviceID,
		"volume_letter":     vol,
		"protector_id":      prot,
		"recovery_password": plain,
	})
}

// HandleDeleteBitLockerKey removes an escrowed BitLocker protector record.
// DELETE /api/devices/{id}/bitlocker/keys/{keyId}
func (h *Handler) HandleDeleteBitLockerKey(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	keyID := chi.URLParam(r, "keyId")
	actor := emailFromCtx(r)

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM device_recovery_keys WHERE id = ? AND device_id = ?
	`), keyID, deviceID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete recovery key")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "recovery key not found")
		return
	}

	h.audit(r, actor, "bitlocker.delete_key", "device", deviceID, fmt.Sprintf(`{"key_id":%q}`, keyID))
	respondOK(w, map[string]string{"status": "deleted"})
}

// HandleRotateBitLockerKeys queues a BitLocker CSP RotateRecoveryPasswords request
// on the target device.
// POST /api/devices/{id}/bitlocker/rotate
func (h *Handler) HandleRotateBitLockerKeys(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, deviceID); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	reqID, queued, err := mdm.EnqueueBitLockerRotatePasswords(h.db, deviceID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue BitLocker recovery key rotation")
		return
	}

	h.wakeDevice(deviceID)
	h.audit(r, actor, "bitlocker.rotate_keys", "device", deviceID, fmt.Sprintf(`{"request_id":%q}`, reqID))
	respondOK(w, map[string]interface{}{
		"status":          "queued",
		"request_id":      reqID,
		"commands_queued": queued,
	})
}
