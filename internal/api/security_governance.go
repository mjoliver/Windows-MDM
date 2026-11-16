package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/auth"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

const defaultGovernanceID = "default"

// APIKeyItem represents a scoped automation Bearer API key (raw key returned ONCE at creation).
type APIKeyItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	RawKey     string     `json:"key,omitempty"`
	Scope      string     `json:"scope"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Revoked    bool       `json:"revoked"`
	CreatedAt  time.Time  `json:"created_at"`
}

// SecurityGovernanceSettings exposes fleet-wide secret reveal governance controls.
type SecurityGovernanceSettings struct {
	RequireRevealJustification bool       `json:"require_reveal_justification"`
	UpdatedBy                  string     `json:"updated_by"`
	UpdatedAt                  *time.Time `json:"updated_at"`
}

// extractAndValidateRevealReason parses an optional JSON {"reason": "..."} body on
// BitLocker/LAPS secret reveal endpoints and enforces require_reveal_justification when enabled.
func (h *Handler) extractAndValidateRevealReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var reason string
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
		if err == nil && len(strings.TrimSpace(string(raw))) > 0 {
			var payload struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				respondErr(w, http.StatusBadRequest, "invalid JSON body")
				return "", false
			}
			reason = strings.TrimSpace(payload.Reason)
		}
	}
	if len(reason) > 250 {
		reason = reason[:250]
	}

	var reqJust int
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COALESCE(require_reveal_justification, 0)
		FROM security_governance_settings
		WHERE id = ?
	`), defaultGovernanceID).Scan(&reqJust)

	if reqJust != 0 && len(reason) < 3 {
		respondErr(w, http.StatusBadRequest, "justification reason (min 3 characters) is required by security governance policy")
		return "", false
	}
	return reason, true
}

// HandleGetSecurityGovernance returns secret-reveal governance settings.
// GET /api/security/governance
func (h *Handler) HandleGetSecurityGovernance(w http.ResponseWriter, r *http.Request) {
	out := SecurityGovernanceSettings{}
	var reqInt int
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT require_reveal_justification, updated_by, updated_at
		FROM security_governance_settings
		WHERE id = ?
	`), defaultGovernanceID).Scan(&reqInt, &out.UpdatedBy, &updatedAt)
	if err == nil {
		out.RequireRevealJustification = reqInt != 0
		t := updatedAt
		out.UpdatedAt = &t
	}
	respondOK(w, out)
}

// HandleUpdateSecurityGovernance updates secret-reveal governance settings.
// PUT /api/security/governance
func (h *Handler) HandleUpdateSecurityGovernance(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		RequireRevealJustification bool `json:"require_reveal_justification"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	now := time.Now().UTC()
	_, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO security_governance_settings (id, require_reveal_justification, updated_by, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			require_reveal_justification = EXCLUDED.require_reveal_justification,
			updated_by                   = EXCLUDED.updated_by,
			updated_at                   = EXCLUDED.updated_at
	`), defaultGovernanceID, boolToSQLInt(body.RequireRevealJustification), actor, now)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to save security governance settings")
		return
	}

	h.audit(r, actor, "security.governance_update", "security_governance", defaultGovernanceID,
		fmt.Sprintf(`{"require_reveal_justification":%t}`, body.RequireRevealJustification))

	h.HandleGetSecurityGovernance(w, r)
}

// HandleGetMyTOTPStatus returns whether the signed-in user has TOTP 2FA enabled.
// GET /api/me/totp
func (h *Handler) HandleGetMyTOTPStatus(w http.ResponseWriter, r *http.Request) {
	actor := strings.ToLower(strings.TrimSpace(emailFromCtx(r)))
	var enabled int
	var recoveryJSON string
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COALESCE(totp_enabled, 0), COALESCE(totp_recovery_hashes, '[]')
		FROM users WHERE LOWER(email) = ?
	`), actor).Scan(&enabled, &recoveryJSON)
	if errors.Is(err, sql.ErrNoRows) {
		respondOK(w, map[string]interface{}{"enabled": false, "recovery_codes_remaining": 0})
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load TOTP status")
		return
	}
	var hashes []string
	_ = json.Unmarshal([]byte(recoveryJSON), &hashes)
	respondOK(w, map[string]interface{}{
		"enabled":                  enabled != 0,
		"recovery_codes_remaining": len(hashes),
	})
}

// HandleSetupMyTOTP generates and vault-seals a pending Base32 TOTP secret for the signed-in user.
// POST /api/me/totp/setup
func (h *Handler) HandleSetupMyTOTP(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
		return
	}
	actor := strings.ToLower(strings.TrimSpace(emailFromCtx(r)))
	if actor == "" || strings.HasPrefix(actor, "apikey:") {
		respondErr(w, http.StatusBadRequest, "interactive user session required to enroll TOTP")
		return
	}

	var exists int
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT COUNT(*) FROM users WHERE LOWER(email) = ?`), actor).Scan(&exists)
	if exists == 0 {
		respondErr(w, http.StatusNotFound, "user account not found")
		return
	}

	sec, err := auth.GenerateTOTPSecret()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}
	enc, err := h.vault.Encrypt(sec, auth.TOTPVaultAADPrefix+actor)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to encrypt TOTP secret")
		return
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE users
		SET totp_secret_encrypted = ?, totp_enabled = 0, totp_recovery_hashes = '[]'
		WHERE LOWER(email) = ?
	`), enc, actor)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to store pending TOTP secret")
		return
	}

	respondOK(w, map[string]interface{}{
		"secret":      sec,
		"otpauth_url": auth.BuildOTPAuthURL("Latchz MDM", actor, sec),
	})
}

// HandleEnableMyTOTP verifies a 6-digit TOTP code against the pending secret, activates 2FA,
// and returns 8 single-use recovery codes.
// POST /api/me/totp/enable
func (h *Handler) HandleEnableMyTOTP(w http.ResponseWriter, r *http.Request) {
	if h.vault == nil {
		respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured")
		return
	}
	actor := strings.ToLower(strings.TrimSpace(emailFromCtx(r)))
	var body struct {
		Code string `json:"code"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	var enc string
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT COALESCE(totp_secret_encrypted, '') FROM users WHERE LOWER(email) = ?
	`), actor).Scan(&enc)
	if err != nil || enc == "" {
		respondErr(w, http.StatusBadRequest, "run POST /api/me/totp/setup first")
		return
	}

	plainSec, err := h.vault.Decrypt(enc, auth.TOTPVaultAADPrefix+actor)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to decrypt pending TOTP secret")
		return
	}
	if !auth.VerifyTOTPCode(plainSec, body.Code, time.Now().UTC()) {
		respondErr(w, http.StatusBadRequest, "invalid 6-digit authenticator code")
		return
	}

	plainCodes, hashesJSON, err := auth.GenerateRecoveryCodes(8)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to generate recovery codes")
		return
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE users SET totp_enabled = 1, totp_recovery_hashes = ? WHERE LOWER(email) = ?
	`), hashesJSON, actor)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to enable TOTP")
		return
	}

	h.audit(r, actor, "auth.totp_enable", "user", actor, "")
	respondOK(w, map[string]interface{}{
		"enabled":        true,
		"recovery_codes": plainCodes,
	})
}

// HandleDisableMyTOTP disables TOTP 2FA on the signed-in user's account.
// POST /api/me/totp/disable
func (h *Handler) HandleDisableMyTOTP(w http.ResponseWriter, r *http.Request) {
	actor := strings.ToLower(strings.TrimSpace(emailFromCtx(r)))
	_, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE users
		SET totp_enabled = 0, totp_secret_encrypted = '', totp_recovery_hashes = '[]'
		WHERE LOWER(email) = ?
	`), actor)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to disable TOTP")
		return
	}
	h.audit(r, actor, "auth.totp_disable", "user", actor, "")
	respondOK(w, map[string]interface{}{"enabled": false})
}

// HandleAdminResetUserTOTP allows a super_admin to clear a locked-out user's TOTP 2FA.
// POST /api/users/{id}/totp-reset
func (h *Handler) HandleAdminResetUserTOTP(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	target, err := h.getUserByID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE users
		SET totp_enabled = 0, totp_secret_encrypted = '', totp_recovery_hashes = '[]'
		WHERE id = ?
	`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reset user TOTP")
		return
	}
	h.audit(r, actor, "user.totp_reset", "user", id, fmt.Sprintf(`{"email":%q}`, target.Email))
	respondOK(w, map[string]interface{}{"reset": true, "id": id})
}

// HandleListAPIKeys returns all automation API keys (never exposing raw secrets).
// GET /api/api-keys
func (h *Handler) HandleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, name, key_prefix, scope, created_by, expires_at, last_used_at, revoked, created_at
		FROM api_keys
		ORDER BY created_at DESC
	`)
	if err != nil {
		slog.Error("api: listing API keys", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list API keys")
		return
	}
	defer rows.Close()

	out := []APIKeyItem{}
	for rows.Next() {
		var it APIKeyItem
		var expAt, lastUsed sql.NullTime
		var rev int
		if err := rows.Scan(
			&it.ID, &it.Name, &it.KeyPrefix, &it.Scope, &it.CreatedBy,
			&expAt, &lastUsed, &rev, &it.CreatedAt,
		); err != nil {
			continue
		}
		if expAt.Valid {
			t := expAt.Time
			it.ExpiresAt = &t
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			it.LastUsedAt = &t
		}
		it.Revoked = rev != 0
		out = append(out, it)
	}
	respondOK(w, out)
}

// HandleCreateAPIKey mints a new scoped Bearer API key ("lzak_..."), returning the raw key ONCE.
// POST /api/api-keys
func (h *Handler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	if strings.HasPrefix(actor, "apikey:") {
		respondErr(w, http.StatusForbidden, "API keys cannot mint other API keys")
		return
	}

	var body struct {
		Name          string `json:"name"`
		Scope         string `json:"scope"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		respondErr(w, http.StatusBadRequest, "name is required (max 80 chars)")
		return
	}
	scope := strings.ToLower(strings.TrimSpace(body.Scope))
	if scope == "" {
		scope = "read_only"
	}
	if !auth.ValidAPIKeyScope(scope) {
		respondErr(w, http.StatusBadRequest, "scope must be 'read_only', 'ops', or 'admin'")
		return
	}
	if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
		respondErr(w, http.StatusBadRequest, "expires_in_days must be between 0 (no expiry) and 3650")
		return
	}

	rawKey, prefix, hashHex, err := auth.GenerateAPIKey()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	id := uuid.NewString()
	now := time.Now().UTC()
	var expPtr *time.Time
	var expArg interface{}
	if body.ExpiresInDays > 0 {
		e := now.Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
		expPtr = &e
		expArg = e
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO api_keys (id, name, key_prefix, key_hash, scope, created_by, expires_at, revoked, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
	`), id, name, prefix, hashHex, scope, actor, expArg, now)
	if err != nil {
		slog.Error("api: inserting API key", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save API key")
		return
	}

	h.audit(r, actor, "apikey.create", "api_key", id,
		fmt.Sprintf(`{"name":%q,"prefix":%q,"scope":%q}`, name, prefix, scope))

	respondCreated(w, APIKeyItem{
		ID:        id,
		Name:      name,
		KeyPrefix: prefix,
		RawKey:    rawKey,
		Scope:     scope,
		CreatedBy: actor,
		ExpiresAt: expPtr,
		Revoked:   false,
		CreatedAt: now,
	})
}

// HandleDeleteAPIKey revokes (or hard-deletes with ?hard=1 or if already revoked) an API key.
// DELETE /api/api-keys/{id}
func (h *Handler) HandleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	hard := r.URL.Query().Get("hard") == "1" || r.URL.Query().Get("hard") == "true"

	var alreadyRevoked int
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT revoked FROM api_keys WHERE id = ?`), id).Scan(&alreadyRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "API key not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	if hard || alreadyRevoked != 0 {
		_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM api_keys WHERE id = ?`), id)
		h.audit(r, actor, "apikey.delete", "api_key", id, "")
		respondOK(w, map[string]interface{}{"deleted": true, "revoked": true, "id": id})
		return
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`UPDATE api_keys SET revoked = 1 WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to revoke API key")
		return
	}
	h.audit(r, actor, "apikey.revoke", "api_key", id, "")
	respondOK(w, map[string]interface{}{"deleted": false, "revoked": true, "id": id})
}
