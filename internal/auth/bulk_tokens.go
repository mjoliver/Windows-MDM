package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// BulkTokenPrefix identifies multi-use / time-bounded staging & OOBE enrollment tokens.
const BulkTokenPrefix = "lzbt_"

// GenerateBulkToken mints a cryptographically random 24-byte bulk enrollment token,
// returning its raw secret ("lzbt_<48 hex chars>"), display prefix ("lzbt_<8 hex>"),
// and lowercase SHA-256 hex digest stored in bulk_enrollment_tokens.
func GenerateBulkToken() (rawToken, prefix, sha256Hex string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generating bulk token: %w", err)
	}
	hexRand := hex.EncodeToString(b)
	rawToken = BulkTokenPrefix + hexRand
	prefix = BulkTokenPrefix + hexRand[:8]
	sha256Hex = HashBulkToken(rawToken)
	return rawToken, prefix, sha256Hex, nil
}

// HashBulkToken returns the SHA-256 hex digest of a raw bulk enrollment token.
func HashBulkToken(rawToken string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawToken)))
	return hex.EncodeToString(sum[:])
}

// VerifyBulkEnrollmentTokenUnconsumed checks that rawToken is an active, unrevoked,
// unexpired bulk enrollment token with remaining capacity WITHOUT incrementing use_count.
// Used when /auth/login?flow=enroll hands the token back to DeviceEnroller.exe, which
// then consumes it once during POST /wstep.
func VerifyBulkEnrollmentTokenUnconsumed(db *sql.DB, rawToken string) (string, error) {
	if db == nil {
		return "", errors.New("bulk enrollment token requires database")
	}
	trimmed := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(trimmed, BulkTokenPrefix) {
		return "", errors.New("not a bulk enrollment token")
	}
	hash := HashBulkToken(trimmed)
	now := nowFunc().UTC()

	var createdBy string
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT created_by
		FROM bulk_enrollment_tokens
		WHERE token_hash = ?
		  AND revoked = 0
		  AND (expires_at IS NULL OR expires_at > ?)
		  AND (max_uses = 0 OR use_count < max_uses)
	`), hash, now).Scan(&createdBy)
	if err != nil {
		return "", errors.New("bulk enrollment token invalid, expired, revoked, or exhausted")
	}
	if strings.TrimSpace(createdBy) == "" {
		createdBy = "bulk-enroll@latchz.local"
	}
	return createdBy, nil
}

// ConsumeBulkEnrollmentToken validates a "lzbt_..." token by SHA-256 hash and
// atomically increments its use_count when unrevoked, unexpired, and below max_uses.
func ConsumeBulkEnrollmentToken(db *sql.DB, rawToken string) (createdByEmail, autoGroupID, tokenID string, err error) {
	if db == nil {
		return "", "", "", errors.New("bulk enrollment token requires database")
	}
	trimmed := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(trimmed, BulkTokenPrefix) {
		return "", "", "", errors.New("not a bulk enrollment token")
	}
	hash := HashBulkToken(trimmed)
	now := nowFunc().UTC()

	res, err := db.Exec(dbpkg.Rebind(`
		UPDATE bulk_enrollment_tokens
		SET use_count = use_count + 1
		WHERE token_hash = ?
		  AND revoked = 0
		  AND (expires_at IS NULL OR expires_at > ?)
		  AND (max_uses = 0 OR use_count < max_uses)
	`), hash, now)
	if err != nil {
		return "", "", "", fmt.Errorf("consuming bulk enrollment token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", "", "", errors.New("bulk enrollment token invalid, expired, revoked, or exhausted")
	}

	err = db.QueryRow(dbpkg.Rebind(`
		SELECT id, COALESCE(created_by, ''), COALESCE(auto_group_id, '')
		FROM bulk_enrollment_tokens
		WHERE token_hash = ?
	`), hash).Scan(&tokenID, &createdByEmail, &autoGroupID)
	if err != nil {
		return "", "", "", err
	}
	if strings.TrimSpace(createdByEmail) == "" {
		createdByEmail = "bulk-enroll@latchz.local"
	}
	return createdByEmail, autoGroupID, tokenID, nil
}

// LookupBulkTokenAutoGroup returns (tokenID, autoGroupID) for a raw bulk token.
func LookupBulkTokenAutoGroup(db *sql.DB, rawToken string) (tokenID, autoGroupID string) {
	if db == nil || !strings.HasPrefix(strings.TrimSpace(rawToken), BulkTokenPrefix) {
		return "", ""
	}
	_ = db.QueryRow(dbpkg.Rebind(`
		SELECT id, COALESCE(auto_group_id, '')
		FROM bulk_enrollment_tokens
		WHERE token_hash = ?
	`), HashBulkToken(rawToken)).Scan(&tokenID, &autoGroupID)
	return tokenID, autoGroupID
}
