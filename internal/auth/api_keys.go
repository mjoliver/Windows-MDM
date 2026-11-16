package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// APIKeyPrefix identifies scoped Latchz automation Bearer tokens.
const APIKeyPrefix = "lzak_"

// ValidAPIKeyScope checks whether scope is one of 'read_only', 'ops', or 'admin'.
func ValidAPIKeyScope(scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "read_only", "ops", "admin":
		return true
	default:
		return false
	}
}

// GenerateAPIKey generates a 24-byte CSPRNG Bearer key ("lzak_<48hex>"), its display prefix, and SHA-256 hex digest.
func GenerateAPIKey() (rawKey, prefix, hashHex string, err error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", "", fmt.Errorf("generating API key: %w", err)
	}
	rawKey = APIKeyPrefix + hex.EncodeToString(raw[:])
	prefix = rawKey[:13] // "lzak_" + 8 hex chars
	hashHex = HashAPIKey(rawKey)
	return rawKey, prefix, hashHex, nil
}

// HashAPIKey computes the lowercase SHA-256 hex digest of a raw lzak_... token.
func HashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}

// ExtractBearerAPIKey extracts a raw "lzak_..." key from Authorization: Bearer <key>, if present.
func ExtractBearerAPIKey(r *http.Request) (string, bool) {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(hdr) < 8 || !strings.EqualFold(hdr[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(hdr[7:])
	if !strings.HasPrefix(tok, APIKeyPrefix) {
		return "", false
	}
	return tok, true
}

// AuthenticateAPIKey validates an lzak_... Bearer token against api_keys, enforcing
// revocation and expiry, updating last_used_at, and returning actor identity + mapped RBAC role + scope.
func AuthenticateAPIKey(db *sql.DB, rawKey string) (actorEmail, role, scope, keyID string, err error) {
	if db == nil {
		return "", "", "", "", errors.New("database is nil")
	}
	trimmed := strings.TrimSpace(rawKey)
	if !strings.HasPrefix(trimmed, APIKeyPrefix) || len(trimmed) < 20 {
		return "", "", "", "", errors.New("invalid API key format")
	}

	hashHex := HashAPIKey(trimmed)
	var (
		name      string
		createdBy string
		expAt     sql.NullTime
		revoked   int
	)
	err = db.QueryRow(dbpkg.Rebind(`
		SELECT id, name, scope, created_by, expires_at, revoked
		FROM api_keys
		WHERE key_hash = ?
	`), hashHex).Scan(&keyID, &name, &scope, &createdBy, &expAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", errors.New("invalid API key")
	}
	if err != nil {
		return "", "", "", "", err
	}
	if revoked != 0 {
		return "", "", "", "", errors.New("API key has been revoked")
	}
	now := time.Now().UTC()
	if expAt.Valid && now.After(expAt.Time) {
		return "", "", "", "", errors.New("API key has expired")
	}

	_, _ = db.Exec(dbpkg.Rebind(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`), now, keyID)

	scope = strings.ToLower(strings.TrimSpace(scope))
	switch scope {
	case "admin":
		role = "admin"
	case "ops":
		role = "admin"
	default:
		scope = "read_only"
		role = "user"
	}

	actorEmail = fmt.Sprintf("apikey:%s(%s)", name, createdBy)
	return actorEmail, role, scope, keyID, nil
}

// IsAPIKeyRequestAllowed enforces fine-grained method/path restrictions for 'read_only' and 'ops' API keys.
func IsAPIKeyRequestAllowed(scope, method, path string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	p := strings.ToLower(strings.TrimSpace(path))

	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "read_only":
		return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
	case "ops":
		// 'ops' can read + sync/scan/rename/query, but cannot wipe devices, manage users, or mint API keys.
		if strings.HasPrefix(p, "/api/users") || strings.HasPrefix(p, "/api/api-keys") {
			return false
		}
		if strings.HasSuffix(p, "/wipe") {
			return false
		}
		return true
	case "admin":
		// 'admin' scope cannot mint/delete API keys or mutate super_admin users unless using interactive session
		if strings.HasPrefix(p, "/api/users") && m != http.MethodGet {
			return false
		}
		return true
	default:
		return false
	}
}
