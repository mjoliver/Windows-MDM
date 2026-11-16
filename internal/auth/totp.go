package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/vault"
)

const (
	// TOTPVaultAADPrefix binds encrypted TOTP secrets to the owning user email.
	TOTPVaultAADPrefix = "totp:"
	totpPeriodSeconds  = 30
	totpDigits         = 6
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret generates a 20-byte (160-bit) CSPRNG secret encoded in RFC 4648 Base32 (no padding).
func GenerateTOTPSecret() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating TOTP secret: %w", err)
	}
	return totpBase32.EncodeToString(raw[:]), nil
}

// BuildOTPAuthURL builds a standard Google Authenticator / Microsoft Authenticator / 1Password URI.
func BuildOTPAuthURL(issuer, email, base32Secret string) string {
	iss := strings.TrimSpace(issuer)
	if iss == "" {
		iss = "Latchz MDM"
	}
	acct := strings.TrimSpace(email)
	label := url.PathEscape(iss + ":" + acct)
	q := url.Values{}
	q.Set("secret", strings.ToUpper(strings.TrimSpace(base32Secret)))
	q.Set("issuer", iss)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ComputeTOTPCode computes the 6-digit RFC 6238 TOTP code for base32Secret at timestamp ts.
func ComputeTOTPCode(base32Secret string, ts time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(base32Secret), " ", ""))
	clean = strings.TrimRight(clean, "=")
	key, err := totpBase32.DecodeString(clean)
	if err != nil || len(key) == 0 {
		return "", errors.New("invalid Base32 TOTP secret")
	}

	counter := uint64(ts.Unix() / totpPeriodSeconds)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp), nil
}

// VerifyTOTPCode verifies a 6-digit RFC 6238 TOTP code allowing ±1 time step (30s) clock skew.
func VerifyTOTPCode(base32Secret, code string, now time.Time) bool {
	trimmed := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), " ", ""), "-", "")
	if len(trimmed) != totpDigits {
		return false
	}
	for _, delta := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		expected, err := ComputeTOTPCode(base32Secret, now.Add(delta))
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(trimmed)) == 1 {
			return true
		}
	}
	return false
}

// GenerateRecoveryCodes generates count (default 8) human-friendly XXXX-XXXX single-use codes
// along with their SHA-256 hex digests for database storage.
func GenerateRecoveryCodes(count int) (plainCodes []string, hashesJSON string, err error) {
	if count <= 0 {
		count = 8
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	plainCodes = make([]string, 0, count)
	hashes := make([]string, 0, count)

	for i := 0; i < count; i++ {
		var rnd [8]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, "", err
		}
		var b strings.Builder
		for j := 0; j < 8; j++ {
			if j == 4 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(rnd[j])%len(alphabet)])
		}
		code := b.String()
		plainCodes = append(plainCodes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	raw, _ := json.Marshal(hashes)
	return plainCodes, string(raw), nil
}

func hashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	sum := sha256.Sum256([]byte("latchz-recovery:" + norm))
	return hex.EncodeToString(sum[:])
}

// VerifyUserSecondFactor checks either a 6-digit TOTP code OR a single-use recovery code
// (atomically consuming the recovery code if matched).
func VerifyUserSecondFactor(db *sql.DB, v *vault.Vault, email, submittedCode string, now time.Time) (bool, error) {
	if db == nil {
		return false, errors.New("database is nil")
	}
	normEmail := strings.ToLower(strings.TrimSpace(email))
	var encSecret, recoveryJSON string
	var enabled int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT totp_enabled, COALESCE(totp_secret_encrypted, ''), COALESCE(totp_recovery_hashes, '[]')
		FROM users WHERE LOWER(email) = ?
	`), normEmail).Scan(&enabled, &encSecret, &recoveryJSON)
	if err != nil {
		return false, err
	}
	if enabled == 0 {
		return true, nil
	}
	code := strings.TrimSpace(submittedCode)
	if code == "" {
		return false, nil
	}

	if v != nil && encSecret != "" {
		plainSecret, decErr := v.Decrypt(encSecret, TOTPVaultAADPrefix+normEmail)
		if decErr == nil && VerifyTOTPCode(plainSecret, code, now) {
			return true, nil
		}
	}

	// Check single-use recovery codes
	var hashes []string
	if err := json.Unmarshal([]byte(recoveryJSON), &hashes); err == nil && len(hashes) > 0 {
		candidateHash := hashRecoveryCode(code)
		matchIdx := -1
		for idx, h := range hashes {
			if subtle.ConstantTimeCompare([]byte(h), []byte(candidateHash)) == 1 {
				matchIdx = idx
				break
			}
		}
		if matchIdx >= 0 {
			remaining := append([]string{}, hashes[:matchIdx]...)
			remaining = append(remaining, hashes[matchIdx+1:]...)
			remBytes, _ := json.Marshal(remaining)
			_, _ = db.Exec(dbpkg.Rebind(`
				UPDATE users SET totp_recovery_hashes = ? WHERE LOWER(email) = ?
			`), string(remBytes), normEmail)
			return true, nil
		}
	}

	return false, nil
}
