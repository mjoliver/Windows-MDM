package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// Shared token primitives used by both the OIDC and builtin auth providers, so
// session/enrollment token behaviour (and single-use enforcement) is identical.

func newEnrollmentClaims(email string, now time.Time) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(enrollmentTokenExpiry)),
			ID:        uuid.New().String(),
		},
		Email:     email,
		TokenType: "enroll",
	}
}

func newSessionClaims(email, role string, now time.Time) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTokenExpiry)),
			ID:        uuid.New().String(),
		},
		Email:     email,
		Role:      role,
		TokenType: "session",
	}
}

func signClaims(secret []byte, claims Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// parseHMACToken parses and verifies an HMAC-signed JWT, rejecting any other
// signing algorithm (defends against alg=none / RS256 confusion).
func parseHMACToken(secret []byte, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// consumeJTI records a one-time use of a token id, rejecting replays. A nil db
// disables enforcement (used by pure unit tests).
func consumeJTI(db *sql.DB, jti string) error {
	if db == nil {
		return nil
	}
	if jti == "" {
		return errors.New("enrollment token missing id (jti)")
	}
	res, err := db.Exec(dbpkg.Rebind(
		`INSERT INTO consumed_enrollment_tokens (jti) VALUES (?) ON CONFLICT(jti) DO NOTHING`), jti)
	if err != nil {
		return fmt.Errorf("recording token use: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("enrollment token already used")
	}
	return nil
}

// appruAllowed validates the Windows enrollment return URL against an allowlist
// of Windows app schemes and the server's own https origin, returning a
// normalised, attribute-safe URL. Prevents enrollment-token exfiltration.
func appruAllowed(appru, baseURL string) (template.URL, bool) {
	u, err := url.Parse(appru)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "ms-app", "ms-appx-web", "ms-aad-brokerplugin":
		return template.URL(u.String()), true
	case "https":
		if base, err := url.Parse(baseURL); err == nil && u.Host != "" && strings.EqualFold(u.Host, base.Host) {
			return template.URL(u.String()), true
		}
	}
	return "", false
}
