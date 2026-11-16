package pki

import (
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"golang.org/x/crypto/ocsp"
)

// Valid RFC 5280 CRLReason codes exposed in Latchz MDM.
const (
	RevocationReasonUnspecified          = 0
	RevocationReasonKeyCompromise        = 1
	RevocationReasonCACompromise         = 2
	RevocationReasonAffiliationChanged   = 3
	RevocationReasonSuperseded           = 4
	RevocationReasonCessationOfOperation = 5
)

// RevocationReasonLabel translates an RFC 5280 CRLReason integer to a readable label.
func RevocationReasonLabel(code int) string {
	switch code {
	case RevocationReasonKeyCompromise:
		return "Key Compromise"
	case RevocationReasonCACompromise:
		return "CA Compromise"
	case RevocationReasonAffiliationChanged:
		return "Affiliation Changed"
	case RevocationReasonSuperseded:
		return "Superseded"
	case RevocationReasonCessationOfOperation:
		return "Cessation of Operation"
	default:
		return "Unspecified"
	}
}

// SetPublicBaseURL configures the external https://<domain> base URL used to embed
// RFC 5280 CRLDistributionPoints (/pki/crl.der) and Authority Information Access
// OCSPServer (/pki/ocsp) URIs into newly minted device and client certificates.
func (ca *CA) SetPublicBaseURL(baseURL string) {
	ca.publicBaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

// PublicBaseURL returns the configured external base URL, if any.
func (ca *CA) PublicBaseURL() string {
	return ca.publicBaseURL
}

// RootCert returns the parsed active Root CA x509.Certificate.
func (ca *CA) RootCert() *x509.Certificate {
	return ca.cert
}

// RootThumbprintSHA1 returns the uppercase SHA-1 thumbprint of the active Root CA.
func (ca *CA) RootThumbprintSHA1() string {
	if ca == nil || ca.cert == nil {
		return ""
	}
	return strings.ToUpper(calculateThumbprint(ca.cert))
}

func (ca *CA) applyRevocationURLs(tmpl *x509.Certificate) {
	if ca == nil || tmpl == nil || ca.publicBaseURL == "" {
		return
	}
	tmpl.CRLDistributionPoints = []string{ca.publicBaseURL + "/pki/crl.der"}
	tmpl.OCSPServer = []string{ca.publicBaseURL + "/pki/ocsp"}
}

// RevokeCertByID marks a leaf certificate row as revoked with an RFC 5280 reason code.
// Refuses to revoke the active root_ca certificate.
func (ca *CA) RevokeCertByID(id int64, reason int) error {
	if ca == nil || ca.db == nil {
		return errors.New("CA database is not initialized")
	}
	if reason < 0 || reason > 10 {
		reason = 0
	}
	var certType string
	err := ca.db.QueryRow(dbpkg.Rebind(`SELECT cert_type FROM certificates WHERE id = ?`), id).Scan(&certType)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	if err != nil {
		return err
	}
	if certType == "root_ca" {
		return errors.New("cannot revoke the active Root CA certificate")
	}
	now := nowFunc().UTC()
	_, err = ca.db.Exec(dbpkg.Rebind(`
		UPDATE certificates
		SET revoked = 1,
		    revoked_at = COALESCE(revoked_at, ?),
		    revocation_reason = ?
		WHERE id = ?
	`), now, reason, id)
	return err
}

// GenerateCRL builds and signs an RFC 5280 X.509 v2 Certificate Revocation List
// containing all revoked non-CA certificates issued by the Latchz Root CA.
func (ca *CA) GenerateCRL(validity time.Duration) (crlDER []byte, crlPEM []byte, crlNum int64, revokedCount int, err error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return nil, nil, 0, 0, errors.New("Root CA is not initialized")
	}
	if validity <= 0 {
		validity = 24 * time.Hour
	}

	now := nowFunc().UTC()
	crlNum = now.Unix()
	if ca.db != nil {
		_, _ = ca.db.Exec(dbpkg.Rebind(`
			INSERT INTO pki_crl_state (id, crl_number, updated_at)
			VALUES ('default', 1, ?)
			ON CONFLICT (id) DO UPDATE SET
				crl_number = pki_crl_state.crl_number + 1,
				updated_at = EXCLUDED.updated_at
		`), now)
		var seq int64
		if qErr := ca.db.QueryRow(dbpkg.Rebind(`SELECT crl_number FROM pki_crl_state WHERE id = 'default'`)).Scan(&seq); qErr == nil && seq > 0 {
			crlNum = seq
		}
	}

	var entries []x509.RevocationListEntry
	if ca.db != nil {
		rows, qErr := ca.db.Query(`
			SELECT serial_number, revoked_at, created_at, COALESCE(revocation_reason, 0)
			FROM certificates
			WHERE revoked = 1 AND cert_type <> 'root_ca'
			ORDER BY id ASC
		`)
		if qErr != nil {
			return nil, nil, 0, 0, fmt.Errorf("querying revoked certificates: %w", qErr)
		}
		defer rows.Close()

		for rows.Next() {
			var serialStr string
			var revAt, createdAt sql.NullTime
			var reason int
			if sErr := rows.Scan(&serialStr, &revAt, &createdAt, &reason); sErr != nil {
				continue
			}
			serialInt, ok := new(big.Int).SetString(strings.TrimSpace(serialStr), 10)
			if !ok {
				continue
			}
			revTime := now
			if revAt.Valid {
				revTime = revAt.Time.UTC()
			} else if createdAt.Valid {
				revTime = createdAt.Time.UTC()
			}
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   serialInt,
				RevocationTime: revTime,
				ReasonCode:     reason,
			})
		}
	}

	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(crlNum),
		ThisUpdate:                now.Add(-5 * time.Minute),
		NextUpdate:                now.Add(validity),
		RevokedCertificateEntries: entries,
	}
	crlDER, err = x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("signing X.509 CRL: %w", err)
	}
	crlPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	return crlDER, crlPEM, crlNum, len(entries), nil
}

// HandleOCSPRequest parses an RFC 6960 DER OCSP request and returns a signed DER OCSP response
// indicating Good, Revoked (with timestamp + reason), or Unknown status.
func (ca *CA) HandleOCSPRequest(reqDER []byte) ([]byte, error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return ocsp.InternalErrorErrorResponse, errors.New("Root CA is not initialized")
	}
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return ocsp.MalformedRequestErrorResponse, fmt.Errorf("malformed OCSP request: %w", err)
	}

	now := nowFunc().UTC()
	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now.Add(-2 * time.Minute),
		NextUpdate:   now.Add(1 * time.Hour),
	}

	if ca.db == nil || req.SerialNumber == nil {
		tmpl.Status = ocsp.Unknown
		return ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	}

	var (
		revoked   int
		revAt     sql.NullTime
		createdAt sql.NullTime
		reason    int
	)
	err = ca.db.QueryRow(dbpkg.Rebind(`
		SELECT revoked, revoked_at, created_at, COALESCE(revocation_reason, 0)
		FROM certificates
		WHERE serial_number = ? AND cert_type <> 'root_ca'
		ORDER BY id DESC LIMIT 1
	`), req.SerialNumber.String()).Scan(&revoked, &revAt, &createdAt, &reason)

	if errors.Is(err, sql.ErrNoRows) {
		tmpl.Status = ocsp.Unknown
	} else if err != nil {
		return ocsp.InternalErrorErrorResponse, err
	} else if revoked != 0 {
		tmpl.Status = ocsp.Revoked
		if revAt.Valid {
			tmpl.RevokedAt = revAt.Time.UTC()
		} else if createdAt.Valid {
			tmpl.RevokedAt = createdAt.Time.UTC()
		} else {
			tmpl.RevokedAt = now
		}
		tmpl.RevocationReason = reason
	} else {
		tmpl.Status = ocsp.Good
	}

	respDER, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		return ocsp.InternalErrorErrorResponse, fmt.Errorf("signing OCSP response: %w", err)
	}
	return respDER, nil
}
