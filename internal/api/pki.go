package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/pki"
)

// PKISummary exposes Root CA metadata, CRL/OCSP endpoints, and fleet certificate counts.
type PKISummary struct {
	CASubject         string    `json:"ca_subject"`
	CAThumbprintSHA1  string    `json:"ca_thumbprint_sha1"`
	CASerialNumber    string    `json:"ca_serial_number"`
	CANotBefore       time.Time `json:"ca_not_before"`
	CANotAfter        time.Time `json:"ca_not_after"`
	CRLURL            string    `json:"crl_url"`
	CRLPEMURL         string    `json:"crl_pem_url"`
	OCSPURL           string    `json:"ocsp_url"`
	CRLSequenceNumber int64     `json:"crl_sequence_number"`
	TotalIssued       int       `json:"total_issued"`
	ActiveCerts       int       `json:"active_certs"`
	Expiring30d       int       `json:"expiring_30d"`
	RevokedCerts      int       `json:"revoked_certs"`
}

// IssuedCertificateItem describes a single leaf certificate issued by the Latchz Root CA.
type IssuedCertificateItem struct {
	ID                    int64      `json:"id"`
	CertType              string     `json:"cert_type"`
	Subject               string     `json:"subject"`
	Thumbprint            string     `json:"thumbprint"`
	SerialNumber          string     `json:"serial_number"`
	DeviceID              string     `json:"device_id"`
	DeviceName            string     `json:"device_name"`
	NotBefore             time.Time  `json:"not_before"`
	NotAfter              time.Time  `json:"not_after"`
	DaysRemaining         int        `json:"days_remaining"`
	Revoked               bool       `json:"revoked"`
	RevokedAt             *time.Time `json:"revoked_at"`
	RevocationReason      int        `json:"revocation_reason"`
	RevocationReasonLabel string     `json:"revocation_reason_label"`
	CreatedAt             time.Time  `json:"created_at"`
}

func (h *Handler) resolvedPKIBaseURL(r *http.Request) string {
	if h.ca != nil && h.ca.PublicBaseURL() != "" {
		return h.ca.PublicBaseURL()
	}
	if base := strings.TrimRight(strings.TrimSpace(h.contentBaseURL), "/"); base != "" {
		return base
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = "enterpriseenrollment.lab.local"
	}
	return scheme + "://" + host
}

// HandleServeCRLDER serves a freshly signed RFC 5280 DER CRL at GET /pki/crl.der.
func (h *Handler) HandleServeCRLDER(w http.ResponseWriter, _ *http.Request) {
	if h.ca == nil {
		http.Error(w, "CA not configured", http.StatusServiceUnavailable)
		return
	}
	der, _, _, _, err := h.ca.GenerateCRL(24 * time.Hour)
	if err != nil {
		slog.Error("pki: generating DER CRL", "err", err)
		http.Error(w, "failed to generate CRL", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", `inline; filename="latchz-ca.crl"`)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

// HandleServeCRLPEM serves a freshly signed RFC 5280 PEM CRL at GET /pki/crl.pem.
func (h *Handler) HandleServeCRLPEM(w http.ResponseWriter, _ *http.Request) {
	if h.ca == nil {
		http.Error(w, "CA not configured", http.StatusServiceUnavailable)
		return
	}
	_, pemBytes, _, _, err := h.ca.GenerateCRL(24 * time.Hour)
	if err != nil {
		slog.Error("pki: generating PEM CRL", "err", err)
		http.Error(w, "failed to generate CRL", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="latchz-ca-crl.pem"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBytes)
}

// HandleOCSP serves RFC 6960 OCSP responses over POST /pki/ocsp and GET /pki/ocsp/{reqB64}.
func (h *Handler) HandleOCSP(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		http.Error(w, "CA not configured", http.StatusServiceUnavailable)
		return
	}

	var reqDER []byte
	var err error
	if r.Method == http.MethodGet {
		rawParam := chi.URLParam(r, "reqB64")
		if unesc, uErr := url.PathUnescape(rawParam); uErr == nil && unesc != "" {
			rawParam = unesc
		}
		reqDER, err = base64.StdEncoding.DecodeString(strings.TrimSpace(rawParam))
		if err != nil {
			reqDER, err = base64.URLEncoding.DecodeString(strings.TrimSpace(rawParam))
		}
		if err != nil || len(reqDER) == 0 {
			http.Error(w, "invalid base64 OCSP request", http.StatusBadRequest)
			return
		}
	} else {
		reqDER, err = io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil || len(reqDER) == 0 {
			http.Error(w, "empty OCSP request body", http.StatusBadRequest)
			return
		}
	}

	respDER, _ := h.ca.HandleOCSPRequest(reqDER)
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}

// HandleGetPKISummary returns Root CA health, CRL/OCSP URLs, and leaf certificate statistics.
// GET /api/pki/summary
func (h *Handler) HandleGetPKISummary(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil || h.ca.RootCert() == nil {
		respondErr(w, http.StatusServiceUnavailable, "internal Root CA is not configured")
		return
	}
	rc := h.ca.RootCert()
	base := h.resolvedPKIBaseURL(r)

	sum := PKISummary{
		CASubject:        rc.Subject.String(),
		CAThumbprintSHA1: h.ca.RootThumbprintSHA1(),
		CASerialNumber:   rc.SerialNumber.String(),
		CANotBefore:      rc.NotBefore.UTC(),
		CANotAfter:       rc.NotAfter.UTC(),
		CRLURL:           base + "/pki/crl.der",
		CRLPEMURL:        base + "/pki/crl.pem",
		OCSPURL:          base + "/pki/ocsp",
	}

	_ = h.db.QueryRowContext(r.Context(), `SELECT crl_number FROM pki_crl_state WHERE id = 'default'`).Scan(&sum.CRLSequenceNumber)

	now := time.Now().UTC()
	soon := now.Add(30 * 24 * time.Hour)
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN revoked = 0 AND not_after > ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN revoked = 0 AND not_after > ? AND not_after <= ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END), 0)
		FROM certificates
		WHERE cert_type <> 'root_ca'
	`), now, now, soon).Scan(
		&sum.TotalIssued,
		&sum.ActiveCerts,
		&sum.Expiring30d,
		&sum.RevokedCerts,
	)

	respondOK(w, sum)
}

// HandleListPKICertificates lists issued device mTLS and client_pfx leaf certificates.
// GET /api/pki/certificates
func (h *Handler) HandleListPKICertificates(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT
			c.id, c.cert_type, COALESCE(c.subject, ''), c.thumbprint, c.serial_number,
			COALESCE(c.device_id, ''), COALESCE(d.device_name, ''),
			c.not_before, c.not_after,
			c.revoked, c.revoked_at, COALESCE(c.revocation_reason, 0),
			c.created_at
		FROM certificates c
		LEFT JOIN devices d ON d.id = c.device_id
		WHERE c.cert_type <> 'root_ca'
		ORDER BY c.id DESC
		LIMIT 200
	`)
	if err != nil {
		slog.Error("api: listing PKI certificates", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list certificates")
		return
	}
	defer rows.Close()

	now := time.Now().UTC()
	out := []IssuedCertificateItem{}
	for rows.Next() {
		var it IssuedCertificateItem
		var rev int
		var revAt sql.NullTime
		if err := rows.Scan(
			&it.ID, &it.CertType, &it.Subject, &it.Thumbprint, &it.SerialNumber,
			&it.DeviceID, &it.DeviceName,
			&it.NotBefore, &it.NotAfter,
			&rev, &revAt, &it.RevocationReason,
			&it.CreatedAt,
		); err != nil {
			continue
		}
		it.Thumbprint = strings.ToUpper(it.Thumbprint)
		it.Revoked = rev != 0
		if revAt.Valid {
			t := revAt.Time.UTC()
			it.RevokedAt = &t
		}
		it.RevocationReasonLabel = pki.RevocationReasonLabel(it.RevocationReason)
		days := int(math.Ceil(it.NotAfter.Sub(now).Hours() / 24.0))
		if days < 0 {
			days = 0
		}
		it.DaysRemaining = days
		out = append(out, it)
	}

	respondOK(w, out)
}

// HandleRevokePKICertificate revokes an issued leaf certificate by database ID.
// POST /api/pki/certificates/{certId}/revoke
func (h *Handler) HandleRevokePKICertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		respondErr(w, http.StatusServiceUnavailable, "internal Root CA is not configured")
		return
	}
	actor := emailFromCtx(r)
	rawID := chi.URLParam(r, "certId")
	certID, err := strconv.ParseInt(strings.TrimSpace(rawID), 10, 64)
	if err != nil || certID <= 0 {
		respondErr(w, http.StatusBadRequest, "invalid certificate ID")
		return
	}

	var body struct {
		Reason int `json:"reason"`
	}
	if r.ContentLength > 0 {
		if !decodeBody(w, r, &body) {
			return
		}
	}

	if err := h.ca.RevokeCertByID(certID, body.Reason); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "certificate not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	h.audit(r, actor, "pki.cert_revoke", "certificate", strconv.FormatInt(certID, 10),
		fmt.Sprintf(`{"reason":%d,"reason_label":%q}`, body.Reason, pki.RevocationReasonLabel(body.Reason)))

	respondOK(w, map[string]interface{}{
		"revoked":      true,
		"id":           certID,
		"reason":       body.Reason,
		"reason_label": pki.RevocationReasonLabel(body.Reason),
	})
}
