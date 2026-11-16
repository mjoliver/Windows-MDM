package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/testutil"
	"golang.org/x/crypto/ocsp"
	"software.sslmate.com/src/go-pkcs12"
)

func TestPKISummaryRevokeCRLandOCSPHandlers(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	ca.SetPublicBaseURL("https://enterpriseenrollment.lab.local")
	devID := testutil.SeedDevice(t, database, "HW-PKI-API-1")

	h := NewHandler(database.DB)
	h.SetCA(ca)

	pwd, _ := pki.GeneratePFXPassword()
	issued, err := ca.IssueClientPFX(devID, "DESKTOP-PKI-API", nil, 365, pwd)
	if err != nil {
		t.Fatal(err)
	}
	pfxRaw, _ := base64.StdEncoding.DecodeString(issued.PFXBase64)
	_, leafCert, err := pkcs12.Decode(pfxRaw, pwd)
	if err != nil {
		t.Fatal(err)
	}

	// 1. GET /api/pki/summary
	wSum := httptest.NewRecorder()
	h.HandleGetPKISummary(wSum, withDeviceAndKeyRoute("GET", "/api/pki/summary", "", "", "", "admin@lab.local"))
	if wSum.Code != http.StatusOK {
		t.Fatalf("GET /api/pki/summary: got %d body=%s", wSum.Code, wSum.Body.String())
	}
	var sum PKISummary
	if err := json.Unmarshal(wSum.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.ActiveCerts != 1 || sum.RevokedCerts != 0 || sum.CRLURL != "https://enterpriseenrollment.lab.local/pki/crl.der" {
		t.Fatalf("unexpected PKI summary: %+v", sum)
	}

	// 2. GET /api/pki/certificates
	wList := httptest.NewRecorder()
	h.HandleListPKICertificates(wList, withDeviceAndKeyRoute("GET", "/api/pki/certificates", "", "", "", "admin@lab.local"))
	var certs []IssuedCertificateItem
	if err := json.Unmarshal(wList.Body.Bytes(), &certs); err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Revoked {
		t.Fatalf("unexpected PKI certificates list: %+v", certs)
	}

	// 3. POST /pki/ocsp -> Good
	ocspReq, err := ocsp.CreateRequest(leafCert, ca.RootCert(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wOCSP := httptest.NewRecorder()
	h.HandleOCSP(wOCSP, httptest.NewRequest("POST", "/pki/ocsp", bytes.NewReader(ocspReq)))
	if wOCSP.Code != http.StatusOK {
		t.Fatalf("POST /pki/ocsp: got %d", wOCSP.Code)
	}
	parsedOCSP, err := ocsp.ParseResponseForCert(wOCSP.Body.Bytes(), leafCert, ca.RootCert())
	if err != nil || parsedOCSP.Status != ocsp.Good {
		t.Fatalf("expected OCSP Good before revoke, got status=%v err=%v", parsedOCSP.Status, err)
	}

	// 4. POST /api/pki/certificates/{certId}/revoke (reason=1 Key Compromise)
	revReq := httptest.NewRequest("POST", "/api/pki/certificates/"+strconv.FormatInt(certs[0].ID, 10)+"/revoke", strings.NewReader(`{"reason":1}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("certId", strconv.FormatInt(certs[0].ID, 10))
	ctx := context.WithValue(revReq.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, CtxKeyEmail, "admin@lab.local")
	wRev := httptest.NewRecorder()
	h.HandleRevokePKICertificate(wRev, revReq.WithContext(ctx))
	if wRev.Code != http.StatusOK {
		t.Fatalf("POST revoke cert: got %d body=%s", wRev.Code, wRev.Body.String())
	}

	// 5. GET /pki/crl.der & POST /pki/ocsp -> Revoked
	wCRL := httptest.NewRecorder()
	h.HandleServeCRLDER(wCRL, httptest.NewRequest("GET", "/pki/crl.der", nil))
	if wCRL.Code != http.StatusOK {
		t.Fatalf("GET /pki/crl.der: got %d", wCRL.Code)
	}
	parsedCRL, err := x509.ParseRevocationList(wCRL.Body.Bytes())
	if err != nil || len(parsedCRL.RevokedCertificateEntries) != 1 {
		t.Fatalf("unexpected CRL entries: len=%d err=%v", len(parsedCRL.RevokedCertificateEntries), err)
	}

	wOCSP2 := httptest.NewRecorder()
	h.HandleOCSP(wOCSP2, httptest.NewRequest("POST", "/pki/ocsp", bytes.NewReader(ocspReq)))
	parsedOCSP2, err := ocsp.ParseResponseForCert(wOCSP2.Body.Bytes(), leafCert, ca.RootCert())
	if err != nil || parsedOCSP2.Status != ocsp.Revoked || parsedOCSP2.RevocationReason != 1 {
		t.Fatalf("expected OCSP Revoked(reason=1), got %+v err=%v", parsedOCSP2, err)
	}
}
