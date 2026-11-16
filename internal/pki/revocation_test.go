package pki_test

import (
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/testutil"
	"golang.org/x/crypto/ocsp"
	"software.sslmate.com/src/go-pkcs12"
)

func TestPKICRLAndOCSPRevocationLifecycle(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	ca.SetPublicBaseURL("https://enterpriseenrollment.lab.local")
	devID := testutil.SeedDevice(t, database, "HW-PKI-OCSP-1")

	pwd, err := pki.GeneratePFXPassword()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.IssueClientPFX(devID, "DESKTOP-PKI-1", []string{"desktop-pki-1.lab.local"}, 365, pwd)
	if err != nil {
		t.Fatalf("IssueClientPFX: %v", err)
	}

	pfxRaw, err := base64.StdEncoding.DecodeString(issued.PFXBase64)
	if err != nil {
		t.Fatal(err)
	}
	_, leafCert, err := pkcs12.Decode(pfxRaw, pwd)
	if err != nil {
		t.Fatalf("pkcs12.Decode: %v", err)
	}

	// 1. Verify CDP and AIA OCSP URIs are embedded in the minted leaf certificate
	if len(leafCert.CRLDistributionPoints) != 1 || leafCert.CRLDistributionPoints[0] != "https://enterpriseenrollment.lab.local/pki/crl.der" {
		t.Fatalf("unexpected CRLDistributionPoints: %v", leafCert.CRLDistributionPoints)
	}
	if len(leafCert.OCSPServer) != 1 || leafCert.OCSPServer[0] != "https://enterpriseenrollment.lab.local/pki/ocsp" {
		t.Fatalf("unexpected OCSPServer: %v", leafCert.OCSPServer)
	}

	// 2. OCSP before revocation -> Good
	ocspReqDER, err := ocsp.CreateRequest(leafCert, ca.RootCert(), nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	goodDER, err := ca.HandleOCSPRequest(ocspReqDER)
	if err != nil {
		t.Fatalf("HandleOCSPRequest (good): %v", err)
	}
	goodResp, err := ocsp.ParseResponseForCert(goodDER, leafCert, ca.RootCert())
	if err != nil {
		t.Fatalf("ParseResponseForCert (good): %v", err)
	}
	if goodResp.Status != ocsp.Good {
		t.Fatalf("expected OCSP status Good (%d), got %d", ocsp.Good, goodResp.Status)
	}

	// 3. Revoke certificate and verify both OCSP (Revoked) and signed RFC 5280 CRL
	if err := ca.RevokeCertByThumbprint(issued.ThumbprintSHA1); err != nil {
		t.Fatalf("RevokeCertByThumbprint: %v", err)
	}

	revDER, err := ca.HandleOCSPRequest(ocspReqDER)
	if err != nil {
		t.Fatalf("HandleOCSPRequest (revoked): %v", err)
	}
	revResp, err := ocsp.ParseResponseForCert(revDER, leafCert, ca.RootCert())
	if err != nil {
		t.Fatalf("ParseResponseForCert (revoked): %v", err)
	}
	if revResp.Status != ocsp.Revoked {
		t.Fatalf("expected OCSP status Revoked (%d), got %d", ocsp.Revoked, revResp.Status)
	}

	crlDER, crlPEM, crlNum, revCount, err := ca.GenerateCRL(24 * time.Hour)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if crlNum < 1 || revCount != 1 || len(crlPEM) == 0 {
		t.Fatalf("unexpected CRL metadata: num=%d count=%d pemLen=%d", crlNum, revCount, len(crlPEM))
	}
	parsedCRL, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := parsedCRL.CheckSignatureFrom(ca.RootCert()); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}
	found := false
	for _, entry := range parsedCRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leafCert.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("revoked leaf serial %s not found in signed CRL", leafCert.SerialNumber.String())
	}

	// 4. Unknown serial -> OCSP Unknown
	fakeCert := &x509.Certificate{SerialNumber: big.NewInt(999999999)}
	unkReq, err := ocsp.CreateRequest(fakeCert, ca.RootCert(), nil)
	if err != nil {
		t.Fatal(err)
	}
	unkDER, err := ca.HandleOCSPRequest(unkReq)
	if err != nil {
		t.Fatal(err)
	}
	unkResp, err := ocsp.ParseResponse(unkDER, ca.RootCert())
	if err != nil {
		t.Fatal(err)
	}
	if unkResp.Status != ocsp.Unknown {
		t.Fatalf("expected Unknown (%d), got %d", ocsp.Unknown, unkResp.Status)
	}
}
