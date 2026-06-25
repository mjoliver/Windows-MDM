package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/pki"
)

// caFixture caches a generated root-CA row so the (slow) RSA-4096 keygen runs
// at most once per test process. The cached row is re-inserted into each test
// DB and then loaded via pki.Load (fast path, no keygen).
var (
	caOnce sync.Once
	caRow  caFixtureRow
	caErr  error
)

type caFixtureRow struct {
	subject, thumbprint, serial, certPEM, keyEnc string
	notBefore, notAfter                          time.Time
}

func buildCAFixture() {
	dir, err := os.MkdirTemp("", "latchz-ca-fixture")
	if err != nil {
		caErr = err
		return
	}
	defer os.RemoveAll(dir)

	database, err := db.Open("sqlite", filepath.Join(dir, "ca.db"))
	if err != nil {
		caErr = err
		return
	}
	defer database.Close()

	if _, err = pki.Load(database.DB, MasterSecret); err != nil { // generates + stores
		caErr = err
		return
	}
	caErr = database.QueryRow(`
		SELECT subject, thumbprint, serial_number, not_before, not_after, cert_pem, key_pem_encrypted
		FROM certificates WHERE cert_type = 'root_ca' LIMIT 1
	`).Scan(&caRow.subject, &caRow.thumbprint, &caRow.serial, &caRow.notBefore, &caRow.notAfter, &caRow.certPEM, &caRow.keyEnc)
}

// CA returns a *pki.CA backed by the given database, reusing a process-wide
// cached root CA to avoid repeated 4096-bit key generation.
func CA(t testing.TB, database *db.DB) *pki.CA {
	t.Helper()
	caOnce.Do(buildCAFixture)
	if caErr != nil {
		t.Fatalf("testutil: building CA fixture: %v", caErr)
	}
	_, err := database.Exec(db.Rebind(`
		INSERT INTO certificates (cert_type, subject, thumbprint, serial_number, not_before, not_after, cert_pem, key_pem_encrypted)
		VALUES ('root_ca', ?, ?, ?, ?, ?, ?, ?)
	`), caRow.subject, caRow.thumbprint, caRow.serial, caRow.notBefore, caRow.notAfter, caRow.certPEM, caRow.keyEnc)
	if err != nil {
		t.Fatalf("testutil: inserting CA fixture row: %v", err)
	}
	ca, err := pki.Load(database.DB, MasterSecret)
	if err != nil {
		t.Fatalf("testutil: loading CA: %v", err)
	}
	return ca
}

// GenerateKeyCSR creates an RSA-2048 key and a PKCS#10 CSR (DER) with the given
// Common Name — the shape a Windows device submits during WSTEP.
func GenerateKeyCSR(t testing.TB, commonName string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testutil: generating key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatalf("testutil: creating CSR: %v", err)
	}
	return key, csrDER
}

// IssueClientCert issues a device certificate from the test CA and returns the
// parsed certificate (suitable for building a synthetic TLS peer chain).
func IssueClientCert(t testing.TB, ca *pki.CA, deviceID, commonName string) *x509.Certificate {
	t.Helper()
	_, csrDER := GenerateKeyCSR(t, commonName)
	certPEM, err := ca.IssueDeviceCertFromDER(deviceID, commonName, csrDER)
	if err != nil {
		t.Fatalf("testutil: issuing client cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("testutil: decoding issued cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("testutil: parsing issued cert: %v", err)
	}
	return cert
}

// ClientTLSState builds a *tls.ConnectionState presenting the given certificates
// as the peer chain, for handlers that read r.TLS.PeerCertificates.
func ClientTLSState(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  certs,
	}
}
