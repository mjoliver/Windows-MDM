package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/latchzmdm/latchz/internal/db"
)

func newCATestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open("sqlite", filepath.Join(t.TempDir(), "pki.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestIssueDeviceCert_BindsSubjectToDeviceID(t *testing.T) {
	database := newCATestDB(t)
	ca, err := Load(database.DB, "a-sufficiently-long-master-secret")
	if err != nil {
		t.Fatal(err)
	}

	// FK enforcement is on: the device row must exist before issuing its cert.
	if _, err := database.Exec(`INSERT INTO devices (id, hardware_id, is_active) VALUES ('device-uuid-123', 'HW-X', 1)`); err != nil {
		t.Fatal(err)
	}

	// Attacker puts a chosen CommonName in their CSR.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ATTACKER-CHOSEN-IDENTITY"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := ca.IssueDeviceCertFromDER("device-uuid-123", "alice@example.com", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "device-uuid-123" {
		t.Fatalf("cert CN = %q, want server-issued device id (CSR CN must be ignored)", cert.Subject.CommonName)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "alice@example.com" {
		t.Fatalf("cert OU = %v, want enrolling user", cert.Subject.OrganizationalUnit)
	}
}
