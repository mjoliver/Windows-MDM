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
	// Subject must be exactly CN=<deviceID> so the Windows OMA-DM client's
	// SSLCLIENTCERTSEARCHCRITERIA (exact DN match) can locate the cert.
	if len(cert.Subject.Names) != 1 {
		t.Fatalf("cert subject = %q, want only CN=<deviceID>", cert.Subject.String())
	}
	if len(cert.EmailAddresses) == 0 || cert.EmailAddresses[0] != "alice@example.com" {
		t.Fatalf("cert SAN email = %v, want enrolling user", cert.EmailAddresses)
	}
}
