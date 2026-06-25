package testutil

import (
	"crypto/x509"
	"testing"

	"github.com/latchzmdm/latchz/internal/db"
)

func TestSmoke_DB_CA_Seed(t *testing.T) {
	database := DB(t)

	// migrations applied: a known table exists
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n); err != nil {
		t.Fatalf("devices table missing: %v", err)
	}

	ca := CA(t, database)
	if ca.CertPEM() == nil {
		t.Fatal("CA cert PEM is nil")
	}

	// issued client cert must chain to the CA pool
	deviceID := SeedDevice(t, database, "HWID-SMOKE")
	cert := IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.TLSPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}

	// seed graph round-trips
	cat := SeedCatalogEntry(t, database, "./Vendor/MSFT/Policy/Config/Foo", "integer")
	prof := SeedProfileWithSetting(t, database, cat, "1")
	if g := AssignProfile(t, database, deviceID, prof); g == "" {
		t.Fatal("AssignProfile returned empty group id")
	}
	_ = db.DriverName
}
