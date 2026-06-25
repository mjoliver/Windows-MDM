package devauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	idb "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestResolve(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-DA")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	pool := ca.TLSPool()

	t.Run("direct mTLS resolves to the device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(cert)
		id, err := Resolve(database.DB, pool, req, "")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("Resolve = (%+v, %v), want device %q", id, err, deviceID)
		}
		if id.EnrolledBy != "seed@test" {
			t.Fatalf("EnrolledBy = %q", id.EnrolledBy)
		}
	})

	t.Run("trusted-proxy header resolves to the device", func(t *testing.T) {
		pemStr := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Forwarded-Client-Cert", pemStr)
		id, err := Resolve(database.DB, pool, req, "X-Forwarded-Client-Cert")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("proxy-header Resolve = (%+v, %v)", id, err)
		}
	})

	t.Run("no certificate is rejected", func(t *testing.T) {
		if _, err := Resolve(database.DB, pool, httptest.NewRequest("POST", "/x", nil), ""); err == nil {
			t.Fatal("expected rejection without a client cert")
		}
	})

	t.Run("foreign cert is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(selfSigned(t))
		if _, err := Resolve(database.DB, pool, req, ""); err == nil {
			t.Fatal("expected rejection of a cert not chaining to our CA")
		}
	})

	t.Run("revoked cert is rejected", func(t *testing.T) {
		if _, err := database.Exec(idb.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(cert)
		if _, err := Resolve(database.DB, pool, req, ""); err == nil {
			t.Fatal("expected rejection of a revoked cert")
		}
	})
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}
