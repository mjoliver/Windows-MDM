package mdm

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

	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func certToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAuthenticateDevice_RequiresVerifiedClientCert(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HWID-1")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "")

	t.Run("valid client cert authenticates", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(cert)
		got, err := h.authenticateDevice(req)
		if err != nil {
			t.Fatalf("valid cert rejected: %v", err)
		}
		if got != deviceID {
			t.Fatalf("got device %q, want %q", got, deviceID)
		}
	})

	t.Run("hardware_id query param does NOT authenticate", func(t *testing.T) {
		// The removed bypass: anyone knowing a (non-secret) hardware_id could
		// previously impersonate a device with no certificate.
		req := httptest.NewRequest("POST", "/omadm?hwid=HWID-1", nil)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("hardware_id must not authenticate without a client cert")
		}
	})

	t.Run("no certificate is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("request with no client cert must be rejected")
		}
	})

	t.Run("foreign (non-CA) certificate is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(selfSignedCert(t))
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("certificate not chaining to our CA must be rejected")
		}
	})

	t.Run("revoked certificate is rejected", func(t *testing.T) {
		if _, err := database.Exec(db.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(cert)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("revoked device certificate must be rejected")
		}
	})
}

func TestAuthenticateDevice_TrustedProxyHeader(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HWID-PX")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "X-Forwarded-Client-Cert")

	// Simulate nginx $ssl_client_escaped_cert (URL-encoded PEM).
	pemStr := url.QueryEscape(string(certToPEM(cert.Raw)))
	req := httptest.NewRequest("POST", "/omadm", nil)
	req.Header.Set("X-Forwarded-Client-Cert", pemStr)
	got, err := h.authenticateDevice(req)
	if err != nil {
		t.Fatalf("trusted-proxy header cert rejected: %v", err)
	}
	if got != deviceID {
		t.Fatalf("got %q want %q", got, deviceID)
	}

	// Missing header → rejected.
	req2 := httptest.NewRequest("POST", "/omadm", nil)
	if _, err := h.authenticateDevice(req2); err == nil {
		t.Fatal("empty trusted-proxy header must be rejected")
	}
}

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}
