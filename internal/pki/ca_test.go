package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestEncryptDecryptKey_Roundtrip(t *testing.T) {
	secret := "a-sufficiently-long-master-secret-value"
	plaintext := []byte("super secret CA private key material")

	enc, err := encryptKey(plaintext, secret)
	if err != nil {
		t.Fatalf("encryptKey: %v", err)
	}
	if !strings.HasPrefix(enc, vaultFormatV2+":") {
		t.Fatalf("expected v2 prefix, got %q", enc[:8])
	}

	got, err := decryptKey(enc, secret)
	if err != nil {
		t.Fatalf("decryptKey: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q", got)
	}
}

func TestDecryptKey_WrongSecretFails(t *testing.T) {
	enc, err := encryptKey([]byte("data"), "the-correct-master-secret-value-xx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptKey(enc, "a-different-master-secret-value-xx"); err == nil {
		t.Fatal("expected decryption with wrong secret to fail (GCM auth)")
	}
}

func TestDecryptKey_RejectsLegacyFormat(t *testing.T) {
	// A bare hex blob (the old, weak SHA-256 format) must be rejected, not
	// silently mis-handled.
	if _, err := decryptKey("deadbeef", "secret"); err == nil {
		t.Fatal("expected legacy/unknown vault format to be rejected")
	}
}

func TestDeriveVaultKey_SaltDependent(t *testing.T) {
	a := deriveVaultKey("secret", []byte("0123456789abcdef"))
	b := deriveVaultKey("secret", []byte("fedcba9876543210"))
	if string(a) == string(b) {
		t.Fatal("expected different salts to derive different keys")
	}
	if len(a) != kdfKeyLen {
		t.Fatalf("expected %d-byte key, got %d", kdfKeyLen, len(a))
	}
}

func TestIssueDeviceCert_RejectsBadCSRSignature(t *testing.T) {
	// Build a CSR then corrupt it so CheckSignature fails; IssueDeviceCert must
	// refuse rather than sign attacker-tampered requests.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "x"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrDER[len(csrDER)-1] ^= 0xFF // corrupt the signature

	ca := &CA{} // no DB needed: parsing/sig check happens before any DB write
	if _, err := ca.IssueDeviceCertFromDER("dev", "name", csrDER); err == nil {
		t.Fatal("expected IssueDeviceCert to reject a CSR with an invalid signature")
	}
}
