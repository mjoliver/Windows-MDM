// Package pki implements Pane's internal Certificate Authority.
// On first start, a root CA is generated and stored (encrypted) in the database.
// All enrolled devices receive a client certificate signed by this CA.
package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"golang.org/x/crypto/argon2"
)

// nowFunc returns the current time; overridable in tests for deterministic
// certificate validity windows.
var nowFunc = time.Now

// CA holds the active root certificate and private key.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey
	db      *sql.DB
}

// Load loads the CA from the database, or generates a new one if none exists.
func Load(db *sql.DB, masterSecret string) (*CA, error) {
	ca := &CA{db: db}

	// Try to load existing CA from DB
	var certPEM, keyPEMEncrypted string
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT cert_pem, key_pem_encrypted 
		FROM certificates 
		WHERE cert_type = 'root_ca' AND revoked = 0
		ORDER BY created_at DESC LIMIT 1
	`)).Scan(&certPEM, &keyPEMEncrypted)

	if err == sql.ErrNoRows {
		slog.Info("no CA found, generating new root CA")
		return ca.generate(masterSecret)
	}
	if err != nil {
		return nil, fmt.Errorf("querying CA from db: %w", err)
	}

	// Parse the stored certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid CA cert PEM in database")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	// Decrypt and parse the private key
	keyPEMBytes, err := decryptKey(keyPEMEncrypted, masterSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypting CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEMBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM in database")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA private key: %w", err)
	}

	ca.cert = cert
	ca.certPEM = []byte(certPEM)
	ca.key = key

	slog.Info("CA loaded from database",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter.Format(time.RFC3339),
	)
	return ca, nil
}

// generate creates a new root CA and persists it to the database.
func (ca *CA) generate(masterSecret string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Latchz MDM"},
			CommonName:   "Latchz Root CA",
		},
		NotBefore:             nowFunc().Add(-10 * time.Minute),         // small back-date for clock skew
		NotAfter:              nowFunc().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	encryptedKeyHex, err := encryptKey(keyPEM, masterSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypting CA key: %w", err)
	}

	thumbprint := calculateThumbprint(cert)

	_, err = ca.db.Exec(dbpkg.Rebind(`
		INSERT INTO certificates (cert_type, subject, thumbprint, serial_number, not_before, not_after, cert_pem, key_pem_encrypted)
		VALUES ('root_ca', ?, ?, ?, ?, ?, ?, ?)
	`),
		cert.Subject.CommonName,
		thumbprint,
		cert.SerialNumber.String(),
		cert.NotBefore,
		cert.NotAfter,
		string(certPEM),
		encryptedKeyHex,
	)
	if err != nil {
		return nil, fmt.Errorf("storing CA in database: %w", err)
	}

	ca.cert = cert
	ca.certPEM = certPEM
	ca.key = key

	slog.Info("generated new root CA",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter.Format(time.RFC3339),
	)
	return ca, nil
}

// CertPEM returns the root CA certificate in PEM format.
// This is sent to devices during enrollment so they trust our CA.
func (ca *CA) CertPEM() []byte {
	return ca.certPEM
}

// CertDER returns the raw DER-encoded root CA certificate.
func (ca *CA) CertDER() []byte {
	return ca.cert.Raw
}

// IssueDeviceCert signs a device CSR and stores the resulting certificate.
// The certificate Subject is bound to the server-issued deviceID (CommonName)
// and records the enrolling user (OrganizationalUnit) — it deliberately does
// NOT trust the attacker-supplied CSR Subject. Returns the signed cert PEM.
func (ca *CA) IssueDeviceCert(deviceID, enrolledBy string, csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	subject := pkix.Name{
		Organization: []string{"Latchz MDM"},
		CommonName:   deviceID,
	}
	if enrolledBy != "" {
		subject.OrganizationalUnit = []string{enrolledBy}
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    nowFunc().Add(-10 * time.Minute),
		NotAfter:     nowFunc().Add(365 * 24 * time.Hour), // 1 year, rotated on re-enrollment
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing device certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	thumbprint := calculateThumbprint(cert)

	_, err = ca.db.Exec(dbpkg.Rebind(`
		INSERT INTO certificates (cert_type, subject, thumbprint, serial_number, not_before, not_after, cert_pem, device_id)
		VALUES ('device', ?, ?, ?, ?, ?, ?, ?)
	`),
		cert.Subject.CommonName,
		thumbprint,
		cert.SerialNumber.String(),
		cert.NotBefore,
		cert.NotAfter,
		string(certPEM),
		deviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("storing device certificate: %w", err)
	}

	slog.Info("issued device certificate",
		"device_id", deviceID,
		"enrolled_by", enrolledBy,
		"thumbprint", thumbprint,
		"expires", cert.NotAfter.Format(time.RFC3339),
	)
	return certPEM, nil
}

// IssueDeviceCertFromDER signs device CSR bytes (DER) directly and stores the result.
func (ca *CA) IssueDeviceCertFromDER(deviceID, enrolledBy string, csrDER []byte) ([]byte, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return ca.IssueDeviceCert(deviceID, enrolledBy, csrPEM)
}

// RevokeDeviceCerts marks all certificates for a device as revoked.
func (ca *CA) RevokeDeviceCerts(deviceID string) error {
	_, err := ca.db.Exec(dbpkg.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID)
	if err != nil {
		return fmt.Errorf("revoking device certs: %w", err)
	}
	slog.Info("revoked device certificates", "device_id", deviceID)
	return nil
}

// TLSPool returns an x509.CertPool containing the root CA for TLS verification.
func (ca *CA) TLSPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// newID generates a URL-safe unique ID.
func newID() string {
	return uuid.New().String()
}

// ── Vault key encryption (AES-256-GCM with an argon2id-derived key) ───────────
//
// The AES key is derived from the operator's master secret with argon2id using a
// random per-record salt (NOT a bare SHA-256, which is instant to brute-force).
// Stored format: "v2:" + hex(salt || nonce || ciphertext).

const (
	vaultFormatV2 = "v2"
	kdfSaltLen    = 16
	kdfTime       = 2
	kdfMemoryKiB  = 64 * 1024 // 64 MiB
	kdfThreads    = 4
	kdfKeyLen     = 32 // AES-256

	// MinMasterSecretLen is the minimum acceptable master-secret length. argon2id
	// raises the cost of a weak secret, but we still refuse trivially short ones.
	MinMasterSecretLen = 16
)

func deriveVaultKey(masterSecret string, salt []byte) []byte {
	return argon2.IDKey([]byte(masterSecret), salt, kdfTime, kdfMemoryKiB, kdfThreads, kdfKeyLen)
}

func encryptKey(data []byte, masterSecret string) (string, error) {
	salt := make([]byte, kdfSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveVaultKey(masterSecret, salt))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	blob := gcm.Seal(append(salt, nonce...), nonce, data, nil)
	return vaultFormatV2 + ":" + hex.EncodeToString(blob), nil
}

func decryptKey(encoded string, masterSecret string) ([]byte, error) {
	version, hexBlob, ok := strings.Cut(encoded, ":")
	if !ok || version != vaultFormatV2 {
		return nil, fmt.Errorf("unsupported CA key vault format (re-provision the CA on a fresh database)")
	}
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	if len(blob) < kdfSaltLen {
		return nil, fmt.Errorf("ciphertext too short")
	}
	salt, rest := blob[:kdfSaltLen], blob[kdfSaltLen:]
	block, err := aes.NewCipher(deriveVaultKey(masterSecret, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(rest) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// calculateThumbprint computes the SHA-1 hash of the certificate DER (standard X.509 thumbprint).
func calculateThumbprint(cert *x509.Certificate) string {
	h := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", h[:])
}
