package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// generateSelfSignedCert creates a self-signed TLS certificate for development.
// For production, use tls.mode=manual with real certs or tls.mode=auto (Let's Encrypt).
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	// If we already generated one, use it so the user's VM trust doesn't break on restart
	if cert, err := tls.LoadX509KeyPair("pane_dev.crt", "pane_dev.key"); err == nil {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Latchz MDM (dev)"},
			CommonName:   domain,
		},
		DNSNames:  []string{domain, "localhost"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// TEMPORARY: Dump to disk so the user can install it on the Hyper-V VM for testing
	_ = os.WriteFile("pane_dev.crt", certPEM, 0644)
	_ = os.WriteFile("pane_dev.key", keyPEM, 0600)

	return tls.X509KeyPair(certPEM, keyPEM)
}
