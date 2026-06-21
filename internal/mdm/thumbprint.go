package mdm

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

// certThumbprintImpl returns the SHA-1 hex fingerprint of a certificate.
// Separated to avoid duplicate declaration with enrollment package.
func certThumbprintImpl(cert *x509.Certificate) string {
	h := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", h[:])
}
