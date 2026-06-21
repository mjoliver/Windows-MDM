package enrollment

import (
	"crypto/sha1"
	"encoding/pem"
)

// sha1OfPEM returns the SHA-1 fingerprint of the first certificate in a PEM block.
// This is the format Windows expects for CA certificate thumbprints in XCEP responses.
func sha1OfPEM(certPEM []byte) []byte {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}
	h := sha1.Sum(block.Bytes) // SHA-1 of the DER-encoded certificate
	return h[:]
}
