// Package vault provides authenticated AES-256-GCM secret encryption at rest
// keyed from the server's master secret (used for BitLocker recovery keys and
// local administrator credentials).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	formatV1   = "lv1"
	saltLen    = 16
	argonTime  = 2
	argonMemKB = 64 * 1024 // 64 MiB
	argonPar   = 4
	keyLen     = 32

	// MinSecretLen is the minimum master-secret length accepted by New.
	MinSecretLen = 16
)

var domainSalt = []byte("latchz-vault-root-kdf-v1")

// Vault encrypts and decrypts sensitive secrets with per-record salted subkeys
// and context-bound GCM additional authenticated data (AAD).
type Vault struct {
	rootKey []byte
}

// New derives an in-memory root key from masterSecret using Argon2id.
func New(masterSecret string) (*Vault, error) {
	if len(masterSecret) < MinSecretLen {
		return nil, fmt.Errorf("vault: master secret must be at least %d characters", MinSecretLen)
	}
	rk := argon2.IDKey([]byte(masterSecret), domainSalt, argonTime, argonMemKB, argonPar, keyLen)
	return &Vault{rootKey: rk}, nil
}

// NewFast creates a Vault with lightweight Argon2id parameters intended strictly
// for unit tests so test setup does not allocate 64 MiB repeatedly.
func NewFast(masterSecret string) (*Vault, error) {
	if len(masterSecret) < MinSecretLen {
		return nil, fmt.Errorf("vault: master secret must be at least %d characters", MinSecretLen)
	}
	rk := argon2.IDKey([]byte(masterSecret), domainSalt, 1, 8*1024, 1, keyLen)
	return &Vault{rootKey: rk}, nil
}

func (v *Vault) subkey(salt []byte, aad string) []byte {
	mac := hmac.New(sha256.New, v.rootKey)
	mac.Write(salt)
	mac.Write([]byte{0})
	mac.Write([]byte(aad))
	return mac.Sum(nil)
}

// Encrypt seals plaintext under a fresh random 16-byte salt and 12-byte GCM
// nonce, binding aad (e.g. "bitlocker:<device_id>") so ciphertexts cannot be
// transplanted across devices or secret types.
func (v *Vault) Encrypt(plaintext, aad string) (string, error) {
	if v == nil || len(v.rootKey) != keyLen {
		return "", errors.New("vault: not initialized")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("vault: generating salt: %w", err)
	}
	block, err := aes.NewCipher(v.subkey(salt, aad))
	if err != nil {
		return "", fmt.Errorf("vault: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault: creating gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("vault: generating nonce: %w", err)
	}
	out := make([]byte, 0, saltLen+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, []byte(plaintext), []byte(aad))
	return formatV1 + ":" + hex.EncodeToString(out), nil
}

// Decrypt opens an Encrypt-produced token and verifies aad authenticity.
func (v *Vault) Decrypt(encoded, aad string) (string, error) {
	if v == nil || len(v.rootKey) != keyLen {
		return "", errors.New("vault: not initialized")
	}
	ver, hexBlob, ok := strings.Cut(strings.TrimSpace(encoded), ":")
	if !ok || ver != formatV1 {
		return "", errors.New("vault: unsupported ciphertext format")
	}
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return "", fmt.Errorf("vault: invalid hex payload: %w", err)
	}
	if len(blob) < saltLen {
		return "", errors.New("vault: ciphertext truncated")
	}
	salt, rest := blob[:saltLen], blob[saltLen:]
	block, err := aes.NewCipher(v.subkey(salt, aad))
	if err != nil {
		return "", fmt.Errorf("vault: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault: creating gcm: %w", err)
	}
	if len(rest) < gcm.NonceSize() {
		return "", errors.New("vault: ciphertext missing nonce")
	}
	nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("vault: authentication failed: %w", err)
	}
	return string(pt), nil
}
