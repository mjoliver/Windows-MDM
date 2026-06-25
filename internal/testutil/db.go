// Package testutil provides shared helpers for the Latchz test suite:
// throwaway databases, a cached test CA, crypto/CSR fixtures, and seed helpers.
package testutil

import (
	"path/filepath"
	"testing"

	"github.com/latchzmdm/latchz/internal/db"
)

// MasterSecret is a fixed, high-entropy (>=32 byte) vault key used to encrypt
// the test CA's private key. Tests must use a stable value so the cached CA
// fixture decrypts across calls.
const MasterSecret = "test-master-secret-0123456789-abcdefghijklmnop"

// DB opens a fresh temp-file SQLite database with all migrations applied and
// registers cleanup. A temp file (rather than ":memory:") is used so the
// pooled connections all see the same database.
func DB(t testing.TB) *db.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db") + "?_pragma=busy_timeout(5000)"
	database, err := db.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("testutil: opening test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
