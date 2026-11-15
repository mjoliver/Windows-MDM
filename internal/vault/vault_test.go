package vault

import "testing"

func TestVaultRoundTripAndAADBinding(t *testing.T) {
	v, err := NewFast("unit-test-master-secret-at-least-16")
	if err != nil {
		t.Fatalf("NewFast: %v", err)
	}

	secret := "123456-654321-111111-222222-333333-444444-555555-666666"
	ct1, err := v.Encrypt(secret, "bitlocker:dev-1")
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	ct2, err := v.Encrypt(secret, "bitlocker:dev-1")
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	if ct1 == ct2 {
		t.Fatal("expected distinct ciphertexts due to random salt + nonce")
	}

	got, err := v.Decrypt(ct1, "bitlocker:dev-1")
	if err != nil {
		t.Fatalf("Decrypt valid AAD: %v", err)
	}
	if got != secret {
		t.Fatalf("got %q, want %q", got, secret)
	}

	if _, err := v.Decrypt(ct1, "bitlocker:dev-2"); err == nil {
		t.Fatal("expected AAD mismatch to fail authentication")
	}

	otherVault, _ := NewFast("different-master-secret-at-least-16")
	if _, err := otherVault.Decrypt(ct1, "bitlocker:dev-1"); err == nil {
		t.Fatal("expected wrong master key to fail authentication")
	}
}
