package mdm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
)

func generateTestCAPEM(t *testing.T, cn string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Latchz Test PKI"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestTrustedCertWiFiVaultResolutionAndVPNAtomicSyncML(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-CONN-1")

	v, err := vault.NewFast("test-master-secret-at-least-16-bytes")
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(database.DB, nil, "mdm.lab.local", "")
	h.SetVault(v)

	// 1. Parse and queue Trusted Root CA certificate
	pemStr := generateTestCAPEM(t, "Latchz Enterprise Root CA")
	parsed, err := ParseX509CertificatePayload(pemStr)
	if err != nil {
		t.Fatalf("ParseX509CertificatePayload: %v", err)
	}
	if len(parsed.ThumbprintSHA1) != 40 || !strings.Contains(parsed.Subject, "Latchz Enterprise Root CA") {
		t.Fatalf("unexpected parsed cert: %+v", parsed)
	}
	delCertURI, q, err := EnqueueTrustedCertificate(database.DB, devID, "root_ca", parsed.ThumbprintSHA1, parsed.DERBase64)
	if err != nil || q != 1 {
		t.Fatalf("EnqueueTrustedCertificate: q=%d err=%v", q, err)
	}
	if !strings.HasSuffix(delCertURI, "/Root/"+parsed.ThumbprintSHA1) {
		t.Fatalf("unexpected cert deleteURI: %s", delCertURI)
	}

	// 2. Seed Wi-Fi profile with AES-256-GCM encrypted PSK and verify queue uses sentinel (no plaintext PSK in DB)
	profID := "wifi-corp-1"
	secretPSK := "SuperSecretWiFi&PSK!2026"
	encPSK, err := v.Encrypt(secretPSK, WiFiVaultAADPrefix+profID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB.Exec(`
		INSERT INTO network_pki_profiles (id, name, profile_type, wifi_ssid, wifi_security, wifi_psk_encrypted)
		VALUES (?, 'Corp WiFi', 'wifi', 'Latchz Corp 5G', 'WPA2PSK', ?)
	`, profID, encPSK)
	if err != nil {
		t.Fatal(err)
	}

	delWiFiURI, q, err := EnqueueWiFiProfile(database.DB, devID, WiFiProfileSpec{
		ProfileID:   profID,
		SSID:        "Latchz Corp 5G",
		Security:    "WPA2PSK",
		AutoConnect: true,
		KeyMaterial: WiFiVaultSentinel(profID),
	}, false)
	if err != nil || q != 1 {
		t.Fatalf("EnqueueWiFiProfile: q=%d err=%v", q, err)
	}
	if delWiFiURI != "./Device/Vendor/MSFT/WiFi/Profile/Latchz%20Corp%205G" {
		t.Fatalf("unexpected wifi deleteURI: %q", delWiFiURI)
	}

	var queuedWiFiPayload string
	if err := database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND oma_uri LIKE '%/WlanXml'`, devID).Scan(&queuedWiFiPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(queuedWiFiPayload, secretPSK) {
		t.Fatal("plaintext Wi-Fi PSK leaked into command_queue!")
	}

	// 3. Queue VPNv2 profile via <Atomic>
	_, q, err = EnqueueVPNProfile(database.DB, devID, VPNProfileSpec{
		Name:        "Latchz Corp VPN",
		Server:      "vpn.lab.local",
		Protocol:    "IKEv2",
		AuthMethod:  "Eap",
		SplitTunnel: true,
	}, false)
	if err != nil || q != 1 {
		t.Fatalf("EnqueueVPNProfile: q=%d err=%v", q, err)
	}

	// 4. Resolve vault payloads in-memory and marshal full SyncML response
	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil || len(pending) != 3 {
		t.Fatalf("loadPendingCommands: len=%d err=%v", len(pending), err)
	}
	h.resolveVaultPayloads(devID, pending)

	sess := &Session{NextCmdID: 1, CmdMap: map[string]int{}}
	doc := SyncML{
		SyncBody: SyncBody{
			Commands: buildSyncMLCommands(sess, pending),
			Final:    &struct{}{},
		},
	}
	rawSyncML, err := xml.Marshal(doc)
	if err != nil {
		t.Fatalf("xml.Marshal SyncML: %v", err)
	}
	out := string(rawSyncML)

	// Verify Wi-Fi PSK was decrypted & XML-escaped inside WLANProfile (& -> &amp; inside escaped XML -> &amp;amp;)
	if strings.Contains(out, VaultWiFiSentinelPrefix) {
		t.Fatalf("vault sentinel was not resolved in SyncML: %s", out)
	}
	if !strings.Contains(out, "SuperSecretWiFi") {
		t.Fatalf("expected decrypted Wi-Fi PSK in SyncML output: %s", out)
	}
	// Verify VPNv2 ProfileXML is wrapped inside <Atomic>
	if !strings.Contains(out, "./Vendor/MSFT/VPNv2/Latchz-Corp-VPN/ProfileXML") || !strings.Contains(out, "<Atomic>") {
		t.Fatalf("expected Atomic VPNv2 ProfileXML in SyncML output: %s", out)
	}
}
