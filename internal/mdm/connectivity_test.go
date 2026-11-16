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

	// Verify RootCATrustedCertificates EncodedCertificate uses <Format>b64</Format>
	if !strings.Contains(out, `EncodedCertificate</LocURI></Target><Meta><Format xmlns="syncml:metinf">b64</Format>`) {
		t.Fatalf("expected <Format>b64</Format> on EncodedCertificate in SyncML output: %s", out)
	}
	// Verify Wi-Fi PSK was decrypted & XML-escaped inside WLANProfile (& -> &amp; inside escaped XML -> &amp;amp;)
	if strings.Contains(out, VaultWiFiSentinelPrefix) {
		t.Fatalf("vault sentinel was not resolved in SyncML: %s", out)
	}
	if !strings.Contains(out, "SuperSecretWiFi") {
		t.Fatalf("expected decrypted Wi-Fi PSK in SyncML output: %s", out)
	}
	// Verify VPNv2 ProfileXML is wrapped inside <Atomic> with strict XSD sequence (RoutingPolicyType before NativeProtocolType)
	if !strings.Contains(out, "./Device/Vendor/MSFT/VPNv2/Latchz-Corp-VPN/ProfileXML") || !strings.Contains(out, "<Atomic>") {
		t.Fatalf("expected Atomic VPNv2 ProfileXML in SyncML output: %s", out)
	}
	idxRouting := strings.Index(out, "RoutingPolicyType")
	idxProto := strings.Index(out, "NativeProtocolType")
	if idxRouting <= 0 || idxProto <= idxRouting {
		t.Fatalf("expected RoutingPolicyType before NativeProtocolType per Microsoft VPNv2 XSD: %s", out)
	}
}

func TestPFXClientCertificateAtomicOrderingVaultAndEAPTLSWiFi(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-PFX-1")

	v, err := vault.NewFast("test-master-secret-at-least-16-bytes")
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(database.DB, nil, "mdm.lab.local", "")
	h.SetVault(v)

	profID := "pfx-prof-1"
	thumb := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	plainPwd := "SecretAlnumPFXPwd2026XYZ"
	plainBlob := "MIIJ7AIBAzCCCSCgADCCAQACAQBase64PFXTest=="

	encPwd, err := v.Encrypt(plainPwd, PFXVaultPwdAAD(devID, profID))
	if err != nil {
		t.Fatal(err)
	}
	encBlob, err := v.Encrypt(plainBlob, PFXVaultBlobAAD(devID, profID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB.Exec(`
		INSERT INTO network_pki_profiles (id, name, profile_type)
		VALUES (?, '802.1X Machine Cert', 'client_cert')
	`, profID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB.Exec(`
		INSERT INTO device_issued_client_certs (
			device_id, profile_id, thumbprint, serial_number, subject,
			not_before, not_after, pfx_b64_encrypted, pfx_password_encrypted
		) VALUES (?, ?, ?, '12345', 'CN=DESKTOP-TEST', ?, ?, ?, ?)
	`, devID, profID, thumb, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), encBlob, encPwd)
	if err != nil {
		t.Fatal(err)
	}

	// Pass keyLocation=2 with exportable=true -> must coerce KeyLocation=3 per Microsoft CSP constraint!
	delURI, q, err := EnqueuePFXClientCertificate(database.DB, devID, profID, thumb, 2, true)
	if err != nil || q != 1 {
		t.Fatalf("EnqueuePFXClientCertificate: q=%d err=%v", q, err)
	}
	if delURI != "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/"+thumb {
		t.Fatalf("unexpected deleteURI: %s", delURI)
	}

	// Verify neither plaintext password nor PFX blob is stored in command_queue
	var rawQueued string
	if err := database.DB.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ?`, devID).Scan(&rawQueued); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawQueued, plainPwd) || strings.Contains(rawQueued, plainBlob) {
		t.Fatal("plaintext PFX password or blob leaked into command_queue!")
	}

	// Also verify WPA2Enterprise EAP-TLS WLANProfile XML generation
	eapXML, err := BuildWLANProfileXML(WiFiProfileSpec{
		ProfileID:      "wifi-eap-1",
		SSID:           "Corp-8021X",
		Security:       "WPA2Enterprise",
		AutoConnect:    true,
		EAPServerNames: "radius.lab.local",
	})
	if err != nil {
		t.Fatalf("BuildWLANProfileXML WPA2Enterprise: %v", err)
	}
	if !strings.Contains(eapXML, "<useOneX>true</useOneX>") || !strings.Contains(eapXML, "<Type>13</Type>") || !strings.Contains(eapXML, "<ServerNames>radius.lab.local</ServerNames>") {
		t.Fatalf("unexpected EAP-TLS WLANProfile XML: %s", eapXML)
	}

	// Resolve vault payloads in-memory and marshal SyncML
	pending, err := loadPendingCommands(database.DB, devID)
	if err != nil || len(pending) != 1 {
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
		t.Fatal(err)
	}
	out := string(rawSyncML)

	if strings.Contains(out, VaultPFXPwdSentinelPrefix) || strings.Contains(out, VaultPFXBlobSentinelPrefix) {
		t.Fatalf("PFX vault sentinels were not resolved in SyncML: %s", out)
	}
	if !strings.Contains(out, plainPwd) || !strings.Contains(out, plainBlob) {
		t.Fatalf("expected decrypted PFX password and blob in SyncML: %s", out)
	}
	if !strings.Contains(out, `KeyLocation</LocURI></Target><Meta><Format xmlns="syncml:metinf">int</Format><Type>text/plain</Type></Meta><Data>3</Data>`) {
		t.Fatalf("expected KeyLocation=3 (int) in SyncML: %s", out)
	}
	if !strings.Contains(out, `PFXKeyExportable</LocURI></Target><Meta><Format xmlns="syncml:metinf">bool</Format><Type>text/plain</Type></Meta><Data>true</Data>`) {
		t.Fatalf("expected PFXKeyExportable=true (bool) in SyncML: %s", out)
	}

	// CRITICAL: PFXCertBlob MUST be the LAST <Add> inside <Atomic>!
	idxKeyLoc := strings.Index(out, "/KeyLocation")
	idxExport := strings.Index(out, "/PFXKeyExportable")
	idxEncType := strings.Index(out, "/PFXCertPasswordEncryptionType")
	idxPwd := strings.Index(out, "/PFXCertPassword")
	idxBlob := strings.Index(out, "/PFXCertBlob")
	if !(idxKeyLoc > 0 && idxKeyLoc < idxExport && idxExport < idxEncType && idxEncType < idxPwd && idxPwd < idxBlob) {
		t.Fatalf("PFXCertBlob MUST be last inside <Atomic>! indices: keyLoc=%d export=%d enc=%d pwd=%d blob=%d",
			idxKeyLoc, idxExport, idxEncType, idxPwd, idxBlob)
	}
}
