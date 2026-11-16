package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/policy"
	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
	"software.sslmate.com/src/go-pkcs12"
)

func makeAPITestCertPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Latchz Lab Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestConnectivityProfilesLifecycle(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-CONN-API-1")
	h := NewHandler(database.DB)
	v, err := vault.NewFast("test-master-secret-at-least-16-bytes")
	if err != nil {
		t.Fatal(err)
	}
	h.SetVault(v)

	// 1. Create Root CA profile
	certPEM := makeAPITestCertPEM(t)
	certBodyBytes, _ := json.Marshal(map[string]interface{}{
		"name":            "Corp Root CA",
		"profile_type":    "root_ca",
		"certificate_pem": certPEM,
	})
	wCert := httptest.NewRecorder()
	h.HandleCreateConnectivityProfile(wCert, withDeviceAndKeyRoute("POST", "/api/connectivity/profiles", string(certBodyBytes), "", "", "admin@lab.local"))
	if wCert.Code != http.StatusCreated {
		t.Fatalf("create root_ca: want 201, got %d body=%s", wCert.Code, wCert.Body.String())
	}
	var createdCert ConnectivityProfile
	if err := json.Unmarshal(wCert.Body.Bytes(), &createdCert); err != nil {
		t.Fatal(err)
	}
	if len(createdCert.CertThumbprint) != 40 || createdCert.CommandsQueued == 0 {
		t.Fatalf("unexpected created cert profile: %+v", createdCert)
	}

	// 2. Create Wi-Fi WPA2-PSK profile (verify PSK is never returned in API JSON)
	wWiFi := httptest.NewRecorder()
	h.HandleCreateConnectivityProfile(wWiFi, withDeviceAndKeyRoute("POST", "/api/connectivity/profiles", `{
		"name": "Corp HQ Wi-Fi",
		"profile_type": "wifi",
		"wifi_ssid": "CorpHQ",
		"wifi_security": "WPA2PSK",
		"wifi_psk": "UltraSecretPass123!"
	}`, "", "", "admin@lab.local"))
	if wWiFi.Code != http.StatusCreated {
		t.Fatalf("create wifi: want 201, got %d body=%s", wWiFi.Code, wWiFi.Body.String())
	}
	if strings.Contains(wWiFi.Body.String(), "UltraSecretPass123!") {
		t.Fatal("Wi-Fi PSK leaked in API response!")
	}

	// 3. Create VPNv2 profile
	wVPN := httptest.NewRecorder()
	h.HandleCreateConnectivityProfile(wVPN, withDeviceAndKeyRoute("POST", "/api/connectivity/profiles", `{
		"name": "Corp IKEv2 VPN",
		"profile_type": "vpn",
		"vpn_server": "vpn.corp.example.com",
		"vpn_protocol": "IKEv2",
		"vpn_auth_method": "Eap",
		"vpn_split_tunnel": true
	}`, "", "", "admin@lab.local"))
	if wVPN.Code != http.StatusCreated {
		t.Fatalf("create vpn: want 201, got %d body=%s", wVPN.Code, wVPN.Body.String())
	}
	var createdVPN ConnectivityProfile
	if err := json.Unmarshal(wVPN.Body.Bytes(), &createdVPN); err != nil {
		t.Fatal(err)
	}

	// 4. Verify GET /api/devices/{id}/connectivity lists all 3 deployed profiles
	wDev := httptest.NewRecorder()
	h.HandleGetDeviceConnectivity(wDev, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/connectivity", "", devID, "", "admin@lab.local"))
	if wDev.Code != http.StatusOK {
		t.Fatalf("GET device connectivity: want 200, got %d", wDev.Code)
	}
	var devItems []DeviceConnectivityItem
	if err := json.Unmarshal(wDev.Body.Bytes(), &devItems); err != nil {
		t.Fatal(err)
	}
	if len(devItems) != 3 {
		t.Fatalf("want 3 deployed connectivity items on device, got %d", len(devItems))
	}

	// 5. Delete VPN profile -> verify <Delete> queued on ./Vendor/MSFT/VPNv2/Corp-IKEv2-VPN
	wDel := httptest.NewRecorder()
	h.HandleDeleteConnectivityProfile(wDel, withDeviceAndKeyRoute("DELETE", "/api/connectivity/profiles/"+createdVPN.ID, "", createdVPN.ID, "", "admin@lab.local"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("DELETE vpn profile: want 200, got %d body=%s", wDel.Code, wDel.Body.String())
	}

	var delCmdCount int
	if err := database.DB.QueryRow(`
		SELECT COUNT(*) FROM command_queue
		WHERE device_id = ? AND command_type = 'Delete' AND oma_uri = './Device/Vendor/MSFT/VPNv2/Corp-IKEv2-VPN'
	`, devID).Scan(&delCmdCount); err != nil {
		t.Fatal(err)
	}
	if delCmdCount != 1 {
		t.Fatalf("expected 1 Delete command for VPNv2 profile, got %d", delCmdCount)
	}
}

func TestClientPFXCertificateAndEAPTLSWiFiLifecycle(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-CLIENT-CERT-1")
	_, _ = database.DB.Exec(`UPDATE devices SET device_name = 'DESKTOP-LAB01', serial_number = 'SN9988' WHERE id = ?`, devID)

	masterSecret := "test-master-secret-at-least-16-bytes"
	ca, err := pki.Load(database.DB, masterSecret)
	if err != nil {
		t.Fatalf("pki.Load: %v", err)
	}
	v, err := vault.NewFast(masterSecret)
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(database.DB)
	h.SetVault(v)
	h.SetCA(ca)
	policy.SetClientCertHandlers(h.ProvisionDeviceClientCert, h.RevokeDeviceClientCert)
	t.Cleanup(func() { policy.SetClientCertHandlers(nil, nil) })

	// 1. Create per-device Client PFX Certificate profile
	wCC := httptest.NewRecorder()
	h.HandleCreateConnectivityProfile(wCC, withDeviceAndKeyRoute("POST", "/api/connectivity/profiles", `{
		"name": "802.1X Machine Identity",
		"profile_type": "client_cert",
		"client_cert_subject_template": "CN={{device_name}}-{{serial}}",
		"client_cert_validity_days": 180,
		"client_cert_exportable": false,
		"client_cert_key_location": 3
	}`, "", "", "admin@lab.local"))
	if wCC.Code != http.StatusCreated {
		t.Fatalf("create client_cert: want 201, got %d body=%s", wCC.Code, wCC.Body.String())
	}
	var ccProf ConnectivityProfile
	if err := json.Unmarshal(wCC.Body.Bytes(), &ccProf); err != nil {
		t.Fatal(err)
	}
	if ccProf.CommandsQueued != 1 {
		t.Fatalf("expected 1 queued Atomic PFXCertInstall command, got %d", ccProf.CommandsQueued)
	}

	// 2. Decrypt sealed PFX from vault and verify PKCS#12 decodes cleanly with leaf cert CN=DESKTOP-LAB01-SN9988
	var thumb, encBlob, encPwd string
	if err := database.DB.QueryRow(`
		SELECT thumbprint, pfx_b64_encrypted, pfx_password_encrypted
		FROM device_issued_client_certs
		WHERE device_id = ? AND profile_id = ?
	`, devID, ccProf.ID).Scan(&thumb, &encBlob, &encPwd); err != nil {
		t.Fatalf("querying device_issued_client_certs: %v", err)
	}
	plainPwd, err := v.Decrypt(encPwd, mdm.PFXVaultPwdAAD(devID, ccProf.ID))
	if err != nil {
		t.Fatal(err)
	}
	plainB64, err := v.Decrypt(encBlob, mdm.PFXVaultBlobAAD(devID, ccProf.ID))
	if err != nil {
		t.Fatal(err)
	}
	pfxDER, err := base64.StdEncoding.DecodeString(plainB64)
	if err != nil {
		t.Fatal(err)
	}
	privKey, leafCert, err := pkcs12.Decode(pfxDER, plainPwd)
	if err != nil || privKey == nil || leafCert == nil {
		t.Fatalf("pkcs12.Decode failed: err=%v priv=%v cert=%v", err, privKey != nil, leafCert != nil)
	}
	if leafCert.Subject.CommonName != "DESKTOP-LAB01-SN9988" {
		t.Fatalf("unexpected leaf CN: got %q, want DESKTOP-LAB01-SN9988", leafCert.Subject.CommonName)
	}

	// 3. Create WPA2Enterprise (802.1X EAP-TLS) Wi-Fi profile without PSK
	wEAP := httptest.NewRecorder()
	h.HandleCreateConnectivityProfile(wEAP, withDeviceAndKeyRoute("POST", "/api/connectivity/profiles", `{
		"name": "Corp 802.1X Wi-Fi",
		"profile_type": "wifi",
		"wifi_ssid": "Corp-EAPTLS",
		"wifi_security": "WPA2Enterprise",
		"wifi_eap_server_names": "radius.corp.local"
	}`, "", "", "admin@lab.local"))
	if wEAP.Code != http.StatusCreated {
		t.Fatalf("create WPA2Enterprise wifi: want 201, got %d body=%s", wEAP.Code, wEAP.Body.String())
	}

	// 4. Verify GET /api/devices/{id}/connectivity exposes issued_thumbprint & issued_subject
	wDev := httptest.NewRecorder()
	h.HandleGetDeviceConnectivity(wDev, withDeviceAndKeyRoute("GET", "/api/devices/"+devID+"/connectivity", "", devID, "", "admin@lab.local"))
	if wDev.Code != http.StatusOK {
		t.Fatalf("GET device connectivity: want 200, got %d", wDev.Code)
	}
	var items []DeviceConnectivityItem
	if err := json.Unmarshal(wDev.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	foundThumb := false
	for _, it := range items {
		if it.ProfileID == ccProf.ID && it.IssuedThumbprint == thumb && strings.Contains(it.IssuedSubject, "DESKTOP-LAB01-SN9988") {
			foundThumb = true
		}
	}
	if !foundThumb {
		t.Fatalf("expected issued client cert metadata in device connectivity response, got %+v", items)
	}

	// 5. Delete client_cert profile -> verify <Delete> on PFXCertInstall/{Thumbprint} + CA cert revocation
	wDel := httptest.NewRecorder()
	h.HandleDeleteConnectivityProfile(wDel, withDeviceAndKeyRoute("DELETE", "/api/connectivity/profiles/"+ccProf.ID, "", ccProf.ID, "", "admin@lab.local"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("DELETE client_cert profile: want 200, got %d", wDel.Code)
	}

	var delPFXCount int
	if err := database.DB.QueryRow(`
		SELECT COUNT(*) FROM command_queue
		WHERE device_id = ? AND command_type = 'Delete'
		  AND oma_uri = ?
	`, devID, "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/"+thumb).Scan(&delPFXCount); err != nil {
		t.Fatal(err)
	}
	if delPFXCount != 1 {
		t.Fatalf("expected 1 Delete command for PFXCertInstall/%s, got %d", thumb, delPFXCount)
	}

	var revoked int
	if err := database.DB.QueryRow(`SELECT revoked FROM certificates WHERE LOWER(thumbprint) = LOWER(?)`, thumb).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Fatalf("expected leaf client_pfx certificate to be marked revoked=1, got %d", revoked)
	}
}
