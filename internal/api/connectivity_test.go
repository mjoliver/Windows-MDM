package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/testutil"
	"github.com/latchzmdm/latchz/internal/vault"
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
		WHERE device_id = ? AND command_type = 'Delete' AND oma_uri = './Vendor/MSFT/VPNv2/Corp-IKEv2-VPN'
	`, devID).Scan(&delCmdCount); err != nil {
		t.Fatal(err)
	}
	if delCmdCount != 1 {
		t.Fatalf("expected 1 Delete command for VPNv2 profile, got %d", delCmdCount)
	}
}
