package mdm

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	OMARootCATrustedPrefix  = "./Device/Vendor/MSFT/RootCATrustedCertificates"
	OMAWiFiProfilePrefix    = "./Device/Vendor/MSFT/WiFi/Profile"
	OMAVPNv2Prefix          = "./Device/Vendor/MSFT/VPNv2"
	OMAPFXCertInstallPrefix = "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall"

	// WiFiVaultAADPrefix binds encrypted Wi-Fi PSKs in network_pki_profiles to their profile ID.
	WiFiVaultAADPrefix = "wifi_psk:"

	// VaultWiFiSentinelPrefix is embedded inside queued WlanXml payloads so plaintext
	// Wi-Fi passphrases are never persisted in command_queue; HandleOMADM resolves it in-memory.
	VaultWiFiSentinelPrefix = "[VAULT:wifi_psk:"

	// VaultPFXPwdSentinelPrefix and VaultPFXBlobSentinelPrefix are resolved strictly
	// in-memory inside HandleOMADM so PKCS#12 private keys and passwords never land in command_queue.
	VaultPFXPwdSentinelPrefix  = "[VAULT:pfx_pwd:"
	VaultPFXBlobSentinelPrefix = "[VAULT:pfx_blob:"
)

// ParsedCertificate holds validated metadata extracted from a PEM or Base64 DER X.509 certificate.
type ParsedCertificate struct {
	ThumbprintSHA1 string
	Subject        string
	NotAfter       time.Time
	DERBase64      string
}

// ParseX509CertificatePayload parses a PEM-armored or raw Base64 DER X.509 certificate,
// returning its uppercase SHA-1 thumbprint, subject DN, expiry, and single-line Base64 DER.
func ParseX509CertificatePayload(raw string) (*ParsedCertificate, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("certificate payload is empty")
	}

	var der []byte
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil || len(block.Bytes) == 0 {
			return nil, errors.New("invalid PEM certificate block")
		}
		der = block.Bytes
	} else {
		cleaned := strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, trimmed)
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 certificate data: %w", err)
		}
		der = decoded
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing X.509 certificate: %w", err)
	}
	sum := sha1.Sum(cert.Raw)
	subj := strings.TrimSpace(cert.Subject.String())
	if subj == "" {
		subj = cert.Subject.CommonName
	}
	return &ParsedCertificate{
		ThumbprintSHA1: strings.ToUpper(hex.EncodeToString(sum[:])),
		Subject:        subj,
		NotAfter:       cert.NotAfter.UTC(),
		DERBase64:      base64.StdEncoding.EncodeToString(cert.Raw),
	}, nil
}

// EnqueueTrustedCertificate provisions a Root or Intermediate CA certificate via
// ./Device/Vendor/MSFT/RootCATrustedCertificates/{Root|CA}/{Thumbprint}/EncodedCertificate.
func EnqueueTrustedCertificate(dbConn *sql.DB, deviceID, profileType, thumbprint, derBase64 string) (deleteURI string, queued int, err error) {
	tp := strings.ToUpper(strings.TrimSpace(thumbprint))
	if tp == "" || strings.TrimSpace(derBase64) == "" {
		return "", 0, errors.New("thumbprint and certificate DER are required")
	}
	store := "Root"
	if profileType == "intermediate_ca" {
		store = "CA"
	}
	deleteURI = fmt.Sprintf("%s/%s/%s", OMARootCATrustedPrefix, store, tp)
	encodedURI := deleteURI + "/EncodedCertificate"
	if _, err := EnqueueAdd(dbConn, deviceID, encodedURI, strings.TrimSpace(derBase64)); err != nil {
		return "", 0, err
	}
	return deleteURI, 1, nil
}

// WiFiProfileSpec describes a native Windows WLANProfile for ./Device/Vendor/MSFT/WiFi/Profile/{SSID}/WlanXml.
type WiFiProfileSpec struct {
	ProfileID      string
	SSID           string
	Security       string // "WPA2PSK", "WPA3SAE", "WPA2Enterprise", "Open"
	AutoConnect    bool
	HiddenNetwork  bool
	KeyMaterial    string // sentinel or plaintext passphrase
	EAPServerNames string // semicolon-separated RADIUS FQDNs for WPA2Enterprise (EAP-TLS)
}

func xmlEscapeText(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// WiFiVaultSentinel returns the in-queue vault placeholder token for a Wi-Fi profile ID.
func WiFiVaultSentinel(profileID string) string {
	return VaultWiFiSentinelPrefix + strings.TrimSpace(profileID) + "]"
}

// PFXVaultPwdAAD returns the AES-256-GCM AAD binding a PFX password to (deviceID, profileID).
func PFXVaultPwdAAD(deviceID, profileID string) string {
	return "pfx_pwd:" + strings.TrimSpace(deviceID) + ":" + strings.TrimSpace(profileID)
}

// PFXVaultBlobAAD returns the AES-256-GCM AAD binding a PFX archive to (deviceID, profileID).
func PFXVaultBlobAAD(deviceID, profileID string) string {
	return "pfx_blob:" + strings.TrimSpace(deviceID) + ":" + strings.TrimSpace(profileID)
}

// PFXPwdVaultSentinel returns the in-queue vault placeholder for a device PFX password.
func PFXPwdVaultSentinel(deviceID, profileID string) string {
	return VaultPFXPwdSentinelPrefix + strings.TrimSpace(deviceID) + ":" + strings.TrimSpace(profileID) + "]"
}

// PFXBlobVaultSentinel returns the in-queue vault placeholder for a device PFX Base64 archive.
func PFXBlobVaultSentinel(deviceID, profileID string) string {
	return VaultPFXBlobSentinelPrefix + strings.TrimSpace(deviceID) + ":" + strings.TrimSpace(profileID) + "]"
}

// RenderClientCertSubject expands {{device_name}}, {{serial}}, and {{device_id}} placeholders
// into a clean X.509 CommonName and DNS SAN list for per-device client certificate issuance.
func RenderClientCertSubject(tmpl, deviceID, deviceName, serialNumber string) (cn string, dnsSANs []string) {
	shortID := strings.TrimSpace(deviceID)
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	devName := strings.TrimSpace(deviceName)
	if devName == "" {
		devName = "WIN-" + strings.ToUpper(shortID)
	}
	serial := strings.TrimSpace(serialNumber)
	if serial == "" {
		serial = strings.ToUpper(shortID)
	}

	raw := strings.TrimSpace(tmpl)
	if raw == "" {
		raw = "CN={{device_name}}"
	}
	replacer := strings.NewReplacer(
		"{{device_name}}", devName,
		"{{DEVICE_NAME}}", devName,
		"{{serial}}", serial,
		"{{SERIAL}}", serial,
		"{{device_id}}", strings.TrimSpace(deviceID),
		"{{DEVICE_ID}}", strings.TrimSpace(deviceID),
	)
	rendered := strings.TrimSpace(replacer.Replace(raw))
	if len(rendered) >= 3 && strings.EqualFold(rendered[:3], "CN=") {
		rendered = strings.TrimSpace(rendered[3:])
	}
	if rendered == "" {
		rendered = devName
	}
	if strings.TrimSpace(deviceName) != "" {
		dnsSANs = []string{strings.ToLower(strings.TrimSpace(deviceName))}
	}
	return rendered, dnsSANs
}

// EnqueuePFXClientCertificate queues a transactional <Atomic> deployment to
// ./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/{Thumbprint}.
// Per Microsoft's CSP specification, KeyLocation, PFXKeyExportable,
// PFXCertPasswordEncryptionType, and PFXCertPassword MUST precede PFXCertBlob,
// which must be the final <Add> inside <Atomic> to trigger PFXImportCertStore.
func EnqueuePFXClientCertificate(dbConn *sql.DB, deviceID, profileID, thumbprint string, keyLocation int, exportable bool) (deleteURI string, queued int, err error) {
	tp := strings.ToUpper(strings.TrimSpace(thumbprint))
	if tp == "" {
		return "", 0, errors.New("client certificate thumbprint is required")
	}
	if strings.TrimSpace(deviceID) == "" || strings.TrimSpace(profileID) == "" {
		return "", 0, errors.New("device_id and profile_id are required")
	}

	// Microsoft CSP rule: PFXKeyExportable=true is ONLY valid with Software KSP (KeyLocation=3).
	if exportable {
		keyLocation = 3
	} else if keyLocation != 1 && keyLocation != 2 && keyLocation != 3 {
		keyLocation = 3
	}

	expStr := "false"
	if exportable {
		expStr = "true"
	}

	deleteURI = OMAPFXCertInstallPrefix + "/" + tp
	ops := []AtomicSubCommand{
		{CommandType: "Add", OMAURI: deleteURI + "/KeyLocation", Payload: strconv.Itoa(keyLocation), Format: "int"},
		{CommandType: "Add", OMAURI: deleteURI + "/PFXKeyExportable", Payload: expStr, Format: "bool"},
		{CommandType: "Add", OMAURI: deleteURI + "/PFXCertPasswordEncryptionType", Payload: "0", Format: "int"},
		{CommandType: "Add", OMAURI: deleteURI + "/PFXCertPassword", Payload: PFXPwdVaultSentinel(deviceID, profileID), Format: "chr"},
		{CommandType: "Add", OMAURI: deleteURI + "/PFXCertBlob", Payload: PFXBlobVaultSentinel(deviceID, profileID), Format: "chr"},
	}
	if _, err := EnqueueAtomic(dbConn, deviceID, deleteURI, ops); err != nil {
		return "", 0, err
	}
	return deleteURI, 1, nil
}

// BuildWLANProfileXML builds a standards-compliant Microsoft WLANProfile v1 XML document.
func BuildWLANProfileXML(spec WiFiProfileSpec) (string, error) {
	ssid := strings.TrimSpace(spec.SSID)
	if ssid == "" || len(ssid) > 32 {
		return "", errors.New("wifi_ssid must be between 1 and 32 characters")
	}
	connMode := "manual"
	if spec.AutoConnect {
		connMode = "auto"
	}
	nonBroadcast := "false"
	if spec.HiddenNetwork {
		nonBroadcast = "true"
	}

	sec := strings.ToUpper(strings.TrimSpace(spec.Security))
	auth := "WPA2PSK"
	enc := "AES"
	useOneX := "false"
	includeKey := true
	isEnterpriseTLS := false
	switch sec {
	case "WPA2PSK", "":
		auth = "WPA2PSK"
		enc = "AES"
	case "WPA3SAE":
		auth = "WPA3SAE"
		enc = "AES"
	case "WPA2ENTERPRISE":
		auth = "WPA2"
		enc = "AES"
		useOneX = "true"
		includeKey = false
		isEnterpriseTLS = true
	case "OPEN":
		auth = "open"
		enc = "none"
		includeKey = false
	default:
		return "", fmt.Errorf("unsupported wifi_security %q (expected WPA2PSK, WPA3SAE, WPA2Enterprise, or Open)", spec.Security)
	}

	ssidHex := strings.ToUpper(hex.EncodeToString([]byte(ssid)))
	escapedSSID := xmlEscapeText(ssid)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">`)
	b.WriteString(`<name>` + escapedSSID + `</name>`)
	b.WriteString(`<SSIDConfig><SSID><hex>` + ssidHex + `</hex><name>` + escapedSSID + `</name></SSID><nonBroadcast>` + nonBroadcast + `</nonBroadcast></SSIDConfig>`)
	b.WriteString(`<connectionType>ESS</connectionType>`)
	b.WriteString(`<connectionMode>` + connMode + `</connectionMode>`)
	b.WriteString(`<MSM><security><authEncryption><authentication>` + auth + `</authentication><encryption>` + enc + `</encryption><useOneX>` + useOneX + `</useOneX></authEncryption>`)
	if includeKey {
		b.WriteString(`<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>` + xmlEscapeText(spec.KeyMaterial) + `</keyMaterial></sharedKey>`)
	}
	if isEnterpriseTLS {
		srvNames := strings.TrimSpace(spec.EAPServerNames)
		b.WriteString(`<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">`)
		b.WriteString(`<authMode>machineOrUser</authMode>`)
		b.WriteString(`<EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">`)
		b.WriteString(`<EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>`)
		b.WriteString(`<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type><EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">`)
		b.WriteString(`<CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>`)
		b.WriteString(`<ServerValidation><DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>`)
		if srvNames != "" {
			b.WriteString(`<ServerNames>` + xmlEscapeText(srvNames) + `</ServerNames>`)
		} else {
			b.WriteString(`<ServerNames/>`)
		}
		b.WriteString(`</ServerValidation><DifferentUsername>false</DifferentUsername>`)
		b.WriteString(`</EapType></Eap></Config></EapHostConfig></EAPConfig></OneX>`)
	}
	b.WriteString(`</security></MSM></WLANProfile>`)
	return b.String(), nil
}

// EnqueueWiFiProfile queues a Windows WiFi CSP WlanXml provisioning command.
func EnqueueWiFiProfile(dbConn *sql.DB, deviceID string, spec WiFiProfileSpec, replaceExisting bool) (deleteURI string, queued int, err error) {
	wlanXML, err := BuildWLANProfileXML(spec)
	if err != nil {
		return "", 0, err
	}
	escapedSSID := strings.ReplaceAll(url.PathEscape(strings.TrimSpace(spec.SSID)), "+", "%20")
	deleteURI = OMAWiFiProfilePrefix + "/" + escapedSSID
	wlanURI := deleteURI + "/WlanXml"

	if replaceExisting {
		if _, err := EnqueueDelete(dbConn, deviceID, deleteURI); err != nil {
			return "", 0, err
		}
		queued++
	}
	if _, err := EnqueueAdd(dbConn, deviceID, wlanURI, wlanXML); err != nil {
		return "", queued, err
	}
	queued++
	return deleteURI, queued, nil
}

// VPNProfileSpec describes a native Windows 10/11 VPNv2 CSP profile.
type VPNProfileSpec struct {
	Name           string
	Server         string
	Protocol       string // "IKEv2", "Automatic", "L2TP", "SSTP"
	AuthMethod     string // "Eap" (EAP-MSCHAPv2) or "Certificate"
	SplitTunnel    bool
	AlwaysOn       bool
	TrustedNetwork string
}

// SanitizeVPNProfileName normalizes a human VPN name into a clean VPNv2 CSP URI node name.
func SanitizeVPNProfileName(raw string) string {
	return SanitizeFirewallRuleKey(raw)
}

// BuildVPNProfileXML generates a schema-valid Windows VPNv2 <VPNProfile> XML payload.
func BuildVPNProfileXML(spec VPNProfileSpec) (string, error) {
	srv := strings.TrimSpace(spec.Server)
	if srv == "" {
		return "", errors.New("vpn_server is required")
	}
	proto := strings.TrimSpace(spec.Protocol)
	switch proto {
	case "", "IKEv2":
		proto = "IKEv2"
	case "Automatic", "L2TP", "SSTP":
	default:
		return "", fmt.Errorf("unsupported vpn_protocol %q", spec.Protocol)
	}

	routing := "ForceTunnel"
	if spec.SplitTunnel {
		routing = "SplitTunnel"
	}

	// Microsoft VPNv2 ProfileXML enforces strict xs:sequence element ordering:
	//   VPNProfile: RememberCredentials -> AlwaysOn -> TrustedNetworkDetection -> NativeProfile
	//   NativeProfile: Servers -> RoutingPolicyType -> NativeProtocolType -> Authentication
	var b strings.Builder
	b.WriteString(`<VPNProfile>`)
	b.WriteString(`<RememberCredentials>true</RememberCredentials>`)
	if spec.AlwaysOn {
		b.WriteString(`<AlwaysOn>true</AlwaysOn>`)
	}
	if tn := strings.TrimSpace(spec.TrustedNetwork); tn != "" {
		b.WriteString(`<TrustedNetworkDetection>` + xmlEscapeText(tn) + `</TrustedNetworkDetection>`)
	}
	b.WriteString(`<NativeProfile>`)
	b.WriteString(`<Servers>` + xmlEscapeText(srv) + `</Servers>`)
	b.WriteString(`<RoutingPolicyType>` + routing + `</RoutingPolicyType>`)
	b.WriteString(`<NativeProtocolType>` + proto + `</NativeProtocolType>`)
	b.WriteString(`<Authentication>`)
	if strings.EqualFold(strings.TrimSpace(spec.AuthMethod), "Certificate") {
		b.WriteString(`<UserMethod>Certificate</UserMethod>`)
	} else {
		b.WriteString(`<UserMethod>Eap</UserMethod>`)
		b.WriteString(`<Eap><Configuration>`)
		b.WriteString(`<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">`)
		b.WriteString(`<EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">26</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>`)
		b.WriteString(`<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></Config>`)
		b.WriteString(`</EapHostConfig>`)
		b.WriteString(`</Configuration></Eap>`)
	}
	b.WriteString(`</Authentication>`)
	b.WriteString(`</NativeProfile>`)
	b.WriteString(`</VPNProfile>`)
	return b.String(), nil
}

// EnqueueVPNProfile queues a transactional <Atomic> VPNv2 ProfileXML deployment.
func EnqueueVPNProfile(dbConn *sql.DB, deviceID string, spec VPNProfileSpec, replaceExisting bool) (deleteURI string, queued int, err error) {
	profileXML, err := BuildVPNProfileXML(spec)
	if err != nil {
		return "", 0, err
	}
	nodeName := SanitizeVPNProfileName(spec.Name)
	deleteURI = OMAVPNv2Prefix + "/" + nodeName
	xmlURI := deleteURI + "/ProfileXML"

	if replaceExisting {
		if _, err := EnqueueDelete(dbConn, deviceID, deleteURI); err != nil {
			return "", 0, err
		}
		queued++
	}
	ops := []AtomicSubCommand{
		{CommandType: "Add", OMAURI: xmlURI, Payload: profileXML, Format: "chr"},
	}
	if _, err := EnqueueAtomic(dbConn, deviceID, deleteURI, ops); err != nil {
		return "", queued, err
	}
	queued++
	return deleteURI, queued, nil
}
