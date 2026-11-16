package policy

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

// ClientCertProvisionerFunc mints (or reuses) a per-device PKCS#12 client certificate,
// seals its archive + password in the AES-256-GCM vault, and returns its SHA-1 thumbprint.
type ClientCertProvisionerFunc func(db *sql.DB, deviceID, profileID, subjectTemplate string, validityDays int) (thumbprint string, err error)

// ClientCertRevokerFunc marks a retracted per-device client certificate revoked in PKI records.
type ClientCertRevokerFunc func(db *sql.DB, deviceID, profileID, deleteURI string)

var (
	clientCertMu          sync.RWMutex
	clientCertProvisioner ClientCertProvisionerFunc
	clientCertRevoker     ClientCertRevokerFunc
)

// SetClientCertHandlers wires PKI + Vault issuance and revocation into connectivity reconciliation.
func SetClientCertHandlers(provisioner ClientCertProvisionerFunc, revoker ClientCertRevokerFunc) {
	clientCertMu.Lock()
	defer clientCertMu.Unlock()
	clientCertProvisioner = provisioner
	clientCertRevoker = revoker
}

func invokeClientCertProvisioner(db *sql.DB, deviceID, profileID, subjectTemplate string, validityDays int) (string, error) {
	clientCertMu.RLock()
	fn := clientCertProvisioner
	clientCertMu.RUnlock()
	if fn == nil {
		return "", errors.New("client certificate provisioner is not configured (set server.master_secret)")
	}
	return fn(db, deviceID, profileID, subjectTemplate, validityDays)
}

func invokeClientCertRevoker(db *sql.DB, deviceID, profileID, deleteURI string) {
	clientCertMu.RLock()
	fn := clientCertRevoker
	clientCertMu.RUnlock()
	if fn != nil {
		fn(db, deviceID, profileID, deleteURI)
	}
}

type desiredNetworkPKIProfile struct {
	id                        string
	name                      string
	profileType               string
	certThumbprint            string
	certDERB64                string
	wifiSSID                  string
	wifiSecurity              string
	wifiAutoConnect           bool
	wifiHidden                bool
	wifiEAPServerNames        string
	vpnServer                 string
	vpnProtocol               string
	vpnAuthMethod             string
	vpnSplitTunnel            bool
	vpnAlwaysOn               bool
	vpnTrustedNetwork         string
	clientCertSubjectTemplate string
	clientCertValidityDays    int
	clientCertExportable      bool
	clientCertKeyLocation     int
}

// ReconcileConnectivityDevice provisions assigned Root/Intermediate CA certificates,
// per-device PFX client certificates, Wi-Fi profiles, and VPNv2 profiles onto deviceID
// and retracts any unassigned ones.
func ReconcileConnectivityDevice(db *sql.DB, deviceID string) int {
	type prevState struct {
		profileType string
		deleteURI   string
	}
	deployed := make(map[string]prevState)
	sRows, err := db.Query(dbpkg.Rebind(`
		SELECT profile_id, profile_type, delete_oma_uri FROM device_network_pki_state WHERE device_id = ?
	`), deviceID)
	if err == nil {
		for sRows.Next() {
			var pid, ptype, duri string
			if sRows.Scan(&pid, &ptype, &duri) == nil && pid != "" {
				deployed[pid] = prevState{profileType: ptype, deleteURI: duri}
			}
		}
		sRows.Close()
	}

	pRows, err := db.Query(dbpkg.Rebind(`
		SELECT DISTINCT
			p.id, p.name, p.profile_type,
			p.cert_thumbprint, p.cert_der_b64,
			p.wifi_ssid, p.wifi_security, p.wifi_auto_connect, p.wifi_hidden, COALESCE(p.wifi_eap_server_names, ''),
			p.vpn_server, p.vpn_protocol, p.vpn_auth_method, p.vpn_split_tunnel, p.vpn_always_on, p.vpn_trusted_network,
			COALESCE(p.client_cert_subject_template, 'CN={{device_name}}'),
			COALESCE(p.client_cert_validity_days, 365),
			COALESCE(p.client_cert_exportable, 0),
			COALESCE(p.client_cert_key_location, 3)
		FROM network_pki_profiles p
		LEFT JOIN group_network_pki_profiles gp ON gp.profile_id = p.id
		LEFT JOIN device_group_members dgm ON dgm.group_id = gp.group_id AND dgm.device_id = ?
		WHERE p.target_all_devices = 1 OR dgm.device_id IS NOT NULL
	`), deviceID)
	if err != nil {
		return 0
	}
	var desired []desiredNetworkPKIProfile
	desiredIDs := make(map[string]bool)
	for pRows.Next() {
		var d desiredNetworkPKIProfile
		var autoConn, hidden, splitTun, alwaysOn, ccExp int
		if pRows.Scan(
			&d.id, &d.name, &d.profileType,
			&d.certThumbprint, &d.certDERB64,
			&d.wifiSSID, &d.wifiSecurity, &autoConn, &hidden, &d.wifiEAPServerNames,
			&d.vpnServer, &d.vpnProtocol, &d.vpnAuthMethod, &splitTun, &alwaysOn, &d.vpnTrustedNetwork,
			&d.clientCertSubjectTemplate, &d.clientCertValidityDays, &ccExp, &d.clientCertKeyLocation,
		) == nil {
			d.wifiAutoConnect = autoConn != 0
			d.wifiHidden = hidden != 0
			d.vpnSplitTunnel = splitTun != 0
			d.vpnAlwaysOn = alwaysOn != 0
			d.clientCertExportable = ccExp != 0
			desired = append(desired, d)
			desiredIDs[d.id] = true
		}
	}
	pRows.Close()

	var queued int
	for _, d := range desired {
		if _, exists := deployed[d.id]; exists {
			continue
		}
		var (
			delURI string
			q      int
			qerr   error
		)
		switch d.profileType {
		case "root_ca", "intermediate_ca":
			delURI, q, qerr = mdm.EnqueueTrustedCertificate(db, deviceID, d.profileType, d.certThumbprint, d.certDERB64)
		case "client_cert":
			thumb, perr := invokeClientCertProvisioner(db, deviceID, d.id, d.clientCertSubjectTemplate, d.clientCertValidityDays)
			if perr != nil {
				qerr = perr
			} else {
				delURI, q, qerr = mdm.EnqueuePFXClientCertificate(db, deviceID, d.id, thumb, d.clientCertKeyLocation, d.clientCertExportable)
			}
		case "wifi":
			keyMat := ""
			if !strings.EqualFold(d.wifiSecurity, "Open") && !strings.EqualFold(d.wifiSecurity, "WPA2Enterprise") {
				keyMat = mdm.WiFiVaultSentinel(d.id)
			}
			delURI, q, qerr = mdm.EnqueueWiFiProfile(db, deviceID, mdm.WiFiProfileSpec{
				ProfileID:      d.id,
				SSID:           d.wifiSSID,
				Security:       d.wifiSecurity,
				AutoConnect:    d.wifiAutoConnect,
				HiddenNetwork:  d.wifiHidden,
				KeyMaterial:    keyMat,
				EAPServerNames: d.wifiEAPServerNames,
			}, false)
		case "vpn":
			delURI, q, qerr = mdm.EnqueueVPNProfile(db, deviceID, mdm.VPNProfileSpec{
				Name:           d.name,
				Server:         d.vpnServer,
				Protocol:       d.vpnProtocol,
				AuthMethod:     d.vpnAuthMethod,
				SplitTunnel:    d.vpnSplitTunnel,
				AlwaysOn:       d.vpnAlwaysOn,
				TrustedNetwork: d.vpnTrustedNetwork,
			}, false)
		default:
			continue
		}
		if qerr != nil {
			slog.Error("policy: queueing connectivity profile", "device_id", deviceID, "profile_id", d.id, "err", qerr)
			continue
		}
		queued += q
		_, _ = db.Exec(dbpkg.Rebind(`
			INSERT INTO device_network_pki_state (device_id, profile_id, profile_name, profile_type, delete_oma_uri, updated_at)
			VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (device_id, profile_id) DO UPDATE SET
				profile_name   = EXCLUDED.profile_name,
				delete_oma_uri = EXCLUDED.delete_oma_uri,
				updated_at     = CURRENT_TIMESTAMP
		`), deviceID, d.id, d.name, d.profileType, delURI)
	}

	for pid, st := range deployed {
		if !desiredIDs[pid] {
			if st.deleteURI != "" {
				if _, qerr := mdm.EnqueueDelete(db, deviceID, st.deleteURI); qerr == nil {
					queued++
				}
			}
			if st.profileType == "client_cert" {
				invokeClientCertRevoker(db, deviceID, pid, st.deleteURI)
			}
			_, _ = db.Exec(dbpkg.Rebind(`
				DELETE FROM device_network_pki_state WHERE device_id = ? AND profile_id = ?
			`), deviceID, pid)
		}
	}

	return queued
}

// ReconcileConnectivityFleet reconciles Root/Intermediate CA certificates, client PFX certs,
// Wi-Fi, and VPNv2 profiles across all active devices.
func ReconcileConnectivityFleet(db *sql.DB) (governedDevices int, commandsQueued int) {
	rows, err := db.Query(`SELECT id FROM devices WHERE is_active = 1`)
	if err != nil {
		return 0, 0
	}
	var devIDs []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			devIDs = append(devIDs, id)
		}
	}
	rows.Close()

	for _, devID := range devIDs {
		q := ReconcileConnectivityDevice(db, devID)
		if q > 0 {
			governedDevices++
			commandsQueued += q
			notifyWake(devID)
		}
	}
	return governedDevices, commandsQueued
}
