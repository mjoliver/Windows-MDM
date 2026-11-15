package policy

import (
	"database/sql"
	"log/slog"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

type desiredNetworkPKIProfile struct {
	id                string
	name              string
	profileType       string
	certThumbprint    string
	certDERB64        string
	wifiSSID          string
	wifiSecurity      string
	wifiAutoConnect   bool
	wifiHidden        bool
	vpnServer         string
	vpnProtocol       string
	vpnAuthMethod     string
	vpnSplitTunnel    bool
	vpnAlwaysOn       bool
	vpnTrustedNetwork string
}

// ReconcileConnectivityDevice provisions assigned Root/Intermediate CA certificates,
// Wi-Fi profiles, and VPNv2 profiles onto deviceID and retracts any unassigned ones.
func ReconcileConnectivityDevice(db *sql.DB, deviceID string) int {
	type prevState struct {
		deleteURI string
	}
	deployed := make(map[string]prevState)
	sRows, err := db.Query(dbpkg.Rebind(`
		SELECT profile_id, delete_oma_uri FROM device_network_pki_state WHERE device_id = ?
	`), deviceID)
	if err == nil {
		for sRows.Next() {
			var pid, duri string
			if sRows.Scan(&pid, &duri) == nil && pid != "" {
				deployed[pid] = prevState{deleteURI: duri}
			}
		}
		sRows.Close()
	}

	pRows, err := db.Query(dbpkg.Rebind(`
		SELECT DISTINCT
			p.id, p.name, p.profile_type,
			p.cert_thumbprint, p.cert_der_b64,
			p.wifi_ssid, p.wifi_security, p.wifi_auto_connect, p.wifi_hidden,
			p.vpn_server, p.vpn_protocol, p.vpn_auth_method, p.vpn_split_tunnel, p.vpn_always_on, p.vpn_trusted_network
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
		var autoConn, hidden, splitTun, alwaysOn int
		if pRows.Scan(
			&d.id, &d.name, &d.profileType,
			&d.certThumbprint, &d.certDERB64,
			&d.wifiSSID, &d.wifiSecurity, &autoConn, &hidden,
			&d.vpnServer, &d.vpnProtocol, &d.vpnAuthMethod, &splitTun, &alwaysOn, &d.vpnTrustedNetwork,
		) == nil {
			d.wifiAutoConnect = autoConn != 0
			d.wifiHidden = hidden != 0
			d.vpnSplitTunnel = splitTun != 0
			d.vpnAlwaysOn = alwaysOn != 0
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
		case "wifi":
			keyMat := ""
			if !strings.EqualFold(d.wifiSecurity, "Open") {
				keyMat = mdm.WiFiVaultSentinel(d.id)
			}
			delURI, q, qerr = mdm.EnqueueWiFiProfile(db, deviceID, mdm.WiFiProfileSpec{
				ProfileID:     d.id,
				SSID:          d.wifiSSID,
				Security:      d.wifiSecurity,
				AutoConnect:   d.wifiAutoConnect,
				HiddenNetwork: d.wifiHidden,
				KeyMaterial:   keyMat,
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
			_, _ = db.Exec(dbpkg.Rebind(`
				DELETE FROM device_network_pki_state WHERE device_id = ? AND profile_id = ?
			`), deviceID, pid)
		}
	}

	return queued
}

// ReconcileConnectivityFleet reconciles Root/Intermediate CA certificates, Wi-Fi,
// and VPNv2 profiles across all active devices.
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
