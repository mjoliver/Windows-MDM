package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/policy"
)

// ConnectivityProfile represents a managed Root/Intermediate CA certificate,
// per-device client PFX certificate, Wi-Fi profile, or VPNv2 profile (secrets/raw DER omitted).
type ConnectivityProfile struct {
	ID                        string     `json:"id"`
	Name                      string     `json:"name"`
	ProfileType               string     `json:"profile_type"` // "root_ca" | "intermediate_ca" | "client_cert" | "wifi" | "vpn"
	CertThumbprint            string     `json:"cert_thumbprint,omitempty"`
	CertSubject               string     `json:"cert_subject,omitempty"`
	CertNotAfter              *time.Time `json:"cert_not_after,omitempty"`
	ClientCertSubjectTemplate string     `json:"client_cert_subject_template,omitempty"`
	ClientCertValidityDays    int        `json:"client_cert_validity_days,omitempty"`
	ClientCertExportable      bool       `json:"client_cert_exportable"`
	ClientCertKeyLocation     int        `json:"client_cert_key_location,omitempty"`
	WiFiSSID                  string     `json:"wifi_ssid,omitempty"`
	WiFiSecurity              string     `json:"wifi_security,omitempty"`
	WiFiAutoConnect           bool       `json:"wifi_auto_connect"`
	WiFiHidden                bool       `json:"wifi_hidden"`
	WiFiEAPServerNames        string     `json:"wifi_eap_server_names,omitempty"`
	HasWiFiPSK                bool       `json:"has_wifi_psk"`
	VPNServer                 string     `json:"vpn_server,omitempty"`
	VPNProtocol               string     `json:"vpn_protocol,omitempty"`
	VPNAuthMethod             string     `json:"vpn_auth_method,omitempty"`
	VPNSplitTunnel            bool       `json:"vpn_split_tunnel"`
	VPNAlwaysOn               bool       `json:"vpn_always_on"`
	VPNTrustedNetwork         string     `json:"vpn_trusted_network,omitempty"`
	TargetAllDevices          bool       `json:"target_all_devices"`
	GroupIDs                  []string   `json:"group_ids"`
	DeployedDevices           int        `json:"deployed_devices"`
	CreatedBy                 string     `json:"created_by"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
	CommandsQueued            int        `json:"commands_queued,omitempty"`
}

// DeviceConnectivityItem represents one CA cert, client PFX cert, Wi-Fi, or VPN profile deployed on a device.
type DeviceConnectivityItem struct {
	ProfileID        string     `json:"profile_id"`
	ProfileName      string     `json:"profile_name"`
	ProfileType      string     `json:"profile_type"`
	DeleteOMAURI     string     `json:"delete_oma_uri"`
	IssuedThumbprint string     `json:"issued_thumbprint,omitempty"`
	IssuedSubject    string     `json:"issued_subject,omitempty"`
	IssuedNotAfter   *time.Time `json:"issued_not_after,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ProvisionDeviceClientCert mints (or reuses an active) per-device PKCS#12 client certificate
// signed by the Latchz Root CA, seals the .pfx archive + CSPRNG password in the AES-256-GCM vault,
// and returns the uppercase SHA-1 thumbprint for PFXCertInstall CSP deployment.
func (h *Handler) ProvisionDeviceClientCert(dbConn *sql.DB, deviceID, profileID, subjectTemplate string, validityDays int) (string, error) {
	if h.ca == nil {
		return "", errors.New("internal Root CA is not configured")
	}
	if h.vault == nil {
		return "", errors.New("secret vault is not configured (set server.master_secret)")
	}
	targetDB := dbConn
	if targetDB == nil {
		targetDB = h.db
	}

	var existingThumb string
	var existingNotAfter time.Time
	err := targetDB.QueryRow(dbpkg.Rebind(`
		SELECT thumbprint, not_after
		FROM device_issued_client_certs
		WHERE device_id = ? AND profile_id = ?
	`), deviceID, profileID).Scan(&existingThumb, &existingNotAfter)
	if err == nil && existingThumb != "" && existingNotAfter.After(time.Now().UTC().Add(24*time.Hour)) {
		return existingThumb, nil
	}

	var devName, serial string
	_ = targetDB.QueryRow(dbpkg.Rebind(`
		SELECT COALESCE(device_name, ''), COALESCE(serial_number, '')
		FROM devices WHERE id = ?
	`), deviceID).Scan(&devName, &serial)

	cn, dnsSANs := mdm.RenderClientCertSubject(subjectTemplate, deviceID, devName, serial)
	pfxPwd, err := pki.GeneratePFXPassword()
	if err != nil {
		return "", err
	}

	issued, err := h.ca.IssueClientPFX(deviceID, cn, dnsSANs, validityDays, pfxPwd)
	if err != nil {
		return "", err
	}

	encPwd, err := h.vault.Encrypt(pfxPwd, mdm.PFXVaultPwdAAD(deviceID, profileID))
	if err != nil {
		return "", fmt.Errorf("encrypting PFX password: %w", err)
	}
	encBlob, err := h.vault.Encrypt(issued.PFXBase64, mdm.PFXVaultBlobAAD(deviceID, profileID))
	if err != nil {
		return "", fmt.Errorf("encrypting PFX archive: %w", err)
	}

	_, err = targetDB.Exec(dbpkg.Rebind(`
		INSERT INTO device_issued_client_certs (
			device_id, profile_id, thumbprint, serial_number, subject,
			not_before, not_after, pfx_b64_encrypted, pfx_password_encrypted, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT (device_id, profile_id) DO UPDATE SET
			thumbprint             = EXCLUDED.thumbprint,
			serial_number          = EXCLUDED.serial_number,
			subject                = EXCLUDED.subject,
			not_before             = EXCLUDED.not_before,
			not_after              = EXCLUDED.not_after,
			pfx_b64_encrypted      = EXCLUDED.pfx_b64_encrypted,
			pfx_password_encrypted = EXCLUDED.pfx_password_encrypted,
			created_at             = CURRENT_TIMESTAMP
	`), deviceID, profileID, issued.ThumbprintSHA1, issued.SerialNumber, issued.Subject,
		issued.NotBefore, issued.NotAfter, encBlob, encPwd)
	if err != nil {
		return "", fmt.Errorf("saving issued client certificate: %w", err)
	}

	return issued.ThumbprintSHA1, nil
}

// RevokeDeviceClientCert cleans up vault-sealed PFX material and marks the leaf thumbprint revoked.
func (h *Handler) RevokeDeviceClientCert(dbConn *sql.DB, deviceID, profileID, deleteURI string) {
	targetDB := dbConn
	if targetDB == nil {
		targetDB = h.db
	}
	thumb := strings.TrimPrefix(strings.TrimSpace(deleteURI), mdm.OMAPFXCertInstallPrefix+"/")
	if thumb == "" {
		_ = targetDB.QueryRow(dbpkg.Rebind(`
			SELECT thumbprint FROM device_issued_client_certs WHERE device_id = ? AND profile_id = ?
		`), deviceID, profileID).Scan(&thumb)
	}
	_, _ = targetDB.Exec(dbpkg.Rebind(`
		DELETE FROM device_issued_client_certs WHERE device_id = ? AND profile_id = ?
	`), deviceID, profileID)
	if h.ca != nil && thumb != "" {
		_ = h.ca.RevokeCertByThumbprint(thumb)
	}
}

// HandleListConnectivityProfiles lists all Root/Intermediate CA, Client PFX, Wi-Fi, and VPN profiles.
// GET /api/connectivity/profiles
func (h *Handler) HandleListConnectivityProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT
			p.id, p.name, p.profile_type,
			p.cert_thumbprint, p.cert_subject, p.cert_not_after,
			COALESCE(p.client_cert_subject_template, 'CN={{device_name}}'),
			COALESCE(p.client_cert_validity_days, 365),
			COALESCE(p.client_cert_exportable, 0),
			COALESCE(p.client_cert_key_location, 3),
			p.wifi_ssid, p.wifi_security, p.wifi_auto_connect, p.wifi_hidden,
			COALESCE(p.wifi_eap_server_names, ''), p.wifi_psk_encrypted,
			p.vpn_server, p.vpn_protocol, p.vpn_auth_method, p.vpn_split_tunnel, p.vpn_always_on, p.vpn_trusted_network,
			p.target_all_devices, p.created_by, p.created_at, p.updated_at,
			(SELECT COUNT(*) FROM device_network_pki_state dns
			 JOIN devices d ON d.id = dns.device_id
			 WHERE dns.profile_id = p.id AND d.is_active = 1) AS deployed_devices
		FROM network_pki_profiles p
		ORDER BY p.created_at DESC
	`)
	if err != nil {
		slog.Error("api: listing connectivity profiles", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list connectivity profiles")
		return
	}
	defer rows.Close()

	out := []ConnectivityProfile{}
	for rows.Next() {
		var cp ConnectivityProfile
		var notAfter sql.NullTime
		var autoConn, hidden, splitTun, alwaysOn, targetAll, ccExp int
		var pskEnc string
		if err := rows.Scan(
			&cp.ID, &cp.Name, &cp.ProfileType,
			&cp.CertThumbprint, &cp.CertSubject, &notAfter,
			&cp.ClientCertSubjectTemplate, &cp.ClientCertValidityDays, &ccExp, &cp.ClientCertKeyLocation,
			&cp.WiFiSSID, &cp.WiFiSecurity, &autoConn, &hidden, &cp.WiFiEAPServerNames, &pskEnc,
			&cp.VPNServer, &cp.VPNProtocol, &cp.VPNAuthMethod, &splitTun, &alwaysOn, &cp.VPNTrustedNetwork,
			&targetAll, &cp.CreatedBy, &cp.CreatedAt, &cp.UpdatedAt, &cp.DeployedDevices,
		); err != nil {
			continue
		}
		if notAfter.Valid {
			t := notAfter.Time
			cp.CertNotAfter = &t
		}
		cp.ClientCertExportable = ccExp != 0
		cp.WiFiAutoConnect = autoConn != 0
		cp.WiFiHidden = hidden != 0
		cp.HasWiFiPSK = pskEnc != ""
		cp.VPNSplitTunnel = splitTun != 0
		cp.VPNAlwaysOn = alwaysOn != 0
		cp.TargetAllDevices = targetAll != 0
		cp.GroupIDs = []string{}
		out = append(out, cp)
	}

	for i := range out {
		gRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
			SELECT group_id FROM group_network_pki_profiles WHERE profile_id = ? ORDER BY group_id ASC
		`), out[i].ID)
		if err == nil {
			for gRows.Next() {
				var gid string
				if gRows.Scan(&gid) == nil {
					out[i].GroupIDs = append(out[i].GroupIDs, gid)
				}
			}
			gRows.Close()
		}
	}

	respondOK(w, out)
}

// HandleCreateConnectivityProfile creates a Root CA, Intermediate CA, Client PFX Cert,
// Wi-Fi (WPA2/WPA3/WPA2-Enterprise EAP-TLS), or VPNv2 profile and reconciles governed devices.
// POST /api/connectivity/profiles
func (h *Handler) HandleCreateConnectivityProfile(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Name                      string   `json:"name"`
		ProfileType               string   `json:"profile_type"`
		CertificatePEM            string   `json:"certificate_pem"`
		ClientCertSubjectTemplate string   `json:"client_cert_subject_template"`
		ClientCertValidityDays    int      `json:"client_cert_validity_days"`
		ClientCertExportable      bool     `json:"client_cert_exportable"`
		ClientCertKeyLocation     int      `json:"client_cert_key_location"`
		WiFiSSID                  string   `json:"wifi_ssid"`
		WiFiSecurity              string   `json:"wifi_security"`
		WiFiAutoConnect           *bool    `json:"wifi_auto_connect"`
		WiFiHidden                bool     `json:"wifi_hidden"`
		WiFiPSK                   string   `json:"wifi_psk"`
		WiFiEAPServerNames        string   `json:"wifi_eap_server_names"`
		VPNServer                 string   `json:"vpn_server"`
		VPNProtocol               string   `json:"vpn_protocol"`
		VPNAuthMethod             string   `json:"vpn_auth_method"`
		VPNSplitTunnel            *bool    `json:"vpn_split_tunnel"`
		VPNAlwaysOn               bool     `json:"vpn_always_on"`
		VPNTrustedNetwork         string   `json:"vpn_trusted_network"`
		TargetAllDevices          *bool    `json:"target_all_devices"`
		GroupIDs                  []string `json:"group_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}
	ptype := strings.ToLower(strings.TrimSpace(body.ProfileType))
	id := uuid.NewString()
	now := time.Now().UTC()

	targetAll := true
	if body.TargetAllDevices != nil {
		targetAll = *body.TargetAllDevices
	}
	autoConn := true
	if body.WiFiAutoConnect != nil {
		autoConn = *body.WiFiAutoConnect
	}
	splitTunnel := true
	if body.VPNSplitTunnel != nil {
		splitTunnel = *body.VPNSplitTunnel
	}

	var (
		certThumb, certSubj, certDER string
		certNotAfter                 *time.Time
		ccTemplate                   = "CN={{device_name}}"
		ccValDays                    = 365
		ccExportable                 = body.ClientCertExportable
		ccKeyLoc                     = 3
		wifiSSID, wifiSec, pskEnc    string
		wifiEAPServers               string
		vpnSrv, vpnProto, vpnAuth    string
		vpnTrusted                   string
	)

	switch ptype {
	case "root_ca", "intermediate_ca":
		parsed, err := mdm.ParseX509CertificatePayload(body.CertificatePEM)
		if err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
		certThumb = parsed.ThumbprintSHA1
		certSubj = parsed.Subject
		t := parsed.NotAfter
		certNotAfter = &t
		certDER = parsed.DERBase64

	case "client_cert":
		if h.ca == nil {
			respondErr(w, http.StatusServiceUnavailable, "internal Root CA is not configured")
			return
		}
		if h.vault == nil {
			respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
			return
		}
		if t := strings.TrimSpace(body.ClientCertSubjectTemplate); t != "" {
			ccTemplate = t
		}
		if body.ClientCertValidityDays > 0 {
			ccValDays = body.ClientCertValidityDays
		}
		if ccValDays < 1 || ccValDays > 3650 {
			respondErr(w, http.StatusBadRequest, "client_cert_validity_days must be between 1 and 3650")
			return
		}
		if body.ClientCertKeyLocation != 0 {
			if body.ClientCertKeyLocation != 1 && body.ClientCertKeyLocation != 2 && body.ClientCertKeyLocation != 3 {
				respondErr(w, http.StatusBadRequest, "client_cert_key_location must be 1 (TPM), 2 (TPM or Software), or 3 (Software KSP)")
				return
			}
			ccKeyLoc = body.ClientCertKeyLocation
		}
		// Enforce Microsoft PFXCertInstall CSP constraint: exportable keys require Software KSP (3).
		if ccExportable {
			ccKeyLoc = 3
		}

	case "wifi":
		wifiSSID = strings.TrimSpace(body.WiFiSSID)
		wifiSec = strings.TrimSpace(body.WiFiSecurity)
		if wifiSec == "" {
			wifiSec = "WPA2PSK"
		}
		wifiEAPServers = strings.TrimSpace(body.WiFiEAPServerNames)
		if _, err := mdm.BuildWLANProfileXML(mdm.WiFiProfileSpec{
			ProfileID:      id,
			SSID:           wifiSSID,
			Security:       wifiSec,
			AutoConnect:    autoConn,
			HiddenNetwork:  body.WiFiHidden,
			KeyMaterial:    "placeholder123",
			EAPServerNames: wifiEAPServers,
		}); err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !strings.EqualFold(wifiSec, "Open") && !strings.EqualFold(wifiSec, "WPA2Enterprise") {
			if h.vault == nil {
				respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
				return
			}
			psk := body.WiFiPSK
			if len(psk) < 8 || len(psk) > 63 {
				respondErr(w, http.StatusBadRequest, "wifi_psk must be between 8 and 63 characters")
				return
			}
			enc, err := h.vault.Encrypt(psk, mdm.WiFiVaultAADPrefix+id)
			if err != nil {
				respondErr(w, http.StatusInternalServerError, "failed to encrypt Wi-Fi passphrase")
				return
			}
			pskEnc = enc
		}

	case "vpn":
		vpnSrv = strings.TrimSpace(body.VPNServer)
		vpnProto = strings.TrimSpace(body.VPNProtocol)
		if vpnProto == "" {
			vpnProto = "IKEv2"
		}
		vpnAuth = strings.TrimSpace(body.VPNAuthMethod)
		if vpnAuth == "" {
			vpnAuth = "Eap"
		}
		if vpnAuth != "Eap" && vpnAuth != "Certificate" {
			respondErr(w, http.StatusBadRequest, "vpn_auth_method must be 'Eap' or 'Certificate'")
			return
		}
		vpnTrusted = strings.TrimSpace(body.VPNTrustedNetwork)
		if _, err := mdm.BuildVPNProfileXML(mdm.VPNProfileSpec{
			Name:           name,
			Server:         vpnSrv,
			Protocol:       vpnProto,
			AuthMethod:     vpnAuth,
			SplitTunnel:    splitTunnel,
			AlwaysOn:       body.VPNAlwaysOn,
			TrustedNetwork: vpnTrusted,
		}); err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}

	default:
		respondErr(w, http.StatusBadRequest, "profile_type must be root_ca, intermediate_ca, client_cert, wifi, or vpn")
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback()

	var certNotAfterVal interface{}
	if certNotAfter != nil {
		certNotAfterVal = *certNotAfter
	}

	_, err = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO network_pki_profiles (
			id, name, profile_type,
			cert_thumbprint, cert_subject, cert_not_after, cert_der_b64,
			client_cert_subject_template, client_cert_validity_days, client_cert_exportable, client_cert_key_location,
			wifi_ssid, wifi_security, wifi_auto_connect, wifi_hidden, wifi_eap_server_names, wifi_psk_encrypted,
			vpn_server, vpn_protocol, vpn_auth_method, vpn_split_tunnel, vpn_always_on, vpn_trusted_network,
			target_all_devices, created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		id, name, ptype,
		certThumb, certSubj, certNotAfterVal, certDER,
		ccTemplate, ccValDays, boolToSQLInt(ccExportable), ccKeyLoc,
		wifiSSID, wifiSec, boolToSQLInt(autoConn), boolToSQLInt(body.WiFiHidden), wifiEAPServers, pskEnc,
		vpnSrv, vpnProto, vpnAuth, boolToSQLInt(splitTunnel), boolToSQLInt(body.VPNAlwaysOn), vpnTrusted,
		boolToSQLInt(targetAll), actor, now, now,
	)
	if err != nil {
		slog.Error("api: inserting connectivity profile", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save connectivity profile")
		return
	}

	seen := make(map[string]bool)
	groupIDs := []string{}
	for _, rawGID := range body.GroupIDs {
		gid := strings.TrimSpace(rawGID)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		if _, err := tx.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO group_network_pki_profiles (group_id, profile_id) VALUES (?, ?)
		`), gid, id); err != nil {
			respondErr(w, http.StatusBadRequest, "invalid group_id: "+gid)
			return
		}
		groupIDs = append(groupIDs, gid)
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to commit connectivity profile")
		return
	}

	_, queued := policy.ReconcileConnectivityFleet(h.db)

	h.audit(r, actor, "connectivity.profile_create", "connectivity_profile", id,
		fmt.Sprintf(`{"name":%q,"profile_type":%q,"commands_queued":%d}`, name, ptype, queued))

	respondCreated(w, ConnectivityProfile{
		ID:                        id,
		Name:                      name,
		ProfileType:               ptype,
		CertThumbprint:            certThumb,
		CertSubject:               certSubj,
		CertNotAfter:              certNotAfter,
		ClientCertSubjectTemplate: ccTemplate,
		ClientCertValidityDays:    ccValDays,
		ClientCertExportable:      ccExportable,
		ClientCertKeyLocation:     ccKeyLoc,
		WiFiSSID:                  wifiSSID,
		WiFiSecurity:              wifiSec,
		WiFiAutoConnect:           autoConn,
		WiFiHidden:                body.WiFiHidden,
		WiFiEAPServerNames:        wifiEAPServers,
		HasWiFiPSK:                pskEnc != "",
		VPNServer:                 vpnSrv,
		VPNProtocol:               vpnProto,
		VPNAuthMethod:             vpnAuth,
		VPNSplitTunnel:            splitTunnel,
		VPNAlwaysOn:               body.VPNAlwaysOn,
		VPNTrustedNetwork:         vpnTrusted,
		TargetAllDevices:          targetAll,
		GroupIDs:                  groupIDs,
		CreatedBy:                 actor,
		CreatedAt:                 now,
		UpdatedAt:                 now,
		CommandsQueued:            queued,
	})
}

// HandleDeleteConnectivityProfile removes a Root CA, Client PFX, Wi-Fi, or VPN profile and queues
// <Delete> on every device that previously received it.
// DELETE /api/connectivity/profiles/{id}
func (h *Handler) HandleDeleteConnectivityProfile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var name, ptype string
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT name, profile_type FROM network_pki_profiles WHERE id = ?
	`), id).Scan(&name, &ptype)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "connectivity profile not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "database error")
		return
	}

	if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM network_pki_profiles WHERE id = ?`), id); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete connectivity profile")
		return
	}

	_, queued := policy.ReconcileConnectivityFleet(h.db)

	h.audit(r, actor, "connectivity.profile_delete", "connectivity_profile", id,
		fmt.Sprintf(`{"name":%q,"profile_type":%q,"commands_queued":%d}`, name, ptype, queued))

	respondOK(w, map[string]interface{}{
		"deleted":         true,
		"commands_queued": queued,
	})
}

// HandleGetDeviceConnectivity returns CA certificates, Client PFX certs, Wi-Fi, and VPN profiles deployed on a device.
// GET /api/devices/{id}/connectivity
func (h *Handler) HandleGetDeviceConnectivity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT
			dns.profile_id, dns.profile_name, dns.profile_type, dns.delete_oma_uri,
			COALESCE(dic.thumbprint, ''), COALESCE(dic.subject, ''), dic.not_after,
			dns.updated_at
		FROM device_network_pki_state dns
		LEFT JOIN device_issued_client_certs dic
		  ON dic.device_id = dns.device_id AND dic.profile_id = dns.profile_id
		WHERE dns.device_id = ?
		ORDER BY dns.updated_at DESC
	`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load device connectivity state")
		return
	}
	defer rows.Close()

	items := []DeviceConnectivityItem{}
	for rows.Next() {
		var it DeviceConnectivityItem
		var notAfter sql.NullTime
		if rows.Scan(
			&it.ProfileID, &it.ProfileName, &it.ProfileType, &it.DeleteOMAURI,
			&it.IssuedThumbprint, &it.IssuedSubject, &notAfter, &it.UpdatedAt,
		) == nil {
			if notAfter.Valid {
				t := notAfter.Time
				it.IssuedNotAfter = &t
			}
			items = append(items, it)
		}
	}
	respondOK(w, items)
}
