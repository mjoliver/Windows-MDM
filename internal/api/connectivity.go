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
	"github.com/latchzmdm/latchz/internal/policy"
)

// ConnectivityProfile represents a managed Root/Intermediate CA certificate,
// Wi-Fi profile, or VPNv2 profile (secrets/raw DER omitted).
type ConnectivityProfile struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	ProfileType       string     `json:"profile_type"` // "root_ca" | "intermediate_ca" | "wifi" | "vpn"
	CertThumbprint    string     `json:"cert_thumbprint,omitempty"`
	CertSubject       string     `json:"cert_subject,omitempty"`
	CertNotAfter      *time.Time `json:"cert_not_after,omitempty"`
	WiFiSSID          string     `json:"wifi_ssid,omitempty"`
	WiFiSecurity      string     `json:"wifi_security,omitempty"`
	WiFiAutoConnect   bool       `json:"wifi_auto_connect"`
	WiFiHidden        bool       `json:"wifi_hidden"`
	HasWiFiPSK        bool       `json:"has_wifi_psk"`
	VPNServer         string     `json:"vpn_server,omitempty"`
	VPNProtocol       string     `json:"vpn_protocol,omitempty"`
	VPNAuthMethod     string     `json:"vpn_auth_method,omitempty"`
	VPNSplitTunnel    bool       `json:"vpn_split_tunnel"`
	VPNAlwaysOn       bool       `json:"vpn_always_on"`
	VPNTrustedNetwork string     `json:"vpn_trusted_network,omitempty"`
	TargetAllDevices  bool       `json:"target_all_devices"`
	GroupIDs          []string   `json:"group_ids"`
	DeployedDevices   int        `json:"deployed_devices"`
	CreatedBy         string     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	CommandsQueued    int        `json:"commands_queued,omitempty"`
}

// DeviceConnectivityItem represents one CA cert, Wi-Fi, or VPN profile deployed on a device.
type DeviceConnectivityItem struct {
	ProfileID    string    `json:"profile_id"`
	ProfileName  string    `json:"profile_name"`
	ProfileType  string    `json:"profile_type"`
	DeleteOMAURI string    `json:"delete_oma_uri"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// HandleListConnectivityProfiles lists all Root/Intermediate CA, Wi-Fi, and VPN profiles.
// GET /api/connectivity/profiles
func (h *Handler) HandleListConnectivityProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT
			p.id, p.name, p.profile_type,
			p.cert_thumbprint, p.cert_subject, p.cert_not_after,
			p.wifi_ssid, p.wifi_security, p.wifi_auto_connect, p.wifi_hidden, p.wifi_psk_encrypted,
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
		var autoConn, hidden, splitTun, alwaysOn, targetAll int
		var pskEnc string
		if err := rows.Scan(
			&cp.ID, &cp.Name, &cp.ProfileType,
			&cp.CertThumbprint, &cp.CertSubject, &notAfter,
			&cp.WiFiSSID, &cp.WiFiSecurity, &autoConn, &hidden, &pskEnc,
			&cp.VPNServer, &cp.VPNProtocol, &cp.VPNAuthMethod, &splitTun, &alwaysOn, &cp.VPNTrustedNetwork,
			&targetAll, &cp.CreatedBy, &cp.CreatedAt, &cp.UpdatedAt, &cp.DeployedDevices,
		); err != nil {
			continue
		}
		if notAfter.Valid {
			t := notAfter.Time
			cp.CertNotAfter = &t
		}
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

// HandleCreateConnectivityProfile creates a Root CA, Intermediate CA, Wi-Fi, or VPNv2 profile
// and reconciles governed devices.
// POST /api/connectivity/profiles
func (h *Handler) HandleCreateConnectivityProfile(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Name              string   `json:"name"`
		ProfileType       string   `json:"profile_type"`
		CertificatePEM    string   `json:"certificate_pem"`
		WiFiSSID          string   `json:"wifi_ssid"`
		WiFiSecurity      string   `json:"wifi_security"`
		WiFiAutoConnect   *bool    `json:"wifi_auto_connect"`
		WiFiHidden        bool     `json:"wifi_hidden"`
		WiFiPSK           string   `json:"wifi_psk"`
		VPNServer         string   `json:"vpn_server"`
		VPNProtocol       string   `json:"vpn_protocol"`
		VPNAuthMethod     string   `json:"vpn_auth_method"`
		VPNSplitTunnel    *bool    `json:"vpn_split_tunnel"`
		VPNAlwaysOn       bool     `json:"vpn_always_on"`
		VPNTrustedNetwork string   `json:"vpn_trusted_network"`
		TargetAllDevices  *bool    `json:"target_all_devices"`
		GroupIDs          []string `json:"group_ids"`
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
		wifiSSID, wifiSec, pskEnc    string
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

	case "wifi":
		wifiSSID = strings.TrimSpace(body.WiFiSSID)
		wifiSec = strings.TrimSpace(body.WiFiSecurity)
		if wifiSec == "" {
			wifiSec = "WPA2PSK"
		}
		if _, err := mdm.BuildWLANProfileXML(mdm.WiFiProfileSpec{
			ProfileID:     id,
			SSID:          wifiSSID,
			Security:      wifiSec,
			AutoConnect:   autoConn,
			HiddenNetwork: body.WiFiHidden,
			KeyMaterial:   "placeholder123",
		}); err != nil {
			respondErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !strings.EqualFold(wifiSec, "Open") {
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
		respondErr(w, http.StatusBadRequest, "profile_type must be root_ca, intermediate_ca, wifi, or vpn")
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
			wifi_ssid, wifi_security, wifi_auto_connect, wifi_hidden, wifi_psk_encrypted,
			vpn_server, vpn_protocol, vpn_auth_method, vpn_split_tunnel, vpn_always_on, vpn_trusted_network,
			target_all_devices, created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		id, name, ptype,
		certThumb, certSubj, certNotAfterVal, certDER,
		wifiSSID, wifiSec, boolToSQLInt(autoConn), boolToSQLInt(body.WiFiHidden), pskEnc,
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
		ID:                id,
		Name:              name,
		ProfileType:       ptype,
		CertThumbprint:    certThumb,
		CertSubject:       certSubj,
		CertNotAfter:      certNotAfter,
		WiFiSSID:          wifiSSID,
		WiFiSecurity:      wifiSec,
		WiFiAutoConnect:   autoConn,
		WiFiHidden:        body.WiFiHidden,
		HasWiFiPSK:        pskEnc != "",
		VPNServer:         vpnSrv,
		VPNProtocol:       vpnProto,
		VPNAuthMethod:     vpnAuth,
		VPNSplitTunnel:    splitTunnel,
		VPNAlwaysOn:       body.VPNAlwaysOn,
		VPNTrustedNetwork: vpnTrusted,
		TargetAllDevices:  targetAll,
		GroupIDs:          groupIDs,
		CreatedBy:         actor,
		CreatedAt:         now,
		UpdatedAt:         now,
		CommandsQueued:    queued,
	})
}

// HandleDeleteConnectivityProfile removes a Root CA, Wi-Fi, or VPN profile and queues
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

// HandleGetDeviceConnectivity returns CA certificates, Wi-Fi, and VPN profiles deployed on a device.
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
		SELECT profile_id, profile_name, profile_type, delete_oma_uri, updated_at
		FROM device_network_pki_state
		WHERE device_id = ?
		ORDER BY updated_at DESC
	`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load device connectivity state")
		return
	}
	defer rows.Close()

	items := []DeviceConnectivityItem{}
	for rows.Next() {
		var it DeviceConnectivityItem
		if rows.Scan(&it.ProfileID, &it.ProfileName, &it.ProfileType, &it.DeleteOMAURI, &it.UpdatedAt) == nil {
			items = append(items, it)
		}
	}
	respondOK(w, items)
}
