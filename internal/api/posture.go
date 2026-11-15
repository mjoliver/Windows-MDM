package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// DevicePosture represents hardware inventory and Windows security posture for a device.
type DevicePosture struct {
	DeviceID          string     `json:"device_id"`
	Collected         bool       `json:"collected"`
	TotalRAMMB        *int64     `json:"total_ram_mb"`
	TotalStorageMB    *int64     `json:"total_storage_mb"`
	FreeStorageMB     *int64     `json:"free_storage_mb"`
	BIOSVersion       string     `json:"bios_version"`
	OSPlatform        string     `json:"os_platform"`
	TPMVersion        string     `json:"tpm_version"`
	SecureBootState   *int64     `json:"secure_boot_state"`
	SecureBootLabel   string     `json:"secure_boot_label"`
	EncryptionStatus  *int64     `json:"encryption_status"`
	EncryptionLabel   string     `json:"encryption_label"`
	AntivirusStatus   *int64     `json:"antivirus_status"`
	AntivirusLabel    string     `json:"antivirus_label"`
	FirewallStatus    *int64     `json:"firewall_status"`
	FirewallLabel     string     `json:"firewall_label"`
	UpdatedAt         *time.Time `json:"updated_at"`
	WNSEnabled        bool       `json:"wns_enabled"`
	WNSChannelActive  bool       `json:"wns_channel_active"`
	WNSUpdatedAt      *time.Time `json:"wns_updated_at"`
	WNSLastPushAt     *time.Time `json:"wns_last_push_at"`
	WNSLastPushStatus string     `json:"wns_last_push_status"`
}

// FleetPostureSummary aggregates security posture health across active enrolled devices.
type FleetPostureSummary struct {
	TotalActiveDevices     int `json:"total_active_devices"`
	PostureReportedDevices int `json:"posture_reported_devices"`
	SecureBootEnabled      int `json:"secure_boot_enabled"`
	BitLockerEncrypted     int `json:"bitlocker_encrypted"`
	AntivirusHealthy       int `json:"antivirus_healthy"`
	FirewallHealthy        int `json:"firewall_healthy"`
}

func secureBootLabel(v *int64) string {
	if v == nil {
		return "Unknown"
	}
	switch *v {
	case 1:
		return "Enabled"
	case 2:
		return "Disabled"
	case 0:
		return "Unsupported"
	default:
		return fmt.Sprintf("Code %d", *v)
	}
}

func encryptionLabel(v *int64) string {
	if v == nil {
		return "Unknown"
	}
	if *v == 0 {
		return "Encrypted"
	}
	return fmt.Sprintf("Attention (0x%X)", *v)
}

func securityMonitorLabel(v *int64) string {
	if v == nil {
		return "Unknown"
	}
	switch *v {
	case 0:
		return "Active & Monitoring"
	case 1:
		return "Disabled"
	case 2:
		return "Partially Monitoring"
	case 3:
		return "Temporarily Paused"
	case 4:
		return "Not Applicable"
	default:
		return fmt.Sprintf("Code %d", *v)
	}
}

// HandleGetDevicePosture returns the latest collected hardware and security posture for a device.
// GET /api/devices/{id}/posture
func (h *Handler) HandleGetDevicePosture(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var exists int
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM devices WHERE id = ?`), id,
	).Scan(&exists); err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if exists == 0 {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	var (
		ram, totalDisk, freeDisk           sql.NullInt64
		bios, platform, tpm                sql.NullString
		secBoot, encStatus, avStat, fwStat sql.NullInt64
		updatedAt                          time.Time
	)

	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT total_ram_mb, total_storage_mb, free_storage_mb,
		       COALESCE(bios_version,''), COALESCE(os_platform,''), COALESCE(tpm_version,''),
		       secure_boot_state, encryption_status, antivirus_status, firewall_status,
		       updated_at
		FROM device_posture
		WHERE device_id = ?
	`), id).Scan(
		&ram, &totalDisk, &freeDisk,
		&bios, &platform, &tpm,
		&secBoot, &encStatus, &avStat, &fwStat,
		&updatedAt,
	)

	populateWNS := func(p *DevicePosture) {
		p.WNSEnabled = h.wns != nil && h.wns.Enabled()
		var (
			channelURI     string
			chanUpdatedAt  time.Time
			lastPushAt     sql.NullTime
			lastPushStatus sql.NullString
		)
		wErr := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
			SELECT channel_uri, updated_at, last_push_at, COALESCE(last_push_status, '')
			FROM device_wns_channels
			WHERE device_id = ?
		`), id).Scan(&channelURI, &chanUpdatedAt, &lastPushAt, &lastPushStatus)
		if wErr == nil && channelURI != "" {
			p.WNSChannelActive = true
			p.WNSUpdatedAt = &chanUpdatedAt
			if lastPushAt.Valid {
				t := lastPushAt.Time
				p.WNSLastPushAt = &t
			}
			p.WNSLastPushStatus = lastPushStatus.String
		}
	}

	if errors.Is(err, sql.ErrNoRows) {
		p := DevicePosture{
			DeviceID:        id,
			Collected:       false,
			SecureBootLabel: "Unknown",
			EncryptionLabel: "Unknown",
			AntivirusLabel:  "Unknown",
			FirewallLabel:   "Unknown",
		}
		populateWNS(&p)
		respondOK(w, p)
		return
	}
	if err != nil {
		slog.Error("api: reading device posture", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load device posture")
		return
	}

	toPtr := func(n sql.NullInt64) *int64 {
		if !n.Valid {
			return nil
		}
		v := n.Int64
		return &v
	}

	p := DevicePosture{
		DeviceID:         id,
		Collected:        true,
		TotalRAMMB:       toPtr(ram),
		TotalStorageMB:   toPtr(totalDisk),
		FreeStorageMB:    toPtr(freeDisk),
		BIOSVersion:      bios.String,
		OSPlatform:       platform.String,
		TPMVersion:       tpm.String,
		SecureBootState:  toPtr(secBoot),
		EncryptionStatus: toPtr(encStatus),
		AntivirusStatus:  toPtr(avStat),
		FirewallStatus:   toPtr(fwStat),
		UpdatedAt:        &updatedAt,
	}
	p.SecureBootLabel = secureBootLabel(p.SecureBootState)
	p.EncryptionLabel = encryptionLabel(p.EncryptionStatus)
	p.AntivirusLabel = securityMonitorLabel(p.AntivirusStatus)
	p.FirewallLabel = securityMonitorLabel(p.FirewallStatus)
	populateWNS(&p)

	respondOK(w, p)
}

// HandleRefreshDevicePosture queues OMA-DM Get commands for hardware and security posture URIs.
// POST /api/devices/{id}/posture/refresh
func (h *Handler) HandleRefreshDevicePosture(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queued, err := enqueueRef.PostureRefresh(h.db, id)
	if err != nil {
		slog.Error("api: queuing posture refresh", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue posture refresh")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.posture_refresh", "device", id, fmt.Sprintf(`{"commands_queued":%d}`, queued))
	slog.Info("posture refresh queued", "device_id", id, "commands_queued", queued, "actor", actor)
	respondOK(w, map[string]interface{}{"status": "queued", "commands_queued": queued})
}

// HandleFleetPostureSummary returns fleet-wide counts for Secure Boot, BitLocker, Defender, and Firewall.
// GET /api/posture/summary
func (h *Handler) HandleFleetPostureSummary(w http.ResponseWriter, r *http.Request) {
	var summary FleetPostureSummary
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM devices WHERE is_active = 1`),
	).Scan(&summary.TotalActiveDevices); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to query devices")
		return
	}

	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN dp.secure_boot_state = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dp.encryption_status = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dp.antivirus_status = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dp.firewall_status = 0 THEN 1 ELSE 0 END), 0)
		FROM device_posture dp
		JOIN devices d ON d.id = dp.device_id
		WHERE d.is_active = 1
	`)).Scan(
		&summary.PostureReportedDevices,
		&summary.SecureBootEnabled,
		&summary.BitLockerEncrypted,
		&summary.AntivirusHealthy,
		&summary.FirewallHealthy,
	)
	if err != nil {
		slog.Error("api: querying fleet posture summary", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to query posture summary")
		return
	}

	respondOK(w, summary)
}
