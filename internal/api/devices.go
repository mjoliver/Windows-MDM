package api

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/webhooks"
)

// Device is the JSON representation of an enrolled device.
type Device struct {
	ID               string     `json:"id"`
	HardwareID       string     `json:"hardware_id"`
	DeviceName       string     `json:"device_name"`
	PendingHostname  string     `json:"pending_hostname,omitempty"`
	OSVersion        string     `json:"os_version"`
	OSBuild          string     `json:"os_build"`
	Manufacturer     string     `json:"manufacturer"`
	Model            string     `json:"model"`
	SerialNumber     string     `json:"serial_number"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	EnrolledBy       string     `json:"enrolled_by"`
	LastCheckin      *time.Time `json:"last_checkin"`
	ComplianceStatus string     `json:"compliance_status"`
	EnrollmentState  string     `json:"enrollment_state"`
	RetiredAt        *time.Time `json:"retired_at,omitempty"`
	IsActive         bool       `json:"is_active"`
}

// HandleListDevices returns all enrolled devices (or includes retired devices when ?include_retired=1).
// GET /api/devices
func (h *Handler) HandleListDevices(w http.ResponseWriter, r *http.Request) {
	includeRetired := r.URL.Query().Get("include_retired") == "1" || r.URL.Query().Get("include_retired") == "true"
	query := `
		SELECT id, hardware_id, COALESCE(device_name,''), COALESCE(pending_hostname,''),
		       COALESCE(os_version,''), COALESCE(os_build,''), COALESCE(manufacturer,''), COALESCE(model,''),
		       COALESCE(serial_number,''), enrolled_at, COALESCE(enrolled_by,''),
		       last_checkin, compliance_status, COALESCE(enrollment_state,'enrolled'), retired_at, is_active
		FROM devices
	`
	if !includeRetired {
		query += ` WHERE is_active = 1`
	}
	query += ` ORDER BY enrolled_at DESC`

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(query))
	if err != nil {
		slog.Error("api: listing devices", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list devices")
		return
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var isActive int
		if err := rows.Scan(
			&d.ID, &d.HardwareID, &d.DeviceName, &d.PendingHostname,
			&d.OSVersion, &d.OSBuild, &d.Manufacturer, &d.Model, &d.SerialNumber,
			&d.EnrolledAt, &d.EnrolledBy, &d.LastCheckin,
			&d.ComplianceStatus, &d.EnrollmentState, &d.RetiredAt, &isActive,
		); err != nil {
			slog.Error("api: scanning device row", "err", err)
			continue
		}
		d.IsActive = isActive == 1
		devices = append(devices, d)
	}
	if devices == nil {
		devices = []Device{} // return [] not null
	}
	respondOK(w, devices)
}

// HandleGetDevice returns a single device with its pending commands.
// GET /api/devices/{id}
func (h *Handler) HandleGetDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	d, err := h.getDevice(r, id)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Load pending commands count
	var pendingCmds int
	_ = h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND status = 'pending'`), id,
	).Scan(&pendingCmds)

	respondOK(w, map[string]interface{}{
		"device":           d,
		"pending_commands": pendingCmds,
	})
}

// HandleUnenrollDevice marks a device as unenrolled and revokes its certificate.
// DELETE /api/devices/{id}
func (h *Handler) HandleUnenrollDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	// Mark device as inactive / retired
	res, err := tx.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE devices SET is_active = 0, enrollment_state = 'retired', retired_at = CURRENT_TIMESTAMP WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to unenroll device")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	// Revoke device certificates
	_, _ = tx.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), id)

	// Cancel pending commands
	_, _ = tx.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE command_queue SET status = 'cancelled' WHERE device_id = ? AND status = 'pending'`), id)

	// Audit log
	_, _ = tx.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO audit_log (user_email, action, target_type, target_id, ip_address)
		VALUES (?, 'device.unenroll', 'device', ?, ?)
	`), actor, id, r.RemoteAddr)

	if err := tx.Commit(); err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	if h.wns != nil {
		_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM device_wns_channels WHERE device_id = ?`), id)
	}

	slog.Info("device unenrolled", "device_id", id, "actor", actor)
	respondOK(w, map[string]string{"status": "unenrolled", "device_id": id})
}

// HandleLockDevice queues a remote lock command for the device.
// POST /api/devices/{id}/lock
func (h *Handler) HandleLockDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	queueID, err := enqueueRef.Lock(h.db, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue lock command")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.lock", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Info("remote lock queued", "device_id", id, "actor", actor)
	respondOK(w, map[string]interface{}{"status": "queued", "queue_id": queueID})
}

// HandleRebootDevice queues an immediate restart command via Reboot CSP.
// POST /api/devices/{id}/reboot
func (h *Handler) HandleRebootDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queueID, err := enqueueRef.Reboot(h.db, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue reboot command")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.reboot", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Info("remote reboot queued", "device_id", id, "actor", actor)
	respondOK(w, map[string]interface{}{"status": "queued", "queue_id": queueID})
}

// HandleWipeDevice queues a factory reset command. Requires confirmation.
// POST /api/devices/{id}/wipe
func (h *Handler) HandleWipeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.Confirm {
		respondErr(w, http.StatusBadRequest, `wipe requires {"confirm": true} in the request body`)
		return
	}

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	queueID, err := enqueueRef.Wipe(h.db, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue wipe command")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.wipe", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Warn("remote wipe queued", "device_id", id, "actor", actor)
	respondOK(w, map[string]interface{}{"status": "queued", "queue_id": queueID, "warning": "device will be factory reset on next check-in"})
}

// HandleRenameDevice queues a remote hostname change via ./DevDetail/Ext/Microsoft/DNSComputerName
// (supports %SERIAL% and %RAND:x% macros; takes full DNS/NetBIOS effect after reboot).
// POST /api/devices/{id}/rename
func (h *Handler) HandleRenameDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		Hostname  string `json:"hostname"`
		RebootNow bool   `json:"reboot_now"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	normalized, err := mdm.ValidateHostnameTemplate(body.Hostname)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	dev, err := h.getDevice(r, id)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queueID, err := enqueueRef.Rename(h.db, id, normalized)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue rename command")
		return
	}

	pendingVal := normalized
	if dev.DeviceName != "" && equalFoldTrim(dev.DeviceName, normalized) {
		pendingVal = ""
	}
	_, _ = h.db.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE devices SET pending_hostname = ? WHERE id = ?`),
		pendingVal, id,
	)

	var rebootQueueID int64
	if body.RebootNow {
		rebootQueueID, _ = enqueueRef.Reboot(h.db, id)
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.rename", "device", id, fmt.Sprintf(`{"hostname":%q,"reboot_now":%t,"queue_id":%d}`, normalized, body.RebootNow, queueID))
	slog.Info("remote hostname rename queued", "device_id", id, "hostname", normalized, "reboot_now", body.RebootNow, "actor", actor)
	respondOK(w, map[string]interface{}{
		"status":          "queued",
		"hostname":        normalized,
		"reboot_now":      body.RebootNow,
		"queue_id":        queueID,
		"reboot_queue_id": rebootQueueID,
	})
}

// HandleRetireDevice queues a clean, non-destructive MDM unenrollment via
// ./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Unenroll. User files and OS
// state remain intact while Latchz MDM management is cleanly removed on next check-in.
// POST /api/devices/{id}/retire
func (h *Handler) HandleRetireDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.Confirm {
		respondErr(w, http.StatusBadRequest, `retire requires {"confirm": true} in the request body`)
		return
	}

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queueID, err := enqueueRef.Retire(h.db, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to queue retire command")
		return
	}

	_, _ = h.db.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE devices SET enrollment_state = 'retiring' WHERE id = ?`),
		id,
	)

	h.wakeDevice(id)
	h.audit(r, actor, "device.retire", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Info("clean MDM retire queued", "device_id", id, "actor", actor)
	respondOK(w, map[string]interface{}{
		"status":           "queued",
		"enrollment_state": "retiring",
		"queue_id":         queueID,
		"message":          "device will cleanly unenroll from Latchz MDM on next check-in without wiping personal files",
	})
}

// HandleSyncDevice triggers an immediate policy sync for a device.
// This re-evaluates all profile assignments and re-queues any non-compliant settings.
// POST /api/devices/{id}/sync
func (h *Handler) HandleSyncDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	// Queue a Get for every assigned policy setting to refresh compliance
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT DISTINCT pc.oma_uri
		FROM profile_settings ps
		JOIN policy_catalog pc ON pc.id = ps.catalog_id
		JOIN group_profiles gp ON gp.profile_id = ps.profile_id
		JOIN device_group_members dgm ON dgm.group_id = gp.group_id
		WHERE dgm.device_id = ?
	`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	var queued int
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			continue
		}
		if _, err := mdm.EnqueueGet(h.db, id, uri); err != nil {
			slog.Error("api: queuing sync Get", "uri", uri, "err", err)
			continue
		}
		queued++
	}

	// Also re-evaluate profile assignments and queue Replace commands for non-compliant policies
	policyOps.ApplyDevice(h.db, id)
	h.wakeDevice(id)

	h.audit(r, actor, "device.sync", "device", id, fmt.Sprintf(`{"queued_gets":%d}`, queued))
	respondOK(w, map[string]interface{}{"status": "sync_queued", "commands_queued": queued})
}

// HandlePushWakeDevice sends an immediate WNS wns/raw push notification to wake
// the target device's DMClient and initiate an OMA-DM SyncML session.
// POST /api/devices/{id}/push
func (h *Handler) HandlePushWakeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	if h.wns == nil || !h.wns.Enabled() {
		respondErr(w, http.StatusServiceUnavailable, "WNS push notifications are not configured on this server")
		return
	}

	res, err := h.wns.PushRaw(r.Context(), id)
	if err != nil {
		slog.Warn("api: WNS wake push failed", "device_id", id, "err", err)
		respondErr(w, http.StatusBadGateway, "WNS push failed: "+err.Error())
		return
	}

	h.audit(r, actor, "device.push_wake", "device", id, fmt.Sprintf(`{"status":%q}`, res.Status))
	respondOK(w, res)
}

// HandleGetDeviceCommands returns the command history for a device.
// GET /api/devices/{id}/commands
func (h *Handler) HandleGetDeviceCommands(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id, command_type, oma_uri, status, created_at, sent_at, completed_at, 
		       COALESCE(result_code,''), COALESCE(result_data,'')
		FROM command_queue
		WHERE device_id = ?
		ORDER BY id DESC
		LIMIT 50
	`), id)
	if err != nil {
		slog.Error("api: getting device commands", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to get command history")
		return
	}
	defer rows.Close()

	type Command struct {
		ID          int        `json:"id"`
		Type        string     `json:"type"`
		URI         string     `json:"oma_uri"`
		Status      string     `json:"status"`
		CreatedAt   time.Time  `json:"created_at"`
		SentAt      *time.Time `json:"sent_at"`
		CompletedAt *time.Time `json:"completed_at"`
		ResultCode  string     `json:"result_code"`
		ResultInfo  string     `json:"result_info"`
	}

	var commands []Command
	for rows.Next() {
		var c Command
		if err := rows.Scan(
			&c.ID, &c.Type, &c.URI, &c.Status, &c.CreatedAt,
			&c.SentAt, &c.CompletedAt, &c.ResultCode, &c.ResultInfo,
		); err != nil {
			continue
		}

		// Add friendly info for common SyncML errors
		if c.ResultCode == "406" {
			c.ResultInfo = "Not Acceptable (Device security policy or hardware restriction)"
		} else if c.ResultCode == "405" {
			c.ResultInfo = "Method Not Allowed (URI exists but doesn't support this action)"
		} else if c.ResultCode == "404" {
			c.ResultInfo = "Not Found (The device doesn't have this feature)"
		}

		commands = append(commands, c)
	}

	if commands == nil {
		commands = []Command{}
	}
	respondOK(w, map[string]interface{}{"commands": commands})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func equalFoldTrim(a, b string) bool {
	return len(a) == len(b) && (a == b || fmt.Sprintf("%s", toLowerASCII(a)) == toLowerASCII(b))
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func (h *Handler) getDevice(r *http.Request, id string) (*Device, error) {
	var d Device
	var isActive int
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, hardware_id, COALESCE(device_name,''), COALESCE(pending_hostname,''),
		       COALESCE(os_version,''), COALESCE(os_build,''), COALESCE(manufacturer,''), COALESCE(model,''),
		       COALESCE(serial_number,''), enrolled_at, COALESCE(enrolled_by,''),
		       last_checkin, compliance_status, COALESCE(enrollment_state,'enrolled'), retired_at, is_active
		FROM devices WHERE id = ?
	`), id).Scan(
		&d.ID, &d.HardwareID, &d.DeviceName, &d.PendingHostname,
		&d.OSVersion, &d.OSBuild, &d.Manufacturer, &d.Model, &d.SerialNumber,
		&d.EnrolledAt, &d.EnrolledBy, &d.LastCheckin,
		&d.ComplianceStatus, &d.EnrollmentState, &d.RetiredAt, &isActive,
	)
	if err != nil {
		return nil, err
	}
	d.IsActive = isActive == 1
	return &d, nil
}

func (h *Handler) audit(r *http.Request, actor, action, targetType, targetID, details string) {
	_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO audit_log (user_email, action, target_type, target_id, details, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)
	`), actor, action, targetType, targetID, details, r.RemoteAddr)

	if h.webhooks != nil {
		switch action {
		case "bitlocker.reveal_key", "laps.reveal_password", "device.retire", "device.wipe":
			h.webhooks.EmitAsync(webhooks.Event{
				Type:     action,
				Actor:    actor,
				TargetID: targetID,
				Summary:  fmt.Sprintf("%s triggered by %s on %s %s", action, actor, targetType, targetID),
				Data: map[string]interface{}{
					"target_type": targetType,
					"details":     details,
				},
			})
		}
	}
}

// keep imports used
var _ = uuid.New
var _ = mdm.EnqueueGet
