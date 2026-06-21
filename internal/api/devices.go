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
	"github.com/latchzmdm/latchz/internal/policy"
)

// Device is the JSON representation of an enrolled device.
type Device struct {
	ID               string     `json:"id"`
	HardwareID       string     `json:"hardware_id"`
	DeviceName       string     `json:"device_name"`
	OSVersion        string     `json:"os_version"`
	OSBuild          string     `json:"os_build"`
	Manufacturer     string     `json:"manufacturer"`
	Model            string     `json:"model"`
	SerialNumber     string     `json:"serial_number"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	EnrolledBy       string     `json:"enrolled_by"`
	LastCheckin      *time.Time `json:"last_checkin"`
	ComplianceStatus string     `json:"compliance_status"`
	IsActive         bool       `json:"is_active"`
}

// HandleListDevices returns all enrolled devices.
// GET /api/devices
func (h *Handler) HandleListDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id, hardware_id, COALESCE(device_name,''), COALESCE(os_version,''),
		       COALESCE(os_build,''), COALESCE(manufacturer,''), COALESCE(model,''),
		       COALESCE(serial_number,''), enrolled_at, COALESCE(enrolled_by,''),
		       last_checkin, compliance_status, is_active
		FROM devices
		WHERE is_active = 1
		ORDER BY enrolled_at DESC
	`))
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
			&d.ID, &d.HardwareID, &d.DeviceName, &d.OSVersion,
			&d.OSBuild, &d.Manufacturer, &d.Model, &d.SerialNumber,
			&d.EnrolledAt, &d.EnrolledBy, &d.LastCheckin,
			&d.ComplianceStatus, &isActive,
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
		"device":               d,
		"pending_commands":     pendingCmds,
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

	// Mark device as inactive
	res, err := tx.ExecContext(r.Context(),
		dbpkg.Rebind(`UPDATE devices SET is_active = 0 WHERE id = ?`), id)
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

	h.audit(r, actor, "device.lock", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Info("remote lock queued", "device_id", id, "actor", actor)
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

	h.audit(r, actor, "device.wipe", "device", id, fmt.Sprintf(`{"queue_id":%d}`, queueID))
	slog.Warn("remote wipe queued", "device_id", id, "actor", actor)
	respondOK(w, map[string]interface{}{"status": "queued", "queue_id": queueID, "warning": "device will be factory reset on next check-in"})
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
	policy.ApplyDevice(h.db, id)

	h.audit(r, actor, "device.sync", "device", id, fmt.Sprintf(`{"queued_gets":%d}`, queued))
	respondOK(w, map[string]interface{}{"status": "sync_queued", "commands_queued": queued})
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
		ORDER BY created_at DESC
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

func (h *Handler) getDevice(r *http.Request, id string) (*Device, error) {
	var d Device
	var isActive int
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, hardware_id, COALESCE(device_name,''), COALESCE(os_version,''),
		       COALESCE(os_build,''), COALESCE(manufacturer,''), COALESCE(model,''),
		       COALESCE(serial_number,''), enrolled_at, COALESCE(enrolled_by,''),
		       last_checkin, compliance_status, is_active
		FROM devices WHERE id = ?
	`), id).Scan(
		&d.ID, &d.HardwareID, &d.DeviceName, &d.OSVersion,
		&d.OSBuild, &d.Manufacturer, &d.Model, &d.SerialNumber,
		&d.EnrolledAt, &d.EnrolledBy, &d.LastCheckin,
		&d.ComplianceStatus, &isActive,
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
}

// keep imports used
var _ = uuid.New
var _ = mdm.EnqueueGet
