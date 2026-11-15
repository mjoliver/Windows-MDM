package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/msi"
)

// msiInspectURL is injectable for unit tests so MSI inspection can be tested offline.
var msiInspectURL = msi.InspectRemoteURL

// MSIApp represents a registered Win32 .msi line-of-business application.
type MSIApp struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Publisher            string    `json:"publisher"`
	Version              string    `json:"version"`
	ProductCode          string    `json:"product_code"`
	UpgradeCode          string    `json:"upgrade_code"`
	ContentURL           string    `json:"content_url"`
	SHA256               string    `json:"sha256"`
	FileSizeBytes        int64     `json:"file_size_bytes"`
	CommandLine          string    `json:"command_line"`
	TimeoutMinutes       int       `json:"timeout_minutes"`
	RetryCount           int       `json:"retry_count"`
	RetryIntervalMinutes int       `json:"retry_interval_minutes"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	GroupCount           int       `json:"group_count"`
	InstalledCount       int       `json:"installed_count"`
	TargetDeviceCount    int       `json:"target_device_count"`
}

// DeviceAppInstall tracks the deployment state of an MSI package on a device.
type DeviceAppInstall struct {
	DeviceID      string    `json:"device_id"`
	DeviceName    string    `json:"device_name"`
	AppID         string    `json:"app_id"`
	AppName       string    `json:"app_name"`
	Publisher     string    `json:"publisher"`
	Version       string    `json:"version"`
	ProductCode   string    `json:"product_code"`
	DesiredAction string    `json:"desired_action"`
	StatusCode    *int64    `json:"status_code"`
	StatusLabel   string    `json:"status_label"`
	LastError     string    `json:"last_error"`
	LastErrorDesc string    `json:"last_error_desc"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// HandleInspectMSI downloads an HTTPS .msi package, computes its SHA-256 hash,
// and extracts MSI Property table metadata (ProductCode, Name, Version, Publisher).
// POST /api/apps/inspect
func (h *Handler) HandleInspectMSI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ContentURL string `json:"content_url"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	body.ContentURL = strings.TrimSpace(body.ContentURL)
	if err := msi.ValidateContentURL(body.ContentURL); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
	meta, err := msiInspectURL(r.Context(), body.ContentURL)
	if err != nil {
		slog.Warn("api: MSI inspection failed", "url", body.ContentURL, "err", err)
		respondErr(w, http.StatusBadGateway, "MSI inspection failed: "+err.Error())
		return
	}
	respondOK(w, meta)
}

// HandleListApps returns all registered MSI applications and deployment counts.
// GET /api/apps
func (h *Handler) HandleListApps(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT a.id, a.name, a.publisher, a.version, a.product_code, a.upgrade_code,
		       a.content_url, a.sha256, a.file_size_bytes, a.command_line,
		       a.timeout_minutes, a.retry_count, a.retry_interval_minutes,
		       a.created_at, a.updated_at,
		       (SELECT COUNT(*) FROM group_apps ga WHERE ga.app_id = a.id) AS group_count,
		       (SELECT COUNT(*) FROM device_app_installs dai
		          JOIN devices d ON d.id = dai.device_id
		         WHERE dai.app_id = a.id AND d.is_active = 1 AND dai.status_code = 70) AS installed_count,
		       (SELECT COUNT(*) FROM device_app_installs dai
		          JOIN devices d ON d.id = dai.device_id
		         WHERE dai.app_id = a.id AND d.is_active = 1 AND dai.desired_action = 'install') AS target_device_count
		FROM msi_apps a
		ORDER BY a.created_at DESC
	`))
	if err != nil {
		slog.Error("api: listing MSI apps", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list applications")
		return
	}
	defer rows.Close()

	var apps []MSIApp
	for rows.Next() {
		var a MSIApp
		if err := rows.Scan(
			&a.ID, &a.Name, &a.Publisher, &a.Version, &a.ProductCode, &a.UpgradeCode,
			&a.ContentURL, &a.SHA256, &a.FileSizeBytes, &a.CommandLine,
			&a.TimeoutMinutes, &a.RetryCount, &a.RetryIntervalMinutes,
			&a.CreatedAt, &a.UpdatedAt,
			&a.GroupCount, &a.InstalledCount, &a.TargetDeviceCount,
		); err != nil {
			slog.Error("api: scanning MSI app row", "err", err)
			continue
		}
		apps = append(apps, a)
	}
	if apps == nil {
		apps = []MSIApp{}
	}
	respondOK(w, apps)
}

// HandleCreateApp registers a new MSI application (auto-inspecting the remote
// MSI URL if product_code or sha256 are omitted).
// POST /api/apps
func (h *Handler) HandleCreateApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name                 string `json:"name"`
		Publisher            string `json:"publisher"`
		Version              string `json:"version"`
		ProductCode          string `json:"product_code"`
		UpgradeCode          string `json:"upgrade_code"`
		ContentURL           string `json:"content_url"`
		SHA256               string `json:"sha256"`
		FileSizeBytes        int64  `json:"file_size_bytes"`
		CommandLine          string `json:"command_line"`
		TimeoutMinutes       int    `json:"timeout_minutes"`
		RetryCount           *int   `json:"retry_count"`
		RetryIntervalMinutes int    `json:"retry_interval_minutes"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	body.ContentURL = strings.TrimSpace(body.ContentURL)
	if err := msi.ValidateContentURL(body.ContentURL); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Auto-inspect remote MSI if critical cryptographic/identity metadata is omitted
	if strings.TrimSpace(body.ProductCode) == "" || strings.TrimSpace(body.SHA256) == "" || strings.TrimSpace(body.Name) == "" {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
		meta, err := msiInspectURL(r.Context(), body.ContentURL)
		if err != nil {
			respondErr(w, http.StatusBadGateway, "failed to auto-inspect MSI URL: "+err.Error())
			return
		}
		if strings.TrimSpace(body.ProductCode) == "" {
			body.ProductCode = meta.ProductCode
		}
		if strings.TrimSpace(body.SHA256) == "" {
			body.SHA256 = meta.SHA256
		}
		if strings.TrimSpace(body.Name) == "" {
			body.Name = meta.ProductName
		}
		if strings.TrimSpace(body.Publisher) == "" {
			body.Publisher = meta.Manufacturer
		}
		if strings.TrimSpace(body.Version) == "" {
			body.Version = meta.ProductVersion
		}
		if strings.TrimSpace(body.UpgradeCode) == "" {
			body.UpgradeCode = meta.UpgradeCode
		}
		if body.FileSizeBytes <= 0 {
			body.FileSizeBytes = meta.FileSizeBytes
		}
	}

	prodCode, err := msi.NormalizeProductCode(body.ProductCode)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	shaHex, err := msi.NormalizeSHA256(body.SHA256)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		respondErr(w, http.StatusBadRequest, "name is required")
		return
	}
	version := strings.TrimSpace(body.Version)
	if version == "" {
		version = "1.0.0"
	}
	cmdLine := strings.TrimSpace(body.CommandLine)
	if cmdLine == "" {
		cmdLine = "/quiet /norestart"
	}
	timeout := body.TimeoutMinutes
	if timeout <= 0 {
		timeout = 15
	}
	retryCount := 3
	if body.RetryCount != nil && *body.RetryCount >= 0 {
		retryCount = *body.RetryCount
	}
	retryInterval := body.RetryIntervalMinutes
	if retryInterval <= 0 {
		retryInterval = 5
	}

	var existing int
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM msi_apps WHERE product_code = ?`), prodCode,
	).Scan(&existing); err == nil && existing > 0 {
		respondErr(w, http.StatusConflict, "an application with this MSI ProductCode is already registered")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO msi_apps (
			id, name, publisher, version, product_code, upgrade_code,
			content_url, sha256, file_size_bytes, command_line,
			timeout_minutes, retry_count, retry_interval_minutes,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`),
		id, name, strings.TrimSpace(body.Publisher), version, prodCode, strings.TrimSpace(body.UpgradeCode),
		body.ContentURL, shaHex, body.FileSizeBytes, cmdLine,
		timeout, retryCount, retryInterval, now, now,
	)
	if err != nil {
		slog.Error("api: creating MSI app", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create application")
		return
	}

	actor := emailFromCtx(r)
	h.audit(r, actor, "app.create", "app", id, fmt.Sprintf(`{"name":%q,"product_code":%q,"version":%q}`, name, prodCode, version))
	slog.Info("MSI app registered", "app_id", id, "name", name, "product_code", prodCode, "actor", actor)

	respondCreated(w, MSIApp{
		ID:                   id,
		Name:                 name,
		Publisher:            strings.TrimSpace(body.Publisher),
		Version:              version,
		ProductCode:          prodCode,
		UpgradeCode:          strings.TrimSpace(body.UpgradeCode),
		ContentURL:           body.ContentURL,
		SHA256:               shaHex,
		FileSizeBytes:        body.FileSizeBytes,
		CommandLine:          cmdLine,
		TimeoutMinutes:       timeout,
		RetryCount:           retryCount,
		RetryIntervalMinutes: retryInterval,
		CreatedAt:            now,
		UpdatedAt:            now,
	})
}

// HandleGetApp returns an MSI application along with assigned groups and per-device deployment status.
// GET /api/apps/{id}
func (h *Handler) HandleGetApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := h.loadMSIApp(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "application not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load application")
		return
	}

	groupIDs := []string{}
	if gRows, err := h.db.QueryContext(r.Context(),
		dbpkg.Rebind(`SELECT group_id FROM group_apps WHERE app_id = ? ORDER BY assigned_at ASC`), id,
	); err == nil {
		defer gRows.Close()
		for gRows.Next() {
			var gid string
			if gRows.Scan(&gid) == nil {
				groupIDs = append(groupIDs, gid)
			}
		}
	}

	installs := []DeviceAppInstall{}
	if iRows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT dai.device_id, COALESCE(d.device_name, ''), dai.app_id,
		       a.name, a.publisher, a.version, dai.product_code,
		       dai.desired_action, dai.status_code, dai.status_label,
		       dai.last_error, dai.last_error_desc, dai.updated_at
		FROM device_app_installs dai
		JOIN msi_apps a ON a.id = dai.app_id
		JOIN devices d ON d.id = dai.device_id
		WHERE dai.app_id = ? AND d.is_active = 1
		ORDER BY dai.updated_at DESC
	`), id); err == nil {
		defer iRows.Close()
		for iRows.Next() {
			var inst DeviceAppInstall
			var sc sql.NullInt64
			if err := iRows.Scan(
				&inst.DeviceID, &inst.DeviceName, &inst.AppID,
				&inst.AppName, &inst.Publisher, &inst.Version, &inst.ProductCode,
				&inst.DesiredAction, &sc, &inst.StatusLabel,
				&inst.LastError, &inst.LastErrorDesc, &inst.UpdatedAt,
			); err == nil {
				if sc.Valid {
					v := sc.Int64
					inst.StatusCode = &v
				}
				installs = append(installs, inst)
			}
		}
	}

	respondOK(w, map[string]interface{}{
		"app":       app,
		"group_ids": groupIDs,
		"installs":  installs,
	})
}

// HandleDeleteApp removes an MSI application from the catalog.
// DELETE /api/apps/{id}
func (h *Handler) HandleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM msi_apps WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete application")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "application not found")
		return
	}

	h.audit(r, actor, "app.delete", "app", id, "")
	respondOK(w, map[string]string{"status": "deleted"})
}

// HandleAssignAppGroups assigns or removes an MSI application from device groups
// and queues install/uninstall commands for member devices.
// PUT /api/apps/{id}/groups
func (h *Handler) HandleAssignAppGroups(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := h.loadMSIApp(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "application not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load application")
		return
	}

	var body struct {
		GroupIDs []string `json:"group_ids"`
		Action   string   `json:"action"` // "add" or "remove"
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Action != "add" && body.Action != "remove" {
		respondErr(w, http.StatusBadRequest, "action must be 'add' or 'remove'")
		return
	}

	seen := make(map[string]bool)
	var affectedDevices []string

	for _, gid := range body.GroupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" {
			continue
		}
		members := h.queryDeviceIDs(r, `
			SELECT dgm.device_id
			FROM device_group_members dgm
			JOIN devices d ON d.id = dgm.device_id
			WHERE dgm.group_id = ? AND d.is_active = 1
		`, gid)
		for _, devID := range members {
			if !seen[devID] {
				seen[devID] = true
				affectedDevices = append(affectedDevices, devID)
			}
		}

		if body.Action == "add" {
			_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
				INSERT INTO group_apps (group_id, app_id) VALUES (?, ?)
				ON CONFLICT (group_id, app_id) DO NOTHING
			`), gid, app.ID)
		} else {
			_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
				DELETE FROM group_apps WHERE group_id = ? AND app_id = ?
			`), gid, app.ID)
		}
	}

	var targeted int
	if body.Action == "add" {
		for _, devID := range affectedDevices {
			if _, err := h.deployMSIAppToDevice(r.Context(), app, devID); err == nil {
				targeted++
			}
		}
	} else {
		for _, devID := range affectedDevices {
			var remaining int
			_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
				SELECT COUNT(*)
				FROM group_apps ga
				JOIN device_group_members dgm ON dgm.group_id = ga.group_id
				WHERE ga.app_id = ? AND dgm.device_id = ?
			`), app.ID, devID).Scan(&remaining)
			if remaining == 0 {
				if err := h.uninstallMSIAppFromDevice(r.Context(), app, devID); err == nil {
					targeted++
				}
			}
		}
	}

	actor := emailFromCtx(r)
	h.audit(r, actor, "app.assign_groups", "app", app.ID,
		fmt.Sprintf(`{"action":%q,"groups":%d,"devices_targeted":%d}`, body.Action, len(body.GroupIDs), targeted))
	respondOK(w, map[string]interface{}{
		"status":           "ok",
		"devices_targeted": targeted,
	})
}

// HandleInstallAppOnDevices queues an MSI deployment directly onto specified devices.
// POST /api/apps/{id}/install
func (h *Handler) HandleInstallAppOnDevices(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := h.loadMSIApp(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "application not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load application")
		return
	}

	var body struct {
		DeviceIDs []string `json:"device_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.DeviceIDs) == 0 {
		respondErr(w, http.StatusBadRequest, "device_ids is required")
		return
	}

	var targeted, totalCmds int
	for _, devID := range body.DeviceIDs {
		devID = strings.TrimSpace(devID)
		if devID == "" {
			continue
		}
		if _, derr := h.getDevice(r, devID); derr != nil {
			continue
		}
		queued, qerr := h.deployMSIAppToDevice(r.Context(), app, devID)
		if qerr != nil {
			slog.Error("api: deploying MSI app to device", "app_id", app.ID, "device_id", devID, "err", qerr)
			continue
		}
		targeted++
		totalCmds += queued
	}

	actor := emailFromCtx(r)
	h.audit(r, actor, "app.install", "app", app.ID,
		fmt.Sprintf(`{"devices_targeted":%d,"commands_queued":%d}`, targeted, totalCmds))
	respondOK(w, map[string]interface{}{
		"status":           "queued",
		"devices_targeted": targeted,
		"commands_queued":  totalCmds,
	})
}

// HandleUninstallAppOnDevices queues an EnterpriseDesktopAppManagement <Delete>
// command on specified devices for the given MSI application.
// POST /api/apps/{id}/uninstall
func (h *Handler) HandleUninstallAppOnDevices(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := h.loadMSIApp(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "application not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load application")
		return
	}

	var body struct {
		DeviceIDs []string `json:"device_ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.DeviceIDs) == 0 {
		respondErr(w, http.StatusBadRequest, "device_ids is required")
		return
	}

	var targeted int
	for _, devID := range body.DeviceIDs {
		devID = strings.TrimSpace(devID)
		if devID == "" {
			continue
		}
		if _, derr := h.getDevice(r, devID); derr != nil {
			continue
		}
		if err := h.uninstallMSIAppFromDevice(r.Context(), app, devID); err != nil {
			slog.Error("api: uninstalling MSI app from device", "app_id", app.ID, "device_id", devID, "err", err)
			continue
		}
		targeted++
	}

	actor := emailFromCtx(r)
	h.audit(r, actor, "app.uninstall", "app", app.ID, fmt.Sprintf(`{"devices_targeted":%d}`, targeted))
	respondOK(w, map[string]interface{}{
		"status":           "queued",
		"devices_targeted": targeted,
	})
}

// HandleGetDeviceApps returns all MSI deployments tracked for a single device.
// GET /api/devices/{id}/apps
func (h *Handler) HandleGetDeviceApps(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT dai.device_id, COALESCE(d.device_name, ''), dai.app_id,
		       a.name, a.publisher, a.version, dai.product_code,
		       dai.desired_action, dai.status_code, dai.status_label,
		       dai.last_error, dai.last_error_desc, dai.updated_at
		FROM device_app_installs dai
		JOIN msi_apps a ON a.id = dai.app_id
		JOIN devices d ON d.id = dai.device_id
		WHERE dai.device_id = ?
		ORDER BY a.name ASC
	`), id)
	if err != nil {
		slog.Error("api: listing device apps", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load device applications")
		return
	}
	defer rows.Close()

	installs := []DeviceAppInstall{}
	for rows.Next() {
		var inst DeviceAppInstall
		var sc sql.NullInt64
		if err := rows.Scan(
			&inst.DeviceID, &inst.DeviceName, &inst.AppID,
			&inst.AppName, &inst.Publisher, &inst.Version, &inst.ProductCode,
			&inst.DesiredAction, &sc, &inst.StatusLabel,
			&inst.LastError, &inst.LastErrorDesc, &inst.UpdatedAt,
		); err == nil {
			if sc.Valid {
				v := sc.Int64
				inst.StatusCode = &v
			}
			installs = append(installs, inst)
		}
	}
	respondOK(w, installs)
}

func (h *Handler) loadMSIApp(ctx context.Context, id string) (*MSIApp, error) {
	var a MSIApp
	err := h.db.QueryRowContext(ctx, dbpkg.Rebind(`
		SELECT a.id, a.name, a.publisher, a.version, a.product_code, a.upgrade_code,
		       a.content_url, a.sha256, a.file_size_bytes, a.command_line,
		       a.timeout_minutes, a.retry_count, a.retry_interval_minutes,
		       a.created_at, a.updated_at,
		       (SELECT COUNT(*) FROM group_apps ga WHERE ga.app_id = a.id),
		       (SELECT COUNT(*) FROM device_app_installs dai
		          JOIN devices d ON d.id = dai.device_id
		         WHERE dai.app_id = a.id AND d.is_active = 1 AND dai.status_code = 70),
		       (SELECT COUNT(*) FROM device_app_installs dai
		          JOIN devices d ON d.id = dai.device_id
		         WHERE dai.app_id = a.id AND d.is_active = 1 AND dai.desired_action = 'install')
		FROM msi_apps a
		WHERE a.id = ?
	`), id).Scan(
		&a.ID, &a.Name, &a.Publisher, &a.Version, &a.ProductCode, &a.UpgradeCode,
		&a.ContentURL, &a.SHA256, &a.FileSizeBytes, &a.CommandLine,
		&a.TimeoutMinutes, &a.RetryCount, &a.RetryIntervalMinutes,
		&a.CreatedAt, &a.UpdatedAt,
		&a.GroupCount, &a.InstalledCount, &a.TargetDeviceCount,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (h *Handler) deployMSIAppToDevice(ctx context.Context, app *MSIApp, deviceID string) (int, error) {
	_, err := h.db.ExecContext(ctx, dbpkg.Rebind(`
		INSERT INTO device_app_installs (
			device_id, app_id, product_code, desired_action,
			status_code, status_label, last_error, last_error_desc, updated_at
		) VALUES (?, ?, ?, 'install', NULL, 'Queued', '', '', CURRENT_TIMESTAMP)
		ON CONFLICT (device_id, app_id) DO UPDATE SET
			product_code    = EXCLUDED.product_code,
			desired_action  = 'install',
			status_code     = NULL,
			status_label    = 'Queued',
			last_error      = '',
			last_error_desc = '',
			updated_at      = CURRENT_TIMESTAMP
	`), deviceID, app.ID, app.ProductCode)
	if err != nil {
		return 0, err
	}

	var contentURLs []string
	if relayURL := h.SignedAppContentURL(app.ID, time.Now().UTC().Add(7*24*time.Hour)); relayURL != "" {
		contentURLs = []string{relayURL, app.ContentURL}
	}

	queued, err := mdm.EnqueueMSIInstall(h.db, deviceID, mdm.MSIInstallSpec{
		ProductCode:          app.ProductCode,
		Version:              app.Version,
		ContentURL:           app.ContentURL,
		ContentURLs:          contentURLs,
		SHA256:               app.SHA256,
		CommandLine:          app.CommandLine,
		TimeoutMinutes:       app.TimeoutMinutes,
		RetryCount:           app.RetryCount,
		RetryIntervalMinutes: app.RetryIntervalMinutes,
	})
	if err != nil {
		return 0, err
	}
	h.wakeDevice(deviceID)
	return queued, nil
}

func (h *Handler) computeContentSignature(appID, expStr string) string {
	mac := hmac.New(sha256.New, h.contentSecret)
	mac.Write([]byte("latchz-msi-content-v1:"))
	mac.Write([]byte(appID))
	mac.Write([]byte(":"))
	mac.Write([]byte(expStr))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignedAppContentURL generates a time-limited, HMAC-signed HTTPS relay URL
// ending in /package.msi for Windows Delivery Optimization (DoSvc) downloads.
func (h *Handler) SignedAppContentURL(appID string, expiresAt time.Time) string {
	if h.contentBaseURL == "" || len(h.contentSecret) == 0 || strings.TrimSpace(appID) == "" {
		return ""
	}
	expStr := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	sig := h.computeContentSignature(appID, expStr)
	return fmt.Sprintf("%s/mdm/apps/%s/%s/%s/package.msi",
		h.contentBaseURL, url.PathEscape(appID), expStr, sig)
}

// HandleServeAppContent streams uncompressed MSI bytes (supporting HEAD and
// HTTP 206 Range requests) to Windows Delivery Optimization while stripping
// Accept-Encoding on the upstream CDN request so providers like dl.google.com
// never return Content-Encoding: gzip on partial byte-range slices.
// GET|HEAD /mdm/apps/{id}/{exp}/{sig}/package.msi
func (h *Handler) HandleServeAppContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(h.contentSecret) == 0 {
		http.Error(w, "content relay not configured", http.StatusServiceUnavailable)
		return
	}

	appID := strings.TrimSpace(chi.URLParam(r, "id"))
	expStr := strings.TrimSpace(chi.URLParam(r, "exp"))
	sigHex := strings.TrimSpace(chi.URLParam(r, "sig"))
	if appID == "" || expStr == "" || sigHex == "" {
		http.Error(w, "invalid content token", http.StatusForbidden)
		return
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid expiry", http.StatusForbidden)
		return
	}
	nowUnix := time.Now().UTC().Unix()
	if expUnix < nowUnix || expUnix > nowUnix+int64((31*24*time.Hour).Seconds()) {
		http.Error(w, "content token expired", http.StatusForbidden)
		return
	}

	expectedSig := h.computeContentSignature(appID, expStr)
	gotBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}
	expBytes, _ := hex.DecodeString(expectedSig)
	if !hmac.Equal(gotBytes, expBytes) {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}

	var contentURL string
	var fileSizeBytes int64
	err = h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT content_url, file_size_bytes FROM msi_apps WHERE id = ?`), appID,
	).Scan(&contentURL, &fileSizeBytes)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("api: querying MSI content_url for relay", "app_id", appID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := msi.ValidateContentURL(contentURL); err != nil {
		http.Error(w, "invalid upstream content URL", http.StatusBadGateway)
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, contentURL, nil)
	if err != nil {
		http.Error(w, "failed building upstream request", http.StatusBadGateway)
		return
	}
	if rng := strings.TrimSpace(r.Header.Get("Range")); rng != "" {
		upReq.Header.Set("Range", rng)
	}
	if ifRng := strings.TrimSpace(r.Header.Get("If-Range")); ifRng != "" {
		upReq.Header.Set("If-Range", ifRng)
	}
	upReq.Header.Del("Accept-Encoding")

	client := h.contentClient
	if client == nil {
		client = msi.NewIdentityHTTPClient(0)
	}
	resp, err := client.Do(upReq)
	if err != nil {
		slog.Warn("api: upstream MSI content relay failed", "app_id", appID, "err", err)
		http.Error(w, "upstream download failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		http.Error(w, "upstream server error", http.StatusBadGateway)
		return
	}

	for _, hdr := range []string{"Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"} {
		if val := resp.Header.Get(hdr); val != "" {
			w.Header().Set(hdr, val)
		}
	}
	if resp.StatusCode == http.StatusOK && w.Header().Get("Content-Length") == "" && fileSizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSizeBytes, 10))
	}
	if w.Header().Get("Accept-Ranges") == "" {
		w.Header().Set("Accept-Ranges", "bytes")
	}
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Cache-Control", "no-transform, private, max-age=3600")

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Minute))
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, resp.Body)
	}
}

func (h *Handler) uninstallMSIAppFromDevice(ctx context.Context, app *MSIApp, deviceID string) error {
	_, err := h.db.ExecContext(ctx, dbpkg.Rebind(`
		INSERT INTO device_app_installs (
			device_id, app_id, product_code, desired_action,
			status_code, status_label, last_error, last_error_desc, updated_at
		) VALUES (?, ?, ?, 'uninstall', NULL, 'Uninstalling', '', '', CURRENT_TIMESTAMP)
		ON CONFLICT (device_id, app_id) DO UPDATE SET
			product_code    = EXCLUDED.product_code,
			desired_action  = 'uninstall',
			status_code     = NULL,
			status_label    = 'Uninstalling',
			last_error      = '',
			last_error_desc = '',
			updated_at      = CURRENT_TIMESTAMP
	`), deviceID, app.ID, app.ProductCode)
	if err != nil {
		return err
	}
	if _, err := mdm.EnqueueMSIUninstall(h.db, deviceID, app.ProductCode); err != nil {
		return err
	}
	h.wakeDevice(deviceID)
	return nil
}
