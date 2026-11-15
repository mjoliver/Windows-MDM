package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

// SoftwareInventoryItem represents a single Win32 or MSI program discovered on a device.
type SoftwareInventoryItem struct {
	AppKey          string    `json:"app_key"`
	Name            string    `json:"name"`
	Publisher       string    `json:"publisher"`
	Version         string    `json:"version"`
	Source          string    `json:"source"`
	ProductCode     string    `json:"product_code"`
	UpgradeCode     string    `json:"upgrade_code"`
	InstallDate     string    `json:"install_date"`
	InstallLocation string    `json:"install_location"`
	ManagedAppID    string    `json:"managed_app_id,omitempty"`
	CatalogVersion  string    `json:"catalog_version,omitempty"`
	VersionState    string    `json:"version_state,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// DeviceSoftwareInventoryResponse is returned by GET /api/devices/{id}/inventory.
type DeviceSoftwareInventoryResponse struct {
	DeviceID     string                  `json:"device_id"`
	Total        int                     `json:"total"`
	LastSyncedAt *time.Time              `json:"last_synced_at"`
	Items        []SoftwareInventoryItem `json:"items"`
}

// ComputeAppVersionState compares a device's live installed version against the
// catalog package version ("up_to_date", "auto_updated", "update_available", or "unknown").
func ComputeAppVersionState(installedVersion, catalogVersion string) string {
	iv := strings.TrimSpace(installedVersion)
	cv := strings.TrimSpace(catalogVersion)
	if iv == "" || cv == "" {
		return "unknown"
	}
	cmp := mdm.CompareAppVersions(iv, cv)
	switch {
	case cmp > 0:
		return "auto_updated"
	case cmp < 0:
		return "update_available"
	default:
		return "up_to_date"
	}
}

// HandleGetDeviceInventory returns all discovered Win32 and MSI applications on a device.
// GET /api/devices/{id}/inventory?q=...
func (h *Handler) HandleGetDeviceInventory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Load catalog apps so managed items can be cross-referenced with catalog versions
	type catEntry struct {
		id, name, publisher, version, productCode, upgradeCode string
	}
	var catApps []catEntry
	if cRows, err := h.db.QueryContext(r.Context(), `SELECT id, name, publisher, version, product_code, upgrade_code FROM msi_apps`); err == nil {
		for cRows.Next() {
			var c catEntry
			if cRows.Scan(&c.id, &c.name, &c.publisher, &c.version, &c.productCode, &c.upgradeCode) == nil {
				catApps = append(catApps, c)
			}
		}
		cRows.Close()
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT app_key, name, publisher, version, source, product_code, upgrade_code,
		       install_date, install_location, updated_at
		FROM device_software_inventory
		WHERE device_id = ?
		ORDER BY LOWER(name) ASC, version DESC
	`), id)
	if err != nil {
		slog.Error("api: listing device software inventory", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load software inventory")
		return
	}
	defer rows.Close()

	var total int
	var latest *time.Time
	items := []SoftwareInventoryItem{}

	for rows.Next() {
		var it SoftwareInventoryItem
		if err := rows.Scan(
			&it.AppKey, &it.Name, &it.Publisher, &it.Version, &it.Source,
			&it.ProductCode, &it.UpgradeCode, &it.InstallDate, &it.InstallLocation, &it.UpdatedAt,
		); err != nil {
			continue
		}
		total++
		if latest == nil || it.UpdatedAt.After(*latest) {
			t := it.UpdatedAt
			latest = &t
		}

		// Cross-link if this program corresponds to a managed catalog MSI app
		singleSlice := []mdm.InventoryRecord{{
			AppKey:      it.AppKey,
			Name:        it.Name,
			Publisher:   it.Publisher,
			Version:     it.Version,
			Source:      it.Source,
			ProductCode: it.ProductCode,
			UpgradeCode: it.UpgradeCode,
		}}
		for _, c := range catApps {
			if mdm.MatchCatalogAppToInventory(c.name, c.publisher, c.productCode, c.upgradeCode, singleSlice) != nil {
				it.ManagedAppID = c.id
				it.CatalogVersion = c.version
				it.VersionState = ComputeAppVersionState(it.Version, c.version)
				break
			}
		}

		if q != "" {
			hay := strings.ToLower(it.Name + " " + it.Publisher + " " + it.Version + " " + it.ProductCode + " " + it.Source)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		items = append(items, it)
	}

	respondOK(w, DeviceSoftwareInventoryResponse{
		DeviceID:     id,
		Total:        total,
		LastSyncedAt: latest,
		Items:        items,
	})
}

// HandleSyncDeviceInventory queues immediate OMA-DM StructData software inventory
// queries on the device and triggers a WNS push wake-up.
// POST /api/devices/{id}/inventory/sync
func (h *Handler) HandleSyncDeviceInventory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	queued, err := mdm.EnqueueSoftwareInventorySync(h.db, id)
	if err != nil {
		slog.Error("api: queueing software inventory sync", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue software inventory sync")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.inventory_sync", "device", id, fmt.Sprintf(`{"commands_queued":%d}`, queued))
	respondOK(w, map[string]interface{}{
		"status":          "queued",
		"commands_queued": queued,
	})
}

// reconcileFleetInventoryVersions updates installed_version across all active devices
// that have already reported software inventory (e.g. after registering or refreshing
// a catalog MSI app).
func (h *Handler) reconcileFleetInventoryVersions(ctx context.Context) {
	rows, err := h.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM device_software_inventory`)
	if err != nil {
		return
	}
	var devIDs []string
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil && d != "" {
			devIDs = append(devIDs, d)
		}
	}
	rows.Close()
	for _, d := range devIDs {
		mdm.ReconcileDeviceAppVersions(h.db, d)
	}
}

func (h *Handler) populateAppVersionCounts(ctx context.Context, apps []MSIApp) {
	if len(apps) == 0 {
		return
	}
	idxByID := make(map[string]int, len(apps))
	for i := range apps {
		idxByID[apps[i].ID] = i
	}
	rows, err := h.db.QueryContext(ctx, `
		SELECT dai.app_id, COALESCE(dai.installed_version, ''), a.version
		FROM device_app_installs dai
		JOIN msi_apps a ON a.id = dai.app_id
		JOIN devices d ON d.id = dai.device_id
		WHERE d.is_active = 1 AND dai.desired_action = 'install' AND COALESCE(dai.installed_version, '') <> ''
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var appID, instVer, catVer string
		if rows.Scan(&appID, &instVer, &catVer) != nil {
			continue
		}
		i, ok := idxByID[appID]
		if !ok {
			continue
		}
		switch ComputeAppVersionState(instVer, catVer) {
		case "auto_updated":
			apps[i].AutoUpdatedCount++
		case "update_available":
			apps[i].OutdatedCount++
		}
	}
}
