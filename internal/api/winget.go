package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/msi"
	"github.com/latchzmdm/latchz/internal/winget"
)

// SetWinGetClient overrides the WinGet catalog client (used by unit tests).
func (h *Handler) SetWinGetClient(c *winget.Client) {
	if c != nil {
		h.winget = c
	}
}

// HandleSearchWinGet searches curated MSI-capable WinGet packages and public WinGet IDs.
// GET /api/apps/winget/search?q=...
func (h *Handler) HandleSearchWinGet(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	results, err := h.winget.Search(r.Context(), q)
	if err != nil {
		respondErr(w, http.StatusBadGateway, "WinGet search failed: "+err.Error())
		return
	}
	if results == nil {
		results = []winget.SearchResult{}
	}
	respondOK(w, results)
}

// HandleResolveWinGet resolves the latest native MSI/WiX manifest for a WinGet package_id.
// GET /api/apps/winget/resolve?package_id=7zip.7zip&arch=x64
func (h *Handler) HandleResolveWinGet(w http.ResponseWriter, r *http.Request) {
	pkgID := strings.TrimSpace(r.URL.Query().Get("package_id"))
	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if err := winget.ValidatePackageID(pkgID); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resolved, err := h.winget.ResolveMSI(r.Context(), pkgID, arch)
	if err != nil {
		respondErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	respondOK(w, resolved)
}

// HandleImportWinGetApp resolves a WinGet package's native MSI/WiX installer,
// verifies its HTTPS URL, ProductCode, and SHA-256 hash, and registers it in msi_apps.
// POST /api/apps/winget/import
func (h *Handler) HandleImportWinGetApp(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		PackageID    string `json:"package_id"`
		Architecture string `json:"architecture"`
		CommandLine  string `json:"command_line"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if err := winget.ValidatePackageID(body.PackageID); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
	resolved, err := h.winget.ResolveMSI(r.Context(), body.PackageID, body.Architecture)
	if err != nil {
		respondErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := msi.ValidateContentURL(resolved.InstallerURL); err != nil {
		respondErr(w, http.StatusBadRequest, "WinGet installer URL failed validation: "+err.Error())
		return
	}

	var fileSize int64
	prodCodeRaw := strings.TrimSpace(resolved.ProductCode)
	shaRaw := strings.TrimSpace(resolved.SHA256)
	upgCode := strings.TrimSpace(resolved.UpgradeCode)
	name := strings.TrimSpace(resolved.Name)
	pub := strings.TrimSpace(resolved.Publisher)
	ver := strings.TrimSpace(resolved.Version)

	if prodCodeRaw == "" || shaRaw == "" {
		meta, err := msiInspectURL(r.Context(), resolved.InstallerURL)
		if err != nil {
			respondErr(w, http.StatusBadGateway, "failed to inspect WinGet MSI binary: "+err.Error())
			return
		}
		if prodCodeRaw == "" {
			prodCodeRaw = meta.ProductCode
		}
		if shaRaw == "" {
			shaRaw = meta.SHA256
		}
		if upgCode == "" {
			upgCode = meta.UpgradeCode
		}
		if name == "" {
			name = meta.ProductName
		}
		if pub == "" {
			pub = meta.Manufacturer
		}
		if ver == "" {
			ver = meta.ProductVersion
		}
		fileSize = meta.FileSizeBytes
	} else {
		// Fast HEAD probe to populate Content-Length without re-downloading large MSIs
		fileSize = h.probeRemoteContentLength(r.Context(), resolved.InstallerURL)
	}

	prodCode, err := msi.NormalizeProductCode(prodCodeRaw)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid WinGet MSI ProductCode: "+err.Error())
		return
	}
	shaHex, err := msi.NormalizeSHA256(shaRaw)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid WinGet MSI SHA-256: "+err.Error())
		return
	}
	if name == "" {
		name = resolved.PackageID
	}
	if ver == "" {
		ver = "1.0.0"
	}
	cmdLine := strings.TrimSpace(body.CommandLine)
	if cmdLine == "" {
		cmdLine = "/quiet /norestart"
	}

	var existing int
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM msi_apps WHERE product_code = ?`), prodCode,
	).Scan(&existing); err == nil && existing > 0 {
		respondErr(w, http.StatusConflict, fmt.Sprintf("%s (%s, %s) is already registered in the catalog", name, ver, prodCode))
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO msi_apps (
			id, name, publisher, version, product_code, upgrade_code,
			content_url, sha256, file_size_bytes, command_line,
			timeout_minutes, retry_count, retry_interval_minutes,
			winget_package_id, winget_arch,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 15, 3, 5, ?, ?, ?, ?)
	`),
		id, name, pub, ver, prodCode, upgCode,
		resolved.InstallerURL, shaHex, fileSize, cmdLine,
		resolved.PackageID, resolved.Architecture,
		now, now,
	)
	if err != nil {
		slog.Error("api: importing WinGet MSI app", "package_id", resolved.PackageID, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save imported WinGet application")
		return
	}

	h.reconcileFleetInventoryVersions(r.Context())
	h.audit(r, actor, "app.winget_import", "app", id,
		fmt.Sprintf(`{"package_id":%q,"name":%q,"version":%q,"product_code":%q}`, resolved.PackageID, name, ver, prodCode))
	slog.Info("WinGet MSI app imported", "app_id", id, "package_id", resolved.PackageID, "version", ver, "actor", actor)

	if loaded, lerr := h.loadMSIApp(r.Context(), id); lerr == nil {
		respondCreated(w, loaded)
		return
	}
	respondCreated(w, MSIApp{
		ID:                   id,
		Name:                 name,
		Publisher:            pub,
		Version:              ver,
		ProductCode:          prodCode,
		UpgradeCode:          upgCode,
		ContentURL:           resolved.InstallerURL,
		SourceType:           "url",
		SHA256:               shaHex,
		FileSizeBytes:        fileSize,
		CommandLine:          cmdLine,
		TimeoutMinutes:       15,
		RetryCount:           3,
		RetryIntervalMinutes: 5,
		WinGetPackageID:      resolved.PackageID,
		WinGetArch:           resolved.Architecture,
		CreatedAt:            now,
		UpdatedAt:            now,
	})
}

// HandleRefreshWinGetApp checks Microsoft's WinGet repository for a newer MSI
// release of an existing catalog application and updates the seed installer
// metadata (version, ProductCode, SHA-256, ContentURL) when a newer release exists.
// POST /api/apps/{id}/winget-refresh
func (h *Handler) HandleRefreshWinGetApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

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
		PackageID string `json:"package_id"`
	}
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		if derr := dec.Decode(&body); derr != nil && !errors.Is(derr, io.EOF) {
			respondErr(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
	}

	pkgID := strings.TrimSpace(body.PackageID)
	if pkgID == "" {
		pkgID = strings.TrimSpace(app.WinGetPackageID)
	}
	if app.SourceType == "upload" && pkgID == "" {
		respondErr(w, http.StatusBadRequest, "locally uploaded MSI packages cannot be refreshed from WinGet without a package_id")
		return
	}
	if pkgID == "" {
		pkgID = h.inferWinGetPackageID(r.Context(), app.Name, app.Publisher)
	}
	if pkgID == "" {
		respondErr(w, http.StatusUnprocessableEntity, "could not match application to a WinGet MSI package_id")
		return
	}
	if err := winget.ValidatePackageID(pkgID); err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
	resolved, err := h.winget.ResolveMSI(r.Context(), pkgID, app.WinGetArch)
	if err != nil {
		respondErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	ver := strings.TrimSpace(resolved.Version)
	if mdm.CompareAppVersions(ver, app.Version) <= 0 {
		if app.WinGetPackageID == "" {
			_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
				UPDATE msi_apps SET winget_package_id = ?, winget_arch = ? WHERE id = ?
			`), resolved.PackageID, resolved.Architecture, app.ID)
			if refreshed, lerr := h.loadMSIApp(r.Context(), app.ID); lerr == nil {
				app = refreshed
			}
		}
		respondOK(w, map[string]interface{}{
			"updated":          false,
			"previous_version": app.Version,
			"latest_version":   ver,
			"app":              app,
		})
		return
	}

	if err := msi.ValidateContentURL(resolved.InstallerURL); err != nil {
		respondErr(w, http.StatusBadRequest, "WinGet installer URL failed validation: "+err.Error())
		return
	}

	var fileSize int64
	prodCodeRaw := strings.TrimSpace(resolved.ProductCode)
	shaRaw := strings.TrimSpace(resolved.SHA256)
	upgCode := strings.TrimSpace(resolved.UpgradeCode)
	if prodCodeRaw == "" || shaRaw == "" {
		meta, merr := msiInspectURL(r.Context(), resolved.InstallerURL)
		if merr != nil {
			respondErr(w, http.StatusBadGateway, "failed to inspect updated WinGet MSI binary: "+merr.Error())
			return
		}
		if prodCodeRaw == "" {
			prodCodeRaw = meta.ProductCode
		}
		if shaRaw == "" {
			shaRaw = meta.SHA256
		}
		if upgCode == "" {
			upgCode = meta.UpgradeCode
		}
		if ver == "" {
			ver = meta.ProductVersion
		}
		fileSize = meta.FileSizeBytes
	} else {
		fileSize = h.probeRemoteContentLength(r.Context(), resolved.InstallerURL)
	}

	prodCode, err := msi.NormalizeProductCode(prodCodeRaw)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid WinGet MSI ProductCode: "+err.Error())
		return
	}
	shaHex, err := msi.NormalizeSHA256(shaRaw)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid WinGet MSI SHA-256: "+err.Error())
		return
	}

	var conflict int
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM msi_apps WHERE product_code = ? AND id <> ?`), prodCode, app.ID,
	).Scan(&conflict); err == nil && conflict > 0 {
		respondErr(w, http.StatusConflict, fmt.Sprintf("another catalog entry already uses ProductCode %s", prodCode))
		return
	}

	if upgCode == "" {
		upgCode = app.UpgradeCode
	}
	if fileSize <= 0 {
		fileSize = app.FileSizeBytes
	}
	prevVer := app.Version
	now := time.Now().UTC()

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		UPDATE msi_apps
		SET version = ?, product_code = ?, upgrade_code = ?,
		    content_url = ?, sha256 = ?, file_size_bytes = ?,
		    winget_package_id = ?, winget_arch = ?, updated_at = ?
		WHERE id = ?
	`), ver, prodCode, upgCode, resolved.InstallerURL, shaHex, fileSize, resolved.PackageID, resolved.Architecture, now, app.ID)
	if err != nil {
		slog.Error("api: updating MSI app from WinGet refresh", "app_id", app.ID, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to update application catalog metadata")
		return
	}

	h.reconcileFleetInventoryVersions(r.Context())
	h.audit(r, actor, "app.winget_refresh", "app", app.ID,
		fmt.Sprintf(`{"package_id":%q,"previous_version":%q,"version":%q,"product_code":%q}`, resolved.PackageID, prevVer, ver, prodCode))

	updatedApp, err := h.loadMSIApp(r.Context(), app.ID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload updated application")
		return
	}
	respondOK(w, map[string]interface{}{
		"updated":          true,
		"previous_version": prevVer,
		"latest_version":   ver,
		"app":              updatedApp,
	})
}

func (h *Handler) inferWinGetPackageID(ctx context.Context, appName, publisher string) string {
	baseName := mdm.CanonicalAppBaseName(appName)
	if baseName == "" {
		return ""
	}
	results, err := h.winget.Search(ctx, baseName)
	if err != nil {
		return ""
	}
	for _, r := range results {
		rBase := mdm.CanonicalAppBaseName(r.Name)
		if rBase == baseName || strings.HasPrefix(rBase, baseName+" ") || strings.HasPrefix(baseName, rBase+" ") {
			return r.PackageID
		}
		if publisher != "" && strings.EqualFold(strings.TrimSpace(r.Publisher), strings.TrimSpace(publisher)) &&
			(strings.Contains(rBase, baseName) || strings.Contains(baseName, rBase)) {
			return r.PackageID
		}
	}
	return ""
}

func (h *Handler) probeRemoteContentLength(ctx context.Context, rawURL string) int64 {
	if h.contentClient == nil {
		return 0
	}
	hCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(hCtx, http.MethodHead, rawURL, nil)
	if err != nil {
		return 0
	}
	resp, err := h.contentClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	if resp.ContentLength > 0 {
		return resp.ContentLength
	}
	return 0
}
