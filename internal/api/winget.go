package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
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
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 15, 3, 5, ?, ?)
	`),
		id, name, pub, ver, prodCode, upgCode,
		resolved.InstallerURL, shaHex, fileSize, cmdLine, now, now,
	)
	if err != nil {
		slog.Error("api: importing WinGet MSI app", "package_id", resolved.PackageID, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save imported WinGet application")
		return
	}

	h.audit(r, actor, "app.winget_import", "app", id,
		fmt.Sprintf(`{"package_id":%q,"name":%q,"version":%q,"product_code":%q}`, resolved.PackageID, name, ver, prodCode))
	slog.Info("WinGet MSI app imported", "app_id", id, "package_id", resolved.PackageID, "version", ver, "actor", actor)

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
		CreatedAt:            now,
		UpdatedAt:            now,
	})
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
