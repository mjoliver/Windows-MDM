package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// CatalogEntry is a single policy from the DDF-ingested catalog.
type CatalogEntry struct {
	ID            int    `json:"id"`
	OMAURI        string `json:"oma_uri"`
	DisplayName   string `json:"display_name"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	CSPName       string `json:"csp_name"`
	DataType      string `json:"data_type"`
	AllowedValues string `json:"allowed_values"` // JSON array string
	DefaultValue  string `json:"default_value"`
	MinOSVersion  string `json:"min_os_version"`
	AccessTypes   string `json:"access_types"` // JSON array string
	IsDeprecated  bool   `json:"is_deprecated"`
}

// HandleListCatalog returns all policy catalog entries.
// Supports optional query params: ?csp=BitLocker&search=encrypt&limit=50&offset=0
// GET /api/catalog
func (h *Handler) HandleListCatalog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	csp := q.Get("csp")
	search := q.Get("search")
	limit := 100
	offset := 0

	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	query := `
		SELECT id, oma_uri, COALESCE(display_name,''), COALESCE(description,''),
		       COALESCE(category,''), COALESCE(csp_name,''), data_type,
		       COALESCE(allowed_values,''), COALESCE(default_value,''),
		       COALESCE(min_os_version,''), COALESCE(access_types,'[]'), is_deprecated
		FROM policy_catalog
		WHERE is_deprecated = 0
	`
	args := []interface{}{}

	if csp != "" {
		query += " AND csp_name = ?"
		args = append(args, csp)
	}
	if search != "" {
		query += " AND (display_name LIKE ? OR oma_uri LIKE ? OR description LIKE ?)"
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern, pattern)
	}

	query += " ORDER BY csp_name, display_name LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(query), args...)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to query catalog")
		return
	}
	defer rows.Close()

	var entries []CatalogEntry
	for rows.Next() {
		var e CatalogEntry
		var isDeprecated int
		if err := rows.Scan(
			&e.ID, &e.OMAURI, &e.DisplayName, &e.Description,
			&e.Category, &e.CSPName, &e.DataType,
			&e.AllowedValues, &e.DefaultValue, &e.MinOSVersion,
			&e.AccessTypes, &isDeprecated,
		); err != nil {
			continue
		}
		e.IsDeprecated = isDeprecated == 1
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []CatalogEntry{}
	}

	// Get total count for pagination
	var total int
	countQuery := "SELECT COUNT(*) FROM policy_catalog WHERE is_deprecated = 0"
	countArgs := []interface{}{}
	if csp != "" {
		countQuery += " AND csp_name = ?"
		countArgs = append(countArgs, csp)
	}
	if search != "" {
		countQuery += " AND (display_name LIKE ? OR oma_uri LIKE ? OR description LIKE ?)"
		pattern := "%" + search + "%"
		countArgs = append(countArgs, pattern, pattern, pattern)
	}
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(countQuery), countArgs...).Scan(&total)

	respondOK(w, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// HandleGetCatalogEntry returns a single catalog entry by ID.
// GET /api/catalog/{id}
func (h *Handler) HandleGetCatalogEntry(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid catalog id")
		return
	}

	var e CatalogEntry
	var isDeprecated int
	err = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, oma_uri, COALESCE(display_name,''), COALESCE(description,''),
		       COALESCE(category,''), COALESCE(csp_name,''), data_type,
		       COALESCE(allowed_values,''), COALESCE(default_value,''),
		       COALESCE(min_os_version,''), COALESCE(access_types,'[]'), is_deprecated
		FROM policy_catalog WHERE id = ?
	`), id).Scan(
		&e.ID, &e.OMAURI, &e.DisplayName, &e.Description,
		&e.Category, &e.CSPName, &e.DataType,
		&e.AllowedValues, &e.DefaultValue, &e.MinOSVersion,
		&e.AccessTypes, &isDeprecated,
	)
	if err != nil {
		respondErr(w, http.StatusNotFound, "catalog entry not found")
		return
	}
	e.IsDeprecated = isDeprecated == 1
	respondOK(w, e)
}

// HandleListCSPs returns all unique CSP names in the catalog, useful for building
// a category tree in the dashboard.
// GET /api/catalog/csps
func (h *Handler) HandleListCSPs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT DISTINCT csp_name, COUNT(*) as count
		FROM policy_catalog
		WHERE is_deprecated = 0 AND csp_name != ''
		GROUP BY csp_name
		ORDER BY csp_name
	`))
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list CSPs")
		return
	}
	defer rows.Close()

	type CSP struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var csps []CSP
	for rows.Next() {
		var c CSP
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			continue
		}
		csps = append(csps, c)
	}
	if csps == nil {
		csps = []CSP{}
	}
	respondOK(w, csps)
}
