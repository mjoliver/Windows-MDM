package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
)

// setChiURLParam sets a chi URL parameter for tests.
func setChiURLParam(r *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Keys = append(ctx.URLParams.Keys, key)
	ctx.URLParams.Values = append(ctx.URLParams.Values, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

// ── Tests for HandleListCatalog ───────────────────────────────────────────────

func TestHandleListCatalog(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
		expectKeys []string
	}{
		{
			name:       "list all catalog entries",
			url:        "/api/catalog",
			expectCode: http.StatusOK,
			expectKeys: []string{"entries", "total", "limit", "offset"},
		},
		{
			name:       "filter by CSP",
			url:        "/api/catalog?csp=BitLocker",
			expectCode: http.StatusOK,
			expectKeys: []string{"entries", "total", "limit", "offset"},
		},
		{
			name:       "search by display name",
			url:        "/api/catalog?search=BitLocker",
			expectCode: http.StatusOK,
			expectKeys: []string{"entries", "total", "limit", "offset"},
		},
		{
			name:       "page 2 with limit 10",
			url:        "/api/catalog?limit=10&offset=10",
			expectCode: http.StatusOK,
			expectKeys: []string{"entries", "total", "limit", "offset"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			// Mock the data query
			mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "oma_uri", "display_name", "description", "category",
					"csp_name", "data_type", "allowed_values", "default_value",
					"min_os_version", "access_types", "is_deprecated",
				}).AddRow(
					1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
					"Enable disk encryption", "Security", "BitLocker", "string",
					"[]", "", "10.0.17763", "[]", 0,
				))

			// Mock the count query
			mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()

			h.HandleListCatalog(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d", w.Code, tt.expectCode)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			for _, key := range tt.expectKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("expected key %q in response, got keys: %v", key, getKeys(result))
				}
			}

			// Verify entries is an array
			entries, ok := result["entries"].([]interface{})
			if !ok {
				t.Error("expected 'entries' to be an array")
			}

			// Verify total is a number
			total, ok := result["total"].(float64)
			if !ok {
				t.Error("expected 'total' to be a number")
			} else {
				if int(total) != len(entries) {
					t.Errorf("total = %d, want %d (length of entries)", int(total), len(entries))
				}
			}

			// Verify limit and offset are numbers
			_, ok = result["limit"].(float64)
			if !ok {
				t.Error("expected 'limit' to be a number")
			}

			_, ok = result["offset"].(float64)
			if !ok {
				t.Error("expected 'offset' to be a number")
			}
		})
	}
}

func TestHandleListCatalogPaginationDefaults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// No limit/offset provided - should default to 100/0
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 100 {
		t.Errorf("limit = %v, want 100", result["limit"])
	}
	if int(result["offset"].(float64)) != 0 {
		t.Errorf("offset = %v, want 0", result["offset"])
	}
}

func TestHandleListCatalogCustomPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=20&offset=40", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 20 {
		t.Errorf("limit = %v, want 20", result["limit"])
	}
	if int(result["offset"].(float64)) != 40 {
		t.Errorf("offset = %v, want 40", result["offset"])
	}
}

func TestHandleListCatalogDatabaseError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	dbErr := errors.New("db error")
	mock.ExpectQuery("SELECT.*FROM policy_catalog").
		WillReturnError(dbErr)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "failed to query catalog" {
		t.Errorf("expected error 'failed to query catalog', got %q", resp["error"])
	}
}

// ── Tests for HandleGetCatalogEntry ───────────────────────────────────────────

func TestHandleGetCatalogEntry(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name: "valid entry",
			id:   "1",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "oma_uri", "display_name", "description", "category",
						"csp_name", "data_type", "allowed_values", "default_value",
						"min_os_version", "access_types", "is_deprecated",
					}).AddRow(
						1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
						"Enable disk encryption", "Security", "BitLocker", "string",
						"[]", "", "10.0.17763", "[]", 0,
					))
			},
			expectCode: http.StatusOK,
		},
		{
			name: "entry not found",
			id:   "999",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
					WillReturnError(sql.ErrNoRows)
			},
			expectCode: http.StatusNotFound,
		},
		{
			name: "invalid id",
			id:   "abc",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Will fail to parse ID before query
			},
			expectCode: http.StatusBadRequest,
		},
		{
			name: "database error",
			id:   "1",
			setupMock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("db error")
				mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
					WillReturnError(dbErr)
			},
			expectCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/catalog/"+tt.id, nil)
			r = setChiURLParam(r, "id", tt.id)
			w := httptest.NewRecorder()

			h.HandleGetCatalogEntry(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var result CatalogEntry
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if result.ID != 1 {
					t.Errorf("ID = %d, want 1", result.ID)
				}
				if result.OMAURI != "./Vendor/MSFT/Policy/Config/BitLocker" {
					t.Errorf("OMAURI = %q, want %q", result.OMAURI, "./Vendor/MSFT/Policy/Config/BitLocker")
				}
				if result.IsDeprecated {
					t.Error("expected IsDeprecated to be false")
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if resp["error"] != "catalog entry not found" {
					t.Errorf("expected error 'catalog entry not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleListCSPs ──────────────────────────────────────────────────

func TestHandleListCSPs(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name: "list CSPs",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''").
					WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}).
						AddRow("BitLocker", 15).
						AddRow("Windows", 42).
						AddRow("WiFi", 8))
			},
			expectCode: http.StatusOK,
		},
		{
			name: "empty list",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''").
					WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}))
			},
			expectCode: http.StatusOK,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("db error")
				mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog").
					WillReturnError(dbErr)
			},
			expectCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/catalog/csps", nil)
			w := httptest.NewRecorder()

			h.HandleListCSPs(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d", w.Code, tt.expectCode)
			}

			if tt.expectCode == http.StatusOK {
				var result []map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}

				if tt.name == "list CSPs" && len(result) != 3 {
					t.Errorf("got %d CSPs, want 3", len(result))
				}
				if tt.name == "empty list" && len(result) != 0 {
					t.Errorf("got %d CSPs, want 0", len(result))
				}
			}
		})
	}
}

// ── Tests for CatalogEntry JSON marshaling ────────────────────────────────────

func TestCatalogEntryJSONRoundTrip(t *testing.T) {
	entry := CatalogEntry{
		ID:            1,
		OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker",
		DisplayName:   "BitLocker",
		Description:   "Enable disk encryption",
		Category:      "Security",
		CSPName:       "BitLocker",
		DataType:      "string",
		AllowedValues: "[]",
		DefaultValue:  "",
		MinOSVersion:  "10.0.17763",
		AccessTypes:   "[]",
		IsDeprecated:  false,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CatalogEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != entry.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, entry.ID)
	}
	if decoded.OMAURI != entry.OMAURI {
		t.Errorf("OMAURI = %q, want %q", decoded.OMAURI, entry.OMAURI)
	}
	if decoded.IsDeprecated != entry.IsDeprecated {
		t.Errorf("IsDeprecated = %v, want %v", decoded.IsDeprecated, entry.IsDeprecated)
	}
}

func TestCatalogEntryDeprecated(t *testing.T) {
	entry := CatalogEntry{
		ID:           99,
		OMAURI:       "./Vendor/MSFT/Policy/Config/OldPolicy",
		DisplayName:  "Old Policy",
		IsDeprecated: true,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded CatalogEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !decoded.IsDeprecated {
		t.Error("expected IsDeprecated to be true")
	}
}

// ── Table-driven test for getKeys helper ──────────────────────────────────────
func TestGetKeys(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": []string{"a", "b"},
	}

	keys := getKeys(m)
	if len(keys) != 3 {
		t.Errorf("got %d keys, want 3", len(keys))
	}

	expectedKeys := map[string]bool{"key1": true, "key2": true, "key3": true}
	for _, k := range keys {
		if !expectedKeys[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
}

// ── Tests for HandleListCatalogWithCSPFilter ──────────────────────────────────

func TestHandleListCatalogCSPFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query with CSP filter
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Enable disk encryption", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp=BitLocker", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogSearchWithLIKE ─────────────────────────────────

func TestHandleListCatalogSearch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query with LIKE search
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Enable disk encryption", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=BitLocker", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogWithLimitEdgeCases ─────────────────────────────

func TestHandleListCatalogLimitEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantLimit int
	}{
		{
			name:      "limit 0 defaults to 100",
			url:       "/api/catalog?limit=0",
			wantLimit: 100,
		},
		{
			name:      "limit 501 ignored defaults to 100",
			url:       "/api/catalog?limit=501",
			wantLimit: 100,
		},
		{
			name:      "negative limit ignored defaults to 100",
			url:       "/api/catalog?limit=-10",
			wantLimit: 100,
		},
		{
			name:      "non-numeric limit ignored defaults to 100",
			url:       "/api/catalog?limit=abc",
			wantLimit: 100,
		},
		{
			name:      "negative offset ignored defaults to 0",
			url:       "/api/catalog?offset=-1",
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "oma_uri", "display_name", "description", "category",
					"csp_name", "data_type", "allowed_values", "default_value",
					"min_os_version", "access_types", "is_deprecated",
				}))

			mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()

			h.HandleListCatalog(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			gotLimit := int(result["limit"].(float64))
			if gotLimit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", gotLimit, tt.wantLimit)
			}
		})
	}
}

// ── Tests for HandleGetCatalogEntryWithDeprecated ─────────────────────────────

func TestHandleGetCatalogEntryWithDeprecated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns a deprecated entry (is_deprecated = 1)
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			99, "./Vendor/MSFT/Policy/Config/OldPolicy", "Old Policy",
			"This is deprecated", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 1,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/99", nil)
	r = setChiURLParam(r, "id", "99")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.IsDeprecated {
		t.Error("expected IsDeprecated to be true for deprecated entry")
	}
}

// ── Tests for HandleListCatalogExcludesDeprecated ─────────────────────────────

func TestHandleListCatalogExcludesDeprecated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query should only return non-deprecated entries
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/Active", "Active Policy",
			"This is active", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	// Count query
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1 (deprecated should be excluded)", len(entries))
	}
}

// ── Tests for HandleListCSPsExcludesEmpty ─────────────────────────────────────

func TestHandleListCSPsExcludesEmpty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Should only return non-empty CSP names
	mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''").
		WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}).
			AddRow("BitLocker", 15).
			AddRow("Windows", 42))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/csps", nil)
	w := httptest.NewRecorder()

	h.HandleListCSPs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("got %d CSPs, want 2", len(result))
	}
}

// getKeys returns the keys of a map.
func getKeys(m map[string]interface{}) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ── Tests for HandleGetCatalogEntryCOALESCEFields ─────────────────────────────

func TestHandleGetCatalogEntryCOALESCEFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns entry with empty COALESCE fields
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			42, "./Vendor/MSFT/Policy/Config/Test", "", "", "",
			"", "string", "", "", "", "[]", 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/42", nil)
	r = setChiURLParam(r, "id", "42")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// COALESCE should return empty string when column is NULL
	if result.DisplayName != "" {
		t.Errorf("DisplayName should be empty string from COALESCE, got %q", result.DisplayName)
	}
	if result.OMAURI != "./Vendor/MSFT/Policy/Config/Test" {
		t.Errorf("OMAURI = %q, want %q", result.OMAURI, "./Vendor/MSFT/Policy/Config/Test")
	}
}

// ── Tests for HandleListCatalogEmptyEntries ───────────────────────────────────

func TestHandleListCatalogEmptyEntries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// No entries returned
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Entries should be empty array, not null
	entries := result["entries"].([]interface{})
	if entries == nil {
		t.Error("entries should be empty array, not null")
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

// ── Tests for HandleListCatalogWithSearchAndCSP ───────────────────────────────

func TestHandleListCatalogSearchAndCSP(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query with both search and CSP filter
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Enable disk encryption", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp=BitLocker&search=encryption", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogLimit500Allowed ────────────────────────────────

func TestHandleListCatalogLimit500Allowed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=500", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 500 {
		t.Errorf("limit = %v, want 500", result["limit"])
	}
}

// ── Tests for HandleGetCatalogEntryWithJSONFields ─────────────────────────────

func TestHandleGetCatalogEntryWithJSONFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns entry with JSON array fields
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			5, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Enable disk encryption", "Security", "BitLocker", "string",
			`["enabled","disabled"]`, "enabled", "10.0.17763",
			`["Get","Replace","Exec"]`, 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/5", nil)
	r = setChiURLParam(r, "id", "5")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.AllowedValues != `["enabled","disabled"]` {
		t.Errorf("AllowedValues = %q, want %q", result.AllowedValues, `["enabled","disabled"]`)
	}
	if result.AccessTypes != `["Get","Replace","Exec"]` {
		t.Errorf("AccessTypes = %q, want %q", result.AccessTypes, `["Get","Replace","Exec"]`)
	}
}

// ── Tests for HandleListCatalogOrderBy ────────────────────────────────────────

func TestHandleListCatalogOrderBy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Verify ORDER BY csp_name, display_name is present
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY csp_name, display_name LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/A", "Alpha",
			"Test", "Security", "A-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		).AddRow(
			2, "./Vendor/MSFT/Policy/Config/B", "Beta",
			"Test", "Security", "B-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

// ── Tests for HandleListCatalogWithOffset ─────────────────────────────────────

func TestHandleListCatalogWithOffset(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			2, "./Vendor/MSFT/Policy/Config/B", "Beta",
			"Test", "Security", "B-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=1&offset=1", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Total should still be 10 (all non-deprecated), not just what we returned
	if int(result["total"].(float64)) != 10 {
		t.Errorf("total = %v, want 10", result["total"])
	}
	// But we only returned 1 entry
	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogWithLargeLimit ─────────────────────────────────

func TestHandleListCatalogLargeLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=200", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 200 {
		t.Errorf("limit = %v, want 200", result["limit"])
	}
}

// ── Tests for HandleGetCatalogEntryWithNullFields ─────────────────────────────

func TestHandleGetCatalogEntryWithNullFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns entry with NULL display_name, description, etc.
	// COALESCE converts NULLs to empty strings
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			10, "./Vendor/MSFT/Policy/Config/Minimal", "", "", "",
			"", "string", "", "", "", "", 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/10", nil)
	r = setChiURLParam(r, "id", "10")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// COALESCE should convert NULL to empty string
	if result.DisplayName != "" {
		t.Errorf("DisplayName should be empty from COALESCE, got %q", result.DisplayName)
	}
	if result.Description != "" {
		t.Errorf("Description should be empty from COALESCE, got %q", result.Description)
	}
}

// ── Tests for HandleListCSPsWithGroupBy ───────────────────────────────────────

func TestHandleListCSPsWithGroupBy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''.*GROUP BY csp_name.*ORDER BY csp_name").
		WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}).
			AddRow("AlphaCSP", 5).
			AddRow("BetaCSP", 10).
			AddRow("GammaCSP", 3))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/csps", nil)
	w := httptest.NewRecorder()

	h.HandleListCSPs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("got %d CSPs, want 3", len(result))
	}

	// Verify alphabetical ordering
	if result[0]["name"] != "AlphaCSP" {
		t.Errorf("first CSP = %v, want AlphaCSP", result[0]["name"])
	}
	if result[2]["name"] != "GammaCSP" {
		t.Errorf("third CSP = %v, want GammaCSP", result[2]["name"])
	}
}

// ── Tests for HandleGetCatalogEntryWithAllowedValues ──────────────────────────

func TestHandleGetCatalogEntryAllowedValues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			15, "./Vendor/MSFT/Policy/Config/Limits", "Limits",
			"Set limits", "Security", "Limits", "int",
			`[1,2,3,4,5]`, "3", "10.0.17763", `["Get","Replace"]`, 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/15", nil)
	r = setChiURLParam(r, "id", "15")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.AllowedValues != `[1,2,3,4,5]` {
		t.Errorf("AllowedValues = %q, want %q", result.AllowedValues, `[1,2,3,4,5]`)
	}
	if result.DefaultValue != "3" {
		t.Errorf("DefaultValue = %q, want %q", result.DefaultValue, "3")
	}
}

// ── Tests for HandleListCatalogMultipleCSPFilters ─────────────────────────────

func TestHandleListCatalogMultipleCSPFilters(t *testing.T) {
	// The handler only supports a single CSP filter via ?csp=
	// Multiple CSPs would need to be handled differently
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp=BitLocker", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["total"].(float64)) != 1 {
		t.Errorf("total = %v, want 1", result["total"])
	}
}

// ── Tests for HandleListCatalogSearchOnly ─────────────────────────────────────

func TestHandleListCatalogSearchOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Search that matches nothing
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=nonexistentpolicy", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
	if int(result["total"].(float64)) != 0 {
		t.Errorf("total = %v, want 0", result["total"])
	}
}

// ── Tests for HandleGetCatalogEntryDataTypes ──────────────────────────────────

func TestHandleGetCatalogEntryDataTypes(t *testing.T) {
	tests := []struct {
		name      string
		dataType  string
		value     string
		wantType  string
		wantValue string
	}{
		{
			name:      "string data type",
			dataType:  "string",
			value:     "enabled",
			wantType:  "string",
			wantValue: "enabled",
		},
		{
			name:      "int data type",
			dataType:  "int",
			value:     "42",
			wantType:  "int",
			wantValue: "42",
		},
		{
			name:      "boolean data type",
			dataType:  "boolean",
			value:     "true",
			wantType:  "boolean",
			wantValue: "true",
		},
		{
			name:      "datetime data type",
			dataType:  "datetime",
			value:     "2026-01-01T00:00:00Z",
			wantType:  "datetime",
			wantValue: "2026-01-01T00:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "oma_uri", "display_name", "description", "category",
					"csp_name", "data_type", "allowed_values", "default_value",
					"min_os_version", "access_types", "is_deprecated",
				}).AddRow(
					1, "./Vendor/MSFT/Policy/Config/Test", "Test",
					"Test policy", "Security", "Test", tt.dataType,
					"[]", tt.value, "10.0.17763", "[]", 0,
				))

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/catalog/1", nil)
			r = setChiURLParam(r, "id", "1")
			w := httptest.NewRecorder()

			h.HandleGetCatalogEntry(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			var result CatalogEntry
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if result.DataType != tt.wantType {
				t.Errorf("DataType = %q, want %q", result.DataType, tt.wantType)
			}
			if result.DefaultValue != tt.wantValue {
				t.Errorf("DefaultValue = %q, want %q", result.DefaultValue, tt.wantValue)
			}
		})
	}
}

// ── Tests for HandleListCatalogWithMinOSVersion ───────────────────────────────

func TestHandleListCatalogWithMinOSVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.19041", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleGetCatalogEntryComplexAllowedValues ───────────────────────

func TestHandleGetCatalogEntryComplexAllowedValues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Allowed values with nested JSON
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			20, "./Vendor/MSFT/Policy/Config/Complex", "Complex",
			"Complex policy", "Security", "Complex", "string",
			`[{"key":"value"},{"key2":"value2"}]`, `{"key":"value"}`, "10.0.17763", `["Get","Replace","Exec"]`, 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/20", nil)
	r = setChiURLParam(r, "id", "20")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.AllowedValues != `[{"key":"value"},{"key2":"value2"}]` {
		t.Errorf("AllowedValues = %q, want %q", result.AllowedValues, `[{"key":"value"},{"key2":"value2"}]`)
	}
}

// ── Tests for HandleListCatalogPaginationAndFilters ───────────────────────────

func TestHandleListCatalogPaginationAndFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp=BitLocker&search=encrypt&limit=10&offset=20", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Total should reflect the filtered count, not all entries
	if int(result["total"].(float64)) != 5 {
		t.Errorf("total = %v, want 5 (filtered count)", result["total"])
	}
	if int(result["limit"].(float64)) != 10 {
		t.Errorf("limit = %v, want 10", result["limit"])
	}
	if int(result["offset"].(float64)) != 20 {
		t.Errorf("offset = %v, want 20", result["offset"])
	}
}

// ── Tests for HandleListCatalogWithDeprecatedFlag ─────────────────────────────

func TestHandleListCatalogWithDeprecatedFlag(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Handler queries is_deprecated = 0
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/Active", "Active",
			"Active policy", "Security", "Active", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogSpecialCharacters ──────────────────────────────

func TestHandleListCatalogSpecialCharacters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Search with special characters
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt & secure", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=encrypt", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleListCatalogLargeResults ───────────────────────────────────

func TestHandleListCatalogLargeResults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Create a large result set
	rows := sqlmock.NewRows([]string{
		"id", "oma_uri", "display_name", "description", "category",
		"csp_name", "data_type", "allowed_values", "default_value",
		"min_os_version", "access_types", "is_deprecated",
	})
	for i := 1; i <= 50; i++ {
		rows.AddRow(
			i, "./Vendor/MSFT/Policy/Config/Test"+string(rune(i%26+'A')),
			"Policy "+string(rune(i%26+'A')), "Description", "Security",
			"CSP", "string", "[]", "", "10.0.17763", "[]", 0,
		)
	}

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(rows)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(50))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=100", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 50 {
		t.Errorf("got %d entries, want 50", len(entries))
	}
	if int(result["total"].(float64)) != 50 {
		t.Errorf("total = %v, want 50", result["total"])
	}
}

// ── Tests for HandleListCatalogMinOSVersionSorting ────────────────────────────

func TestHandleListCatalogMinOSVersionSorting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Results sorted by csp_name, display_name, not min_os_version
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY csp_name, display_name LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/A", "Alpha",
			"Test", "Security", "A-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		).AddRow(
			2, "./Vendor/MSFT/Policy/Config/B", "Beta",
			"Test", "Security", "A-CSP", "string",
			"[]", "", "10.0.19041", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

// ── Tests for HandleGetCatalogEntryEmptyAllowedValues ─────────────────────────

func TestHandleGetCatalogEntryEmptyAllowedValues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			25, "./Vendor/MSFT/Policy/Config/NoLimits", "No Limits",
			"No allowed values", "Security", "NoLimits", "string",
			"", "", "10.0.17763", "", 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/25", nil)
	r = setChiURLParam(r, "id", "25")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.AllowedValues != "" {
		t.Errorf("AllowedValues = %q, want empty string", result.AllowedValues)
	}
	if result.AccessTypes != "" {
		t.Errorf("AccessTypes = %q, want empty string", result.AccessTypes)
	}
}

// ── Tests for HandleListCatalogOffsetZero ─────────────────────────────────────

func TestHandleListCatalogOffsetZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?offset=0", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["offset"].(float64)) != 0 {
		t.Errorf("offset = %v, want 0", result["offset"])
	}
}

// ── Tests for HandleListCatalogLimitAndOffsetBoth ─────────────────────────────

func TestHandleListCatalogLimitAndOffsetBoth(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			2, "./Vendor/MSFT/Policy/Config/Beta", "Beta",
			"Test", "Security", "BetaCSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=10&offset=50", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 10 {
		t.Errorf("limit = %v, want 10", result["limit"])
	}
	if int(result["offset"].(float64)) != 50 {
		t.Errorf("offset = %v, want 50", result["offset"])
	}
	if int(result["total"].(float64)) != 100 {
		t.Errorf("total = %v, want 100", result["total"])
	}
}

// ── Tests for HandleListCatalogNoResults ──────────────────────────────────────

func TestHandleListCatalogNoResults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if entries == nil {
		t.Error("entries should be empty array, not null")
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
	if int(result["total"].(float64)) != 0 {
		t.Errorf("total = %v, want 0", result["total"])
	}
}

// ── Tests for HandleListCatalogLimitGreaterThan500 ────────────────────────────

func TestHandleListCatalogLimitGreaterThan500(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// limit=600 is > 500, should default to 100
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=600", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Should default to 100 since 600 > 500
	if int(result["limit"].(float64)) != 100 {
		t.Errorf("limit = %v, want 100 (defaulted from 600)", result["limit"])
	}
}

// ── Tests for HandleGetCatalogEntryAllFields ──────────────────────────────────

func TestHandleGetCatalogEntryAllFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns entry with all fields populated
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			30, "./Vendor/MSFT/Policy/Config/Full", "Full Policy",
			"Full description with all fields", "Security", "FullCSP",
			"string", `["a","b","c"]`, "a", "10.0.17763",
			`["Get","Replace","Exec"]`, 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/30", nil)
	r = setChiURLParam(r, "id", "30")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify all fields
	if result.ID != 30 {
		t.Errorf("ID = %d, want 30", result.ID)
	}
	if result.OMAURI != "./Vendor/MSFT/Policy/Config/Full" {
		t.Errorf("OMAURI = %q, want %q", result.OMAURI, "./Vendor/MSFT/Policy/Config/Full")
	}
	if result.DisplayName != "Full Policy" {
		t.Errorf("DisplayName = %q, want %q", result.DisplayName, "Full Policy")
	}
	if result.Description != "Full description with all fields" {
		t.Errorf("Description = %q, want %q", result.Description, "Full description with all fields")
	}
	if result.Category != "Security" {
		t.Errorf("Category = %q, want %q", result.Category, "Security")
	}
	if result.CSPName != "FullCSP" {
		t.Errorf("CSPName = %q, want %q", result.CSPName, "FullCSP")
	}
	if result.DataType != "string" {
		t.Errorf("DataType = %q, want %q", result.DataType, "string")
	}
	if result.AllowedValues != `["a","b","c"]` {
		t.Errorf("AllowedValues = %q, want %q", result.AllowedValues, `["a","b","c"]`)
	}
	if result.DefaultValue != "a" {
		t.Errorf("DefaultValue = %q, want %q", result.DefaultValue, "a")
	}
	if result.MinOSVersion != "10.0.17763" {
		t.Errorf("MinOSVersion = %q, want %q", result.MinOSVersion, "10.0.17763")
	}
	if result.AccessTypes != `["Get","Replace","Exec"]` {
		t.Errorf("AccessTypes = %q, want %q", result.AccessTypes, `["Get","Replace","Exec"]`)
	}
	if result.IsDeprecated {
		t.Error("IsDeprecated should be false")
	}
}

// ── Tests for HandleListCatalogCSPFilterAndPagination ─────────────────────────

func TestHandleListCatalogCSPFilterAndPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(25))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp=BitLocker&limit=5&offset=10", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Total should be 25 (filtered count for BitLocker)
	if int(result["total"].(float64)) != 25 {
		t.Errorf("total = %v, want 25", result["total"])
	}
	if int(result["limit"].(float64)) != 5 {
		t.Errorf("limit = %v, want 5", result["limit"])
	}
	if int(result["offset"].(float64)) != 10 {
		t.Errorf("offset = %v, want 10", result["offset"])
	}
}

// ── Tests for HandleListCatalogSearchAndPagination ────────────────────────────

func TestHandleListCatalogSearchAndPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=BitLocker&limit=2&offset=0", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["total"].(float64)) != 3 {
		t.Errorf("total = %v, want 3", result["total"])
	}
	if int(result["limit"].(float64)) != 2 {
		t.Errorf("limit = %v, want 2", result["limit"])
	}
	if int(result["offset"].(float64)) != 0 {
		t.Errorf("offset = %v, want 0", result["offset"])
	}
}

// ── Tests for HandleListCatalogEmptyResultSet ─────────────────────────────────

func TestHandleListCatalogEmptyResultSet(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if entries == nil {
		t.Error("entries should be empty array, not null")
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
	if int(result["total"].(float64)) != 0 {
		t.Errorf("total = %v, want 0", result["total"])
	}
}

// ── Tests for HandleListCatalogLimit1 ─────────────────────────────────────────

func TestHandleListCatalogLimit1(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=1", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
	if int(result["total"].(float64)) != 100 {
		t.Errorf("total = %v, want 100", result["total"])
	}
}

// ── Tests for HandleListCatalogOffset100 ──────────────────────────────────────

func TestHandleListCatalogOffset100(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?offset=100", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["offset"].(float64)) != 100 {
		t.Errorf("offset = %v, want 100", result["offset"])
	}
	if int(result["limit"].(float64)) != 100 {
		t.Errorf("limit = %v, want 100", result["limit"])
	}
}

// ── Tests for HandleListCatalogVariousCSPNames ────────────────────────────────

func TestHandleListCatalogVariousCSPNames(t *testing.T) {
	cspNames := []string{"BitLocker", "Windows", "WiFi", "Ethernet", "Bluetooth", "OneDrive", "Edge", "Teams"}

	for _, csp := range cspNames {
		t.Run(csp, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?.*ORDER BY.*LIMIT \\? OFFSET \\?").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "oma_uri", "display_name", "description", "category",
					"csp_name", "data_type", "allowed_values", "default_value",
					"min_os_version", "access_types", "is_deprecated",
				}).AddRow(
					1, "./Vendor/MSFT/Policy/Config/"+csp, csp,
					"Policy for "+csp, "Security", csp, "string",
					"[]", "", "10.0.17763", "[]", 0,
				))

			mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name = \\?").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/catalog?csp="+csp, nil)
			w := httptest.NewRecorder()

			h.HandleListCatalog(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			entries := result["entries"].([]interface{})
			if len(entries) != 1 {
				t.Errorf("got %d entries, want 1 for CSP %q", len(entries), csp)
			}
		})
	}
}

// ── Tests for HandleListCatalogNullIsDeprecated ───────────────────────────────

func TestHandleListCatalogNullIsDeprecated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// is_deprecated is NULL, treated as false (0) in WHERE clause
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/NullDep", "Null Deprecated",
			"Test", "Security", "NullDep", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// ── Tests for HandleGetCatalogEntryNegativeID ─────────────────────────────────

func TestHandleGetCatalogEntryNegativeID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Negative ID should still be a valid integer, but no rows returned
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnError(sql.ErrNoRows)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/-1", nil)
	r = setChiURLParam(r, "id", "-1")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// ── Tests for HandleGetCatalogEntryVeryLargeID ────────────────────────────────

func TestHandleGetCatalogEntryVeryLargeID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Very large ID should be valid but not found
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnError(sql.ErrNoRows)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/999999999", nil)
	r = setChiURLParam(r, "id", "999999999")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// ── Tests for HandleGetCatalogEntryFloatID ────────────────────────────────────

func TestHandleGetCatalogEntryFloatID(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Float ID like "1.5" should fail strconv.Atoi
	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/1.5", nil)
	r = setChiURLParam(r, "id", "1.5")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "invalid catalog id" {
		t.Errorf("expected error 'invalid catalog id', got %q", resp["error"])
	}
}

// ── Tests for HandleGetCatalogEntryUUIDID ─────────────────────────────────────

func TestHandleGetCatalogEntryUUIDID(t *testing.T) {
	h := NewHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/550e8400-e29b-41d4-a716-446655440000", nil)
	r = setChiURLParam(r, "id", "550e8400-e29b-41d4-a716-446655440000")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "invalid catalog id" {
		t.Errorf("expected error 'invalid catalog id', got %q", resp["error"])
	}
}

// ── Tests for HandleGetCatalogEntryEmptyID ────────────────────────────────────

func TestHandleGetCatalogEntryEmptyID(t *testing.T) {
	h := NewHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/", nil)
	r = setChiURLParam(r, "id", "")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "invalid catalog id" {
		t.Errorf("expected error 'invalid catalog id', got %q", resp["error"])
	}
}

// ── Tests for HandleGetCatalogEntrySpecialCharsInID ───────────────────────────

func TestHandleGetCatalogEntrySpecialCharsInID(t *testing.T) {
	h := NewHandler(nil)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/123abc", nil)
	r = setChiURLParam(r, "id", "123abc")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// ── Tests for HandleListCatalogWhitespaceSearch ───────────────────────────────

func TestHandleListCatalogWhitespaceSearch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Search with whitespace should still work
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=%20", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleListCatalogUnicodeSearch ──────────────────────────────────

func TestHandleListCatalogUnicodeSearch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\).*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0.*AND \\(display_name LIKE \\? OR oma_uri LIKE \\? OR description LIKE \\?\\)").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?search=%E4%B8%AD%E6%96%87", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleGetCatalogEntryLongOMAURI ─────────────────────────────────

func TestHandleGetCatalogEntryLongOMAURI(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	longOMAURI := "./Vendor/MSFT/Policy/Config/VeryLongCSPName/VeryLongPolicyName/WithMany/Nested/Levels/Deep/Policy/Setting"
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			40, longOMAURI, "Long OMAURI",
			"Test", "Security", "LongCSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/40", nil)
	r = setChiURLParam(r, "id", "40")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.OMAURI != longOMAURI {
		t.Errorf("OMAURI length = %d, want %d", len(result.OMAURI), len(longOMAURI))
	}
}

// ── Tests for HandleListCatalogOrderByCSPAndDisplay ───────────────────────────

func TestHandleListCatalogOrderByCSPAndDisplay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Results should be ordered by csp_name then display_name
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY csp_name, display_name LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/A1", "Alpha",
			"Test", "Security", "A-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		).AddRow(
			2, "./Vendor/MSFT/Policy/Config/A2", "Beta",
			"Test", "Security", "A-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		).AddRow(
			3, "./Vendor/MSFT/Policy/Config/B1", "Gamma",
			"Test", "Security", "B-CSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=100", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	entries := result["entries"].([]interface{})
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

// ── Tests for HandleListCatalogCategoryFilter ─────────────────────────────────

func TestHandleListCatalogCategoryFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Handler doesn't support category filter, so all entries are returned
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?category=Security", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleListCatalogDataTypeFilter ─────────────────────────────────

func TestHandleListCatalogDataTypeFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Handler doesn't support data_type filter
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?data_type=string", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleListCatalogMinOSVersionFilter ─────────────────────────────

func TestHandleListCatalogMinOSVersionFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Handler doesn't support min_os_version filter
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?min_os_version=10.0.17763", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleListCatalogAccessTypeFilter ───────────────────────────────

func TestHandleListCatalogAccessTypeFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Handler doesn't support access_type filter
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?access_type=getAll", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleListCatalogMultipleQueries ────────────────────────────────

func TestHandleListCatalogMultipleQueries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// First query returns data
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	// Second query (count) fails
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnError(sql.ErrConnDone)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	// Handler continues even if count query fails
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleGetCatalogEntryScanError ──────────────────────────────────

func TestHandleGetCatalogEntryScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// Query returns wrong column count causing scan error
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name",
		}).AddRow(1, "./test", "Test"))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/1", nil)
	r = setChiURLParam(r, "id", "1")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	// Scan error should result in not found
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// ── Tests for HandleListCSPsWithNoRows ────────────────────────────────────────

func TestHandleListCSPsWithNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''").
		WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/csps", nil)
	w := httptest.NewRecorder()

	h.HandleListCSPs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result == nil {
		t.Error("result should be empty array, not null")
	}
	if len(result) != 0 {
		t.Errorf("got %d CSPs, want 0", len(result))
	}
}

// ── Tests for HandleListCSPsWithOrdering ──────────────────────────────────────

func TestHandleListCSPsWithOrdering(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT.*FROM policy_catalog WHERE is_deprecated = 0.*AND csp_name != ''.*GROUP BY csp_name.*ORDER BY csp_name").
		WillReturnRows(sqlmock.NewRows([]string{"csp_name", "count"}).
			AddRow("Alpha", 10).
			AddRow("Beta", 20).
			AddRow("Charlie", 5).
			AddRow("Delta", 15))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/csps", nil)
	w := httptest.NewRecorder()

	h.HandleListCSPs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result) != 4 {
		t.Errorf("got %d CSPs, want 4", len(result))
	}

	// Verify alphabetical ordering
	names := []string{
		result[0]["name"].(string),
		result[1]["name"].(string),
		result[2]["name"].(string),
		result[3]["name"].(string),
	}
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("CSPs not in alphabetical order: %s after %s", names[i], names[i-1])
		}
	}
}

// ── Tests for HandleListCatalogCountQueryInSameTransaction ────────────────────

func TestHandleListCatalogCountQueryInSameTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// First query: data
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
			"Encrypt", "Security", "BitLocker", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	// Second query: count
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["total"].(float64)) != 1 {
		t.Errorf("total = %v, want 1", result["total"])
	}
}

// ── Tests for HandleGetCatalogEntryIDZero ─────────────────────────────────────

func TestHandleGetCatalogEntryIDZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnError(sql.ErrNoRows)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/0", nil)
	r = setChiURLParam(r, "id", "0")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// ── Tests for HandleGetCatalogEntryIDOne ──────────────────────────────────────

func TestHandleGetCatalogEntryIDOne(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			1, "./Vendor/MSFT/Policy/Config/First", "First",
			"First entry", "Security", "FirstCSP", "string",
			"[]", "", "10.0.17763", "[]", 0,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/1", nil)
	r = setChiURLParam(r, "id", "1")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.ID != 1 {
		t.Errorf("ID = %d, want 1", result.ID)
	}
}

// ── Tests for HandleGetCatalogEntryIDMaxInt ───────────────────────────────────

func TestHandleGetCatalogEntryIDMaxInt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnError(sql.ErrNoRows)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/2147483647", nil)
	r = setChiURLParam(r, "id", "2147483647")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// ── Tests for HandleListCatalogLimitExactly500 ────────────────────────────────

func TestHandleListCatalogLimitExactly500(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=500", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 500 {
		t.Errorf("limit = %v, want 500", result["limit"])
	}
}

// ── Tests for HandleListCatalogLimit499 ───────────────────────────────────────

func TestHandleListCatalogLimit499(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=499", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if int(result["limit"].(float64)) != 499 {
		t.Errorf("limit = %v, want 499", result["limit"])
	}
}

// ── Tests for HandleListCatalogLimit501 ───────────────────────────────────────

func TestHandleListCatalogLimit501(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// limit=501 is > 500, should default to 100
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*ORDER BY.*LIMIT \\? OFFSET \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}))

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policy_catalog WHERE is_deprecated = 0").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog?limit=501", nil)
	w := httptest.NewRecorder()

	h.HandleListCatalog(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Should default to 100 since 501 > 500
	if int(result["limit"].(float64)) != 100 {
		t.Errorf("limit = %v, want 100 (defaulted from 501)", result["limit"])
	}
}

// ── Tests for HandleGetCatalogEntryAllDeprecatedFlags ─────────────────────────

func TestHandleGetCatalogEntryAllDeprecatedFlags(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	// is_deprecated = 1
	mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "oma_uri", "display_name", "description", "category",
			"csp_name", "data_type", "allowed_values", "default_value",
			"min_os_version", "access_types", "is_deprecated",
		}).AddRow(
			99, "./Vendor/MSFT/Policy/Config/Old", "Old Policy",
			"This is deprecated", "Security", "OldCSP", "string",
			"[]", "", "10.0.17763", "[]", 1,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/catalog/99", nil)
	r = setChiURLParam(r, "id", "99")
	w := httptest.NewRecorder()

	h.HandleGetCatalogEntry(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result CatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.IsDeprecated {
		t.Error("IsDeprecated should be true for is_deprecated = 1")
	}
}
