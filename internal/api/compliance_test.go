package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// setChiURLParamForCompliance sets a chi URL parameter for tests.
func setChiURLParamForCompliance(r *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Keys = append(ctx.URLParams.Keys, key)
	ctx.URLParams.Values = append(ctx.URLParams.Values, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

// contextWithAuth creates a context with authentication information for tests.
func contextWithAuth(ctx context.Context, email, role string) context.Context {
	ctx = context.WithValue(ctx, CtxKeyEmail, email)
	ctx = context.WithValue(ctx, CtxKeyRole, role)
	return ctx
}

// ── Tests for HandleFleetCompliance ───────────────────────────────────────────

func TestHandleFleetCompliance(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
		expectKeys []string
	}{
		{
			name: "fleet compliance with issues",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnRows(sqlmock.NewRows([]string{
						"total", "compliant", "non_compliant", "unknown",
					}).AddRow(100, 80, 15, 5))
				mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "fails",
					}).AddRow("./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", 10).
						AddRow("./Vendor/MSFT/Policy/Config/WiFi", "WiFi Settings", 5))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"summary", "top_issues"},
		},
		{
			name: "all devices compliant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnRows(sqlmock.NewRows([]string{
						"total", "compliant", "non_compliant", "unknown",
					}).AddRow(50, 50, 0, 0))
				mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "fails",
					}))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"summary", "top_issues"},
		},
		{
			name: "no devices enrolled",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnRows(sqlmock.NewRows([]string{
						"total", "compliant", "non_compliant", "unknown",
					}).AddRow(0, 0, 0, 0))
				mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "fails",
					}))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"summary", "top_issues"},
		},
		{
			name: "only unknown devices",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnRows(sqlmock.NewRows([]string{
						"total", "compliant", "non_compliant", "unknown",
					}).AddRow(10, 0, 0, 10))
				mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "fails",
					}))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"summary", "top_issues"},
		},
		{
			name: "database error on summary",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnError(sql.ErrConnDone)
			},
			expectCode: http.StatusInternalServerError,
			expectKeys: []string{"error"},
		},
		{
			name: "database error on issues query",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
					WillReturnRows(sqlmock.NewRows([]string{
						"total", "compliant", "non_compliant", "unknown",
					}).AddRow(100, 80, 15, 5))
				mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
					WillReturnError(sql.ErrConnDone)
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"summary", "top_issues"},
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
			r := httptest.NewRequest(http.MethodGet, "/api/compliance", nil)
			w := httptest.NewRecorder()

			h.HandleFleetCompliance(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var result map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				for _, key := range tt.expectKeys {
					if _, ok := result[key]; !ok {
						t.Errorf("expected key %q in response, got keys: %v", key, getKeys(result))
					}
				}

				// Verify summary structure
				summary, ok := result["summary"].(map[string]interface{})
				if !ok {
					t.Fatal("expected 'summary' to be an object")
				}
				if _, ok := summary["total_devices"]; !ok {
					t.Error("expected 'total_devices' in summary")
				}
				if _, ok := summary["compliant_devices"]; !ok {
					t.Error("expected 'compliant_devices' in summary")
				}
				if _, ok := summary["non_compliant_devices"]; !ok {
					t.Error("expected 'non_compliant_devices' in summary")
				}
				if _, ok := summary["unknown_devices"]; !ok {
					t.Error("expected 'unknown_devices' in summary")
				}
				if _, ok := summary["compliance_percent"]; !ok {
					t.Error("expected 'compliance_percent' in summary")
				}

				// Verify top_issues is an array
				issues, ok := result["top_issues"].([]interface{})
				if !ok {
					t.Error("expected 'top_issues' to be an array")
				}
				if tt.name == "fleet compliance with issues" && len(issues) != 2 {
					t.Errorf("got %d issues, want 2", len(issues))
				}
			}

			if tt.expectCode == http.StatusInternalServerError {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "failed to compute compliance" {
					t.Errorf("expected error 'failed to compute compliance', got %q", resp["error"])
				}
			}
		})
	}
}

func TestHandleFleetCompliancePercentageCalculation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "compliant", "non_compliant", "unknown",
		}).AddRow(100, 75, 20, 5))
	mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
		WillReturnRows(sqlmock.NewRows([]string{
			"oma_uri", "display_name", "fails",
		}))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance", nil)
	w := httptest.NewRecorder()

	h.HandleFleetCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	summary, ok := result["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("expected summary to be an object")
	}
	percent := summary["compliance_percent"].(float64)
	if percent != 75 {
		t.Errorf("compliance_percent = %v, want 75", percent)
	}
}

func TestHandleFleetComplianceZeroDivision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "compliant", "non_compliant", "unknown",
		}).AddRow(0, 0, 0, 0))
	mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
		WillReturnRows(sqlmock.NewRows([]string{
			"oma_uri", "display_name", "fails",
		}))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance", nil)
	w := httptest.NewRecorder()

	h.HandleFleetCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	summary := result["summary"].(map[string]interface{})
	total := int(summary["total_devices"].(float64))
	percent := int(summary["compliance_percent"].(float64))
	if total != 0 {
		t.Errorf("total_devices = %d, want 0", total)
	}
	if percent != 0 {
		t.Errorf("compliance_percent = %d, want 0 (no division by zero)", percent)
	}
}

// ── Tests for HandleDeviceCompliance ──────────────────────────────────────────

func TestHandleDeviceCompliance(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		url        string
		deviceID   string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
		expectKeys []string
	}{
		{
			name:     "device with mixed compliance",
			url:      "/api/compliance/dev-001",
			deviceID: "dev-001",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("LAPTOP-01"))
				mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "csp_name",
						"desired_value", "actual_value", "is_compliant", "checked_at",
					}).AddRow(
						"./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "BitLocker",
						"enabled", "enabled", 1, now,
					).AddRow(
						"./Vendor/MSFT/Policy/Config/WiFi", "WiFi Settings", "WiFi",
						"home", "work", 0, now,
					).AddRow(
						"./Vendor/MSFT/Policy/Config/Firewall", "Firewall", "Security",
						"enabled", "", nil, now,
					))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"device_id", "device_name", "compliant", "non_compliant", "unknown", "records"},
		},
		{
			name:     "device fully compliant",
			url:      "/api/compliance/dev-002",
			deviceID: "dev-002",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("LAPTOP-02"))
				mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "csp_name",
						"desired_value", "actual_value", "is_compliant", "checked_at",
					}).AddRow(
						"./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "BitLocker",
						"enabled", "enabled", 1, now,
					).AddRow(
						"./Vendor/MSFT/Policy/Config/WiFi", "WiFi Settings", "WiFi",
						"home", "home", 1, now,
					))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"device_id", "device_name", "compliant", "non_compliant", "unknown", "records"},
		},
		{
			name:     "device not found",
			url:      "/api/compliance/nonexistent",
			deviceID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnError(sql.ErrNoRows)
			},
			expectCode: http.StatusNotFound,
			expectKeys: []string{"error"},
		},
		{
			name:     "device with no compliance records",
			url:      "/api/compliance/dev-empty",
			deviceID: "dev-empty",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("Empty Device"))
				mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "csp_name",
						"desired_value", "actual_value", "is_compliant", "checked_at",
					}))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"device_id", "device_name", "compliant", "non_compliant", "unknown", "records"},
		},
		{
			name:     "device with empty name falls back to id",
			url:      "/api/compliance/dev-003",
			deviceID: "dev-003",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("dev-003"))
				mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
					WillReturnRows(sqlmock.NewRows([]string{
						"oma_uri", "display_name", "csp_name",
						"desired_value", "actual_value", "is_compliant", "checked_at",
					}).AddRow(
						"./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "BitLocker",
						"enabled", "enabled", 1, now,
					))
			},
			expectCode: http.StatusOK,
			expectKeys: []string{"device_id", "device_name", "compliant", "non_compliant", "unknown", "records"},
		},
		{
			name:     "database error on device lookup",
			url:      "/api/compliance/dev-err",
			deviceID: "dev-err",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnError(sql.ErrConnDone)
			},
			expectCode: http.StatusNotFound,
			expectKeys: []string{"error"},
		},
		{
			name:     "database error on compliance records",
			url:      "/api/compliance/dev-004",
			deviceID: "dev-004",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
					WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("Error Device"))
				mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
					WillReturnError(sql.ErrConnDone)
			},
			expectCode: http.StatusInternalServerError,
			expectKeys: []string{"error"},
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
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			r = setChiURLParamForCompliance(r, "deviceId", tt.deviceID)
			w := httptest.NewRecorder()

			h.HandleDeviceCompliance(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var result map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				for _, key := range tt.expectKeys {
					if _, ok := result[key]; !ok {
						t.Errorf("expected key %q in response, got keys: %v", key, getKeys(result))
					}
				}

				// Verify device_id
				deviceID, ok := result["device_id"].(string)
				if !ok {
					t.Error("expected 'device_id' to be a string")
				} else {
					if deviceID == "" {
						t.Error("device_id should not be empty")
					}
				}

				// Verify device_name
				deviceName, ok := result["device_name"].(string)
				if !ok {
					t.Error("expected 'device_name' to be a string")
				}

				// For device with empty name fallback
				if tt.name == "device with empty name falls back to id" {
					if deviceName == "" {
						t.Error("device_name should fall back to id when COALESCE returns NULL")
					}
				}

				// Verify counts
				compliant := int(result["compliant"].(float64))
				nonCompliant := int(result["non_compliant"].(float64))
				unknown := int(result["unknown"].(float64))

				// Verify records is an array
				records, ok := result["records"].([]interface{})
				if !ok {
					t.Error("expected 'records' to be an array")
				}

				// Verify counts match records
				if tt.name == "device with mixed compliance" {
					if compliant != 1 {
						t.Errorf("compliant = %d, want 1", compliant)
					}
					if nonCompliant != 1 {
						t.Errorf("non_compliant = %d, want 1", nonCompliant)
					}
					if unknown != 1 {
						t.Errorf("unknown = %d, want 1", unknown)
					}
					if len(records) != 3 {
						t.Errorf("records count = %d, want 3", len(records))
					}
				}

				if tt.name == "device fully compliant" {
					if compliant != 2 {
						t.Errorf("compliant = %d, want 2", compliant)
					}
					if nonCompliant != 0 {
						t.Errorf("non_compliant = %d, want 0", nonCompliant)
					}
					if unknown != 0 {
						t.Errorf("unknown = %d, want 0", unknown)
					}
				}

				if tt.name == "device with no compliance records" {
					if len(records) != 0 {
						t.Errorf("records count = %d, want 0", len(records))
					}
					if records == nil {
						t.Error("records should be empty array, not null")
					}
				}

				// Verify record structure
				if tt.name == "device with mixed compliance" && len(records) > 0 {
					rec := records[0].(map[string]interface{})
					if _, ok := rec["oma_uri"]; !ok {
						t.Error("record missing 'oma_uri'")
					}
					if _, ok := rec["display_name"]; !ok {
						t.Error("record missing 'display_name'")
					}
					if _, ok := rec["csp_name"]; !ok {
						t.Error("record missing 'csp_name'")
					}
					if _, ok := rec["desired_value"]; !ok {
						t.Error("record missing 'desired_value'")
					}
					if _, ok := rec["actual_value"]; !ok {
						t.Error("record missing 'actual_value'")
					}
					if _, ok := rec["is_compliant"]; !ok {
						t.Error("record missing 'is_compliant'")
					}
					if _, ok := rec["checked_at"]; !ok {
						t.Error("record missing 'checked_at'")
					}
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "device not found" {
					t.Errorf("expected error 'device not found', got %q", resp["error"])
				}
			}

			if tt.expectCode == http.StatusInternalServerError {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "failed to load compliance records" {
					t.Errorf("expected error 'failed to load compliance records', got %q", resp["error"])
				}
			}
		})
	}
}

func TestHandleDeviceComplianceRecordSorting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	now := time.Now()

	mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("Sort Device"))

	mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
		WillReturnRows(sqlmock.NewRows([]string{
			"oma_uri", "display_name", "csp_name",
			"desired_value", "actual_value", "is_compliant", "checked_at",
		}).AddRow(
			"./Vendor/MSFT/Policy/Config/A", "Alpha", "AAA", "val", "val", 0, now,
		).AddRow(
			"./Vendor/MSFT/Policy/Config/B", "Beta", "AAA", "val", "val", 0, now,
		).AddRow(
			"./Vendor/MSFT/Policy/Config/C", "Charlie", "BBB", "val", "val", 1, now,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance/dev-sort", nil)
	r = setChiURLParamForCompliance(r, "deviceId", "dev-sort")
	w := httptest.NewRecorder()

	h.HandleDeviceCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	records := result["records"].([]interface{})
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}

	rec0 := records[0].(map[string]interface{})
	rec1 := records[1].(map[string]interface{})
	rec2 := records[2].(map[string]interface{})

	isCompliant0 := rec0["is_compliant"].(bool)
	isCompliant1 := rec1["is_compliant"].(bool)
	isCompliant2 := rec2["is_compliant"].(bool)

	if isCompliant0 {
		t.Error("first record should be non-compliant")
	}
	if isCompliant1 {
		t.Error("second record should be non-compliant")
	}
	if !isCompliant2 {
		t.Error("third record should be compliant")
	}
}

func TestHandleDeviceComplianceIsCompliantNil(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	now := time.Now()

	mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("Unknown Device"))

	mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
		WillReturnRows(sqlmock.NewRows([]string{
			"oma_uri", "display_name", "csp_name",
			"desired_value", "actual_value", "is_compliant", "checked_at",
		}).AddRow(
			"./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "BitLocker",
			"enabled", "", nil, now,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance/dev-unknown", nil)
	r = setChiURLParamForCompliance(r, "deviceId", "dev-unknown")
	w := httptest.NewRecorder()

	h.HandleDeviceCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	unknown := int(result["unknown"].(float64))
	if unknown != 1 {
		t.Errorf("unknown = %d, want 1", unknown)
	}

	records := result["records"].([]interface{})
	rec := records[0].(map[string]interface{})
	isCompliant := rec["is_compliant"]
	if isCompliant != nil {
		t.Errorf("is_compliant should be nil for unknown, got %v", isCompliant)
	}
}

func TestHandleDeviceComplianceCOALESCEFallbacks(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	now := time.Now()
	omaURI := "./Vendor/MSFT/Policy/Config/BitLocker"

	mock.ExpectQuery("SELECT COALESCE\\(device_name.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{"device_name"}).AddRow("Fallback Device"))

	// COALESCE(pc.display_name, pc.oma_uri) returns oma_uri when display_name is NULL
	// COALESCE(pc.csp_name, '') returns '' when csp_name is NULL
	mock.ExpectQuery("SELECT.*pc.oma_uri.*FROM compliance_records.*ORDER BY").
		WillReturnRows(sqlmock.NewRows([]string{
			"oma_uri", "display_name", "csp_name",
			"desired_value", "actual_value", "is_compliant", "checked_at",
		}).AddRow(
			omaURI, omaURI, "", "", "", 1, now,
		))

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance/dev-fallback", nil)
	r = setChiURLParamForCompliance(r, "deviceId", "dev-fallback")
	w := httptest.NewRecorder()

	h.HandleDeviceCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	records := result["records"].([]interface{})
	rec := records[0].(map[string]interface{})

	displayName := rec["display_name"].(string)
	if displayName != omaURI {
		t.Errorf("display_name = %q, want %q (COALESCE fallback to oma_uri)", displayName, omaURI)
	}

	cspName := rec["csp_name"].(string)
	if cspName != "" {
		t.Errorf("csp_name should be empty string, got %q", cspName)
	}
}

// ── Table-driven tests for ComplianceRecord struct ────────────────────────────

func TestComplianceRecordJSON(t *testing.T) {
	tests := []struct {
		name   string
		record ComplianceRecord
		check  func(ComplianceRecord) error
	}{
		{
			name: "fully compliant record",
			record: ComplianceRecord{
				OMAURI:       "./Vendor/MSFT/Policy/Config/BitLocker",
				DisplayName:  "BitLocker",
				CSPName:      "BitLocker",
				DesiredValue: "enabled",
				ActualValue:  "enabled",
				IsCompliant:  boolPtr(true),
				CheckedAt:    "2026-01-01T00:00:00Z",
			},
			check: func(r ComplianceRecord) error {
				if !*r.IsCompliant {
					return errNonCompliant
				}
				return nil
			},
		},
		{
			name: "non-compliant record",
			record: ComplianceRecord{
				OMAURI:       "./Vendor/MSFT/Policy/Config/WiFi",
				DisplayName:  "WiFi Settings",
				CSPName:      "WiFi",
				DesiredValue: "home",
				ActualValue:  "work",
				IsCompliant:  boolPtr(false),
				CheckedAt:    "2026-01-01T00:00:00Z",
			},
			check: func(r ComplianceRecord) error {
				if *r.IsCompliant {
					return errCompliant
				}
				return nil
			},
		},
		{
			name: "unknown compliance",
			record: ComplianceRecord{
				OMAURI:       "./Vendor/MSFT/Policy/Config/Unknown",
				DisplayName:  "Unknown Policy",
				CSPName:      "",
				DesiredValue: "",
				ActualValue:  "",
				IsCompliant:  nil,
				CheckedAt:    "2026-01-01T00:00:00Z",
			},
			check: func(r ComplianceRecord) error {
				if r.IsCompliant != nil {
					return errHasCompliance
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.check(tt.record); err != nil {
				t.Errorf("check failed: %v", err)
			}

			data, err := json.Marshal(tt.record)
			if err != nil {
				t.Fatalf("failed to marshal ComplianceRecord: %v", err)
			}

			var decoded ComplianceRecord
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal ComplianceRecord: %v", err)
			}

			if decoded.OMAURI != tt.record.OMAURI {
				t.Errorf("OMAURI round-trip: got %q, want %q", decoded.OMAURI, tt.record.OMAURI)
			}
		})
	}
}

var (
	errNonCompliant  = errBool("expected non-compliant")
	errCompliant     = errBool("expected compliant")
	errHasCompliance = errBool("expected nil is_compliant")
)

type errBool string

func (e errBool) Error() string { return string(e) }

// ── Tests for FleetComplianceSummary struct ───────────────────────────────────

func TestFleetComplianceSummaryJSON(t *testing.T) {
	summary := FleetComplianceSummary{
		TotalDevices:        100,
		CompliantDevices:    80,
		NonCompliantDevices: 15,
		UnknownDevices:      5,
		CompliancePercent:   80,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal FleetComplianceSummary: %v", err)
	}

	var decoded FleetComplianceSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal FleetComplianceSummary: %v", err)
	}

	if decoded.TotalDevices != 100 {
		t.Errorf("TotalDevices = %d, want 100", decoded.TotalDevices)
	}
	if decoded.CompliantDevices != 80 {
		t.Errorf("CompliantDevices = %d, want 80", decoded.CompliantDevices)
	}
	if decoded.NonCompliantDevices != 15 {
		t.Errorf("NonCompliantDevices = %d, want 15", decoded.NonCompliantDevices)
	}
	if decoded.UnknownDevices != 5 {
		t.Errorf("UnknownDevices = %d, want 5", decoded.UnknownDevices)
	}
	if decoded.CompliancePercent != 80 {
		t.Errorf("CompliancePercent = %d, want 80", decoded.CompliancePercent)
	}
}

// ── Tests for HandleSyncDeviceWithNoAssignedPolicies ──────────────────────────

func TestHandleSyncDeviceNoAssignedPolicies(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "hardware_id", "device_name", "os_version", "os_build",
			"manufacturer", "model", "serial_number", "enrolled_at", "enrolled_by",
			"last_checkin", "compliance_status", "is_active",
		}).AddRow(
			"dev-001", "hw-123", "LAPTOP-01", "10.0.19045", "19045",
			"Lenovo", "ThinkPad X1", "SN001", time.Now(), "admin@example.com",
			time.Now(), "compliant", 1,
		))

	mock.ExpectQuery("SELECT DISTINCT pc.oma_uri.*FROM profile_settings").
		WillReturnRows(sqlmock.NewRows([]string{"oma_uri"}))

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPost, "/api/devices/dev-001/sync", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleSyncDevice(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if resp["status"] != "sync_queued" {
		t.Errorf("status = %v, want %q", resp["status"], "sync_queued")
	}
	if queued, ok := resp["commands_queued"].(float64); ok && int(queued) != 0 {
		t.Errorf("commands_queued = %v, want 0", queued)
	}
}

// ── Tests for HandleWipeDeviceWithEnqueueError ─────────────────────────────────

func TestHandleWipeDeviceEnqueueError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "hardware_id", "device_name", "os_version", "os_build",
			"manufacturer", "model", "serial_number", "enrolled_at", "enrolled_by",
			"last_checkin", "compliance_status", "is_active",
		}).AddRow(
			"dev-001", "hw-123", "LAPTOP-01", "10.0.19045", "19045",
			"Lenovo", "ThinkPad X1", "SN001", time.Now(), "admin@example.com",
			time.Now(), "compliant", 1,
		))

	mock.ExpectQuery("SELECT.*FROM command_queue").
		WillReturnError(sql.ErrConnDone)

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPost, "/api/devices/dev-001/wipe", bytes.NewReader([]byte(`{"confirm":true}`)))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleWipeDevice(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "failed to queue wipe command" {
		t.Errorf("expected error 'failed to queue wipe command', got %q", resp["error"])
	}
}

// ── Tests for HandleLockDeviceWithEnqueueError ─────────────────────────────────

func TestHandleLockDeviceEnqueueError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "hardware_id", "device_name", "os_version", "os_build",
			"manufacturer", "model", "serial_number", "enrolled_at", "enrolled_by",
			"last_checkin", "compliance_status", "is_active",
		}).AddRow(
			"dev-001", "hw-123", "LAPTOP-01", "10.0.19045", "19045",
			"Lenovo", "ThinkPad X1", "SN001", time.Now(), "admin@example.com",
			time.Now(), "compliant", 1,
		))

	mock.ExpectQuery("SELECT.*FROM command_queue").
		WillReturnError(sql.ErrConnDone)

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPost, "/api/devices/dev-001/lock", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleLockDevice(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["error"] != "failed to queue lock command" {
		t.Errorf("expected error 'failed to queue lock command', got %q", resp["error"])
	}
}

// ── Tests for HandleUnenrollDeviceWithCertRevocation ──────────────────────────

func TestHandleUnenrollDeviceRevokesCertificates(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE devices SET is_active = 0 WHERE id = \\?").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE certificates SET revoked = 1 WHERE device_id = \\?").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE command_queue SET status = 'cancelled' WHERE device_id = \\? AND status = 'pending'").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO audit_log").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodDelete, "/api/devices/dev-001", nil)
	r = r.WithContext(ctx)
	r = setChiURLParamForCompliance(r, "id", "dev-001")
	r.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	h.HandleUnenrollDevice(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["status"] != "unenrolled" {
		t.Errorf("status = %q, want %q", resp["status"], "unenrolled")
	}
}

// ── Tests for HandleSyncDeviceWithEnqueueFailures ─────────────────────────────

func TestHandleSyncDevicePartialEnqueueFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE id = \\?").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "hardware_id", "device_name", "os_version", "os_build",
			"manufacturer", "model", "serial_number", "enrolled_at", "enrolled_by",
			"last_checkin", "compliance_status", "is_active",
		}).AddRow(
			"dev-001", "hw-123", "LAPTOP-01", "10.0.19045", "19045",
			"Lenovo", "ThinkPad X1", "SN001", time.Now(), "admin@example.com",
			time.Now(), "compliant", 1,
		))

	mock.ExpectQuery("SELECT DISTINCT pc.oma_uri.*FROM profile_settings").
		WillReturnRows(sqlmock.NewRows([]string{"oma_uri"}).
			AddRow("./Vendor/MSFT/Policy/Config/BitLocker").
			AddRow("./Vendor/MSFT/Policy/Config/WiFi"))

	mock.ExpectQuery("SELECT.*FROM command_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(50))

	mock.ExpectQuery("SELECT.*FROM command_queue").
		WillReturnError(sql.ErrConnDone)

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPost, "/api/devices/dev-001/sync", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleSyncDevice(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if resp["status"] != "sync_queued" {
		t.Errorf("status = %v, want %q", resp["status"], "sync_queued")
	}
}

// ── Tests for decodeBody edge cases ───────────────────────────────────────────

func TestDecodeBodyEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		expectOK   bool
		targetType interface{}
	}{
		{
			name:       "valid JSON object",
			body:       `{"key":"value"}`,
			expectOK:   true,
			targetType: &map[string]string{},
		},
		{
			name:       "valid JSON number",
			body:       `42`,
			expectOK:   true,
			targetType: &json.RawMessage{},
		},
		{
			name:       "valid JSON boolean",
			body:       `true`,
			expectOK:   true,
			targetType: &json.RawMessage{},
		},
		{
			name:       "valid JSON null",
			body:       `null`,
			expectOK:   true,
			targetType: &json.RawMessage{},
		},
		{
			name:       "trailing comma invalid JSON",
			body:       `{"key":"value",}`,
			expectOK:   false,
			targetType: &map[string]string{},
		},
		{
			name:       "single quote invalid JSON",
			body:       `{'key':'value'}`,
			expectOK:   false,
			targetType: &map[string]string{},
		},
		{
			name:       "undefined invalid JSON",
			body:       `{key: value}`,
			expectOK:   false,
			targetType: &map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Body = &readCloser{reader: []byte(tt.body), position: 0}

			ok := decodeBody(w, r, tt.targetType)
			if ok != tt.expectOK {
				t.Errorf("decodeBody() = %v, want %v", ok, tt.expectOK)
			}

			if !tt.expectOK && w.Code != http.StatusBadRequest {
				t.Errorf("expected status %d for invalid body, got %d", http.StatusBadRequest, w.Code)
			}
		})
	}
}

// ── Tests for respond with various types ───────────────────────────────────────

func TestRespondWithVariousTypes(t *testing.T) {
	tests := []struct {
		name  string
		data  interface{}
		check func(http.ResponseWriter) error
	}{
		{
			name: "string map",
			data: map[string]string{"key": "value"},
			check: func(w http.ResponseWriter) error {
				body := w.(*httptest.ResponseRecorder).Body.String()
				if body == "" {
					return errors.New("empty body")
				}
				return nil
			},
		},
		{
			name: "slice",
			data: []string{"a", "b", "c"},
			check: func(w http.ResponseWriter) error {
				body := w.(*httptest.ResponseRecorder).Body.String()
				if body == "" {
					return errors.New("empty body")
				}
				return nil
			},
		},
		{
			name: "empty slice",
			data: []string{},
			check: func(w http.ResponseWriter) error {
				body := w.(*httptest.ResponseRecorder).Body.String()
				if body == "" {
					return errors.New("empty body")
				}
				return nil
			},
		},
		{
			name: "struct",
			data: struct{ Name string }{Name: "test"},
			check: func(w http.ResponseWriter) error {
				body := w.(*httptest.ResponseRecorder).Body.String()
				if body == "" {
					return errors.New("empty body")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			respond(w, http.StatusOK, tt.data)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			if err := tt.check(w); err != nil {
				t.Errorf("check failed: %v", err)
			}
		})
	}
}

// ── Tests for HandleGetDeviceCommandsResultInfoMapping ────────────────────────

func TestHandleGetDeviceCommandsResultInfoMapping(t *testing.T) {
	tests := []struct {
		resultCode   string
		expectedInfo string
	}{
		{"406", "Not Acceptable (Device security policy or hardware restriction)"},
		{"405", "Method Not Allowed (URI exists but doesn't support this action)"},
		{"404", "Not Found (The device doesn't have this feature)"},
		{"200", ""},
		{"", ""},
		{"500", ""},
	}

	for _, tt := range tests {
		t.Run("result_"+tt.resultCode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			mock.ExpectQuery("SELECT.*FROM command_queue").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "command_type", "oma_uri", "status", "created_at", "sent_at",
					"completed_at", "result_code", "result_data",
				}).AddRow(
					100, "Replace", "./Vendor/MSFT/Policy/Config/Test", "success",
					time.Now(), time.Now(), time.Now(), tt.resultCode, "",
				))

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/devices/dev-001/commands", nil)
			w := httptest.NewRecorder()

			h.HandleGetDeviceCommands(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			commands := result["commands"].([]interface{})
			cmd := commands[0].(map[string]interface{})
			resultInfo := cmd["result_info"].(string)

			if resultInfo != tt.expectedInfo {
				t.Errorf("result_info = %q, want %q", resultInfo, tt.expectedInfo)
			}
		})
	}
}

// ── Tests for policyOps injection ─────────────────────────────────────────────

func TestPolicyOpsInjection(t *testing.T) {
	// Save originals
	origApplyDevice := policyOps.ApplyDevice
	origApplyProfile := policyOps.ApplyProfile
	defer func() {
		policyOps.ApplyDevice = origApplyDevice
		policyOps.ApplyProfile = origApplyProfile
	}()

	var calledDevice, calledProfile bool
	var deviceID, profileID string

	policyOps.ApplyDevice = func(db *sql.DB, id string) {
		calledDevice = true
		deviceID = id
	}
	policyOps.ApplyProfile = func(db *sql.DB, id string) {
		calledProfile = true
		profileID = id
	}

	// ApplyDevice is called from HandleSyncDevice
	{
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("couldn't create sqlmock: %s", err)
		}
		defer db.Close()

		mock.ExpectQuery("SELECT.*FROM devices WHERE id = \\?").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "hardware_id", "device_name", "os_version", "os_build",
				"manufacturer", "model", "serial_number", "enrolled_at", "enrolled_by",
				"last_checkin", "compliance_status", "is_active",
			}).AddRow(
				"dev-001", "hw-123", "LAPTOP-01", "10.0.19045", "19045",
				"Lenovo", "ThinkPad X1", "SN001", time.Now(), "admin@example.com",
				time.Now(), "compliant", 1,
			))
		mock.ExpectQuery("SELECT DISTINCT pc.oma_uri.*FROM profile_settings").
			WillReturnRows(sqlmock.NewRows([]string{"oma_uri"}))
		mock.ExpectExec("INSERT INTO audit_log").
			WillReturnResult(sqlmock.NewResult(1, 1))

		h := NewHandler(db)
		ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
		r := httptest.NewRequest(http.MethodPost, "/api/devices/dev-001/sync", nil)
		r = r.WithContext(ctx)
		r = setChiURLParamForCompliance(r, "id", "dev-001")
		w := httptest.NewRecorder()

		h.HandleSyncDevice(w, r)

		if !calledDevice {
			t.Error("ApplyDevice should have been called by HandleSyncDevice")
		}
		if deviceID != "dev-001" {
			t.Errorf("ApplyDevice called with deviceID %q, want %q", deviceID, "dev-001")
		}
	}

	// ApplyProfile is called from HandleUpdateProfile
	{
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("couldn't create sqlmock: %s", err)
		}
		defer db.Close()

		mock.ExpectBegin()
		mock.ExpectExec("UPDATE profiles SET").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("DELETE FROM profile_settings WHERE profile_id = \\?").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO audit_log").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		mock.ExpectQuery("SELECT.*FROM profiles WHERE id = \\?").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "name", "description", "created_by", "created_at", "updated_at",
			}).AddRow("prof-1", "Test", "", "admin@example.com", time.Now(), time.Now()))
		mock.ExpectQuery("SELECT.*FROM profile_settings.*WHERE ps.profile_id = \\?").
			WillReturnRows(sqlmock.NewRows([]string{
				"catalog_id", "oma_uri", "display_name", "description", "data_type",
				"desired_value", "allowed_values",
			}))

		h := NewHandler(db)
		ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
		r := httptest.NewRequest(http.MethodPut, "/api/profiles/prof-1", bytes.NewReader([]byte(`{"name":"Test","settings":[]}`)))
		r = r.WithContext(ctx)
		r = setChiURLParamForCompliance(r, "id", "prof-1")
		w := httptest.NewRecorder()

		h.HandleUpdateProfile(w, r)

		// Give goroutine time to run
		time.Sleep(50 * time.Millisecond)

		if !calledProfile {
			t.Error("ApplyProfile should have been called by HandleUpdateProfile")
		}
		if profileID != "prof-1" {
			t.Errorf("ApplyProfile called with profileID %q, want %q", profileID, "prof-1")
		}
	}
}

// ── Tests for HandleListCatalogPaginationEdgeCases ────────────────────────────

func TestHandleListCatalogPaginationEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantLimit int
	}{
		{
			name:      "limit zero defaults to 100",
			url:       "/api/catalog?limit=0",
			wantLimit: 100,
		},
		{
			name:      "limit exactly 500 allowed",
			url:       "/api/catalog?limit=500",
			wantLimit: 500,
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

			mock.ExpectQuery("SELECT.*FROM policy_catalog WHERE is_deprecated = 0.*LIMIT").
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

// ── Tests for HandleCreateGroupWithUUIDGeneration ─────────────────────────────

func TestHandleCreateGroupUUIDGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectExec(".").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(".").WillReturnResult(sqlmock.NewResult(1, 1))

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPost, "/api/groups", bytes.NewReader([]byte(`{"name":"Test Group","description":"test"}`)))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleCreateGroup(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp Group
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(resp.ID) < 36 {
		t.Errorf("expected UUID-like ID with at least 36 chars, got %d", len(resp.ID))
	}
}

// ── Tests for HandleUpdateProfileWithEmptySettings ────────────────────────────

func TestHandleUpdateProfileEmptySettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	// UPDATE profiles
	mock.ExpectExec("UPDATE profiles SET").WillReturnResult(sqlmock.NewResult(1, 1))
	// DELETE FROM profile_settings
	mock.ExpectExec("DELETE FROM profile_settings WHERE profile_id = \\?").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// INSERT INTO audit_log (before COMMIT)
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	// loadProfile: SELECT FROM profiles (after COMMIT)
	mock.ExpectQuery("SELECT.*FROM profiles WHERE id =").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "description", "created_by", "created_at", "updated_at",
		}).AddRow("prof-1", "Updated", "", "admin@example.com", time.Now(), time.Now()))
	// loadProfile: SELECT FROM profile_settings (after COMMIT)
	mock.ExpectQuery("SELECT.*FROM profile_settings.*JOIN policy_catalog").
		WillReturnRows(sqlmock.NewRows([]string{
			"catalog_id", "oma_uri", "display_name", "description", "data_type",
			"desired_value", "allowed_values",
		}))

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPut, "/api/profiles/prof-1", bytes.NewReader([]byte(`{
		"name": "Updated",
		"description": "",
		"settings": []
	}`)))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleUpdateProfile(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for HandleAssignDeviceToGroupWithErrors ─────────────────────────────

func TestHandleAssignDeviceToGroupPartialFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mock.ExpectExec(".").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(".").WillReturnError(sql.ErrConnDone)
	mock.ExpectExec(".").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(".").WillReturnResult(sqlmock.NewResult(1, 1))

	h := NewHandler(db)
	ctx := contextWithAuth(context.Background(), "admin@example.com", "admin")
	r := httptest.NewRequest(http.MethodPut, "/api/groups/group-1/devices", bytes.NewReader([]byte(`{
		"device_ids": ["dev-1", "dev-2", "dev-3"],
		"action": "add"
	}`)))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleAssignDeviceToGroup(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// boolPtr returns a pointer to the given bool.
func boolPtr(b bool) *bool {
	return &b
}

// ── Tests for HandleFleetComplianceTopIssues ──────────────────────────────────

func TestHandleFleetComplianceTopIssues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT.*FROM devices WHERE is_active = 1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "compliant", "non_compliant", "unknown",
		}).AddRow(100, 80, 15, 5))

	// Return exactly 10 issues (LIMIT 10 in SQL)
	rows := sqlmock.NewRows([]string{"oma_uri", "display_name", "fails"})
	for i := 1; i <= 10; i++ {
		rows.AddRow(
			"./Vendor/MSFT/Policy/Config/Test"+fmt.Sprintf("%d", i),
			"Issue "+fmt.Sprintf("%d", i),
			i,
		)
	}
	mock.ExpectQuery("SELECT pc.oma_uri.*FROM compliance_records.*GROUP BY").
		WillReturnRows(rows)

	h := NewHandler(db)
	r := httptest.NewRequest(http.MethodGet, "/api/compliance", nil)
	w := httptest.NewRecorder()

	h.HandleFleetCompliance(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	issues := result["top_issues"].([]interface{})
	if len(issues) != 10 {
		t.Errorf("top_issues count = %d, want 10", len(issues))
	}
}