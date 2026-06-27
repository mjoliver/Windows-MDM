package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ── Tests for HandleListProfiles ──────────────────────────────────────────────

func TestHandleListProfiles(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(sqlmock.Sqlmock)
		expectCode  int
		expectCount int
	}{
		{
			name: "list profiles",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow(
					"prof-1", "BitLocker Policy", "Enable BitLocker encryption",
					"admin@example.com", time.Now(), time.Now(),
				).AddRow(
					"prof-2", "WiFi Policy", "Configure WiFi settings",
					"admin@example.com", time.Now(), time.Now(),
				))
			},
			expectCode:  http.StatusOK,
			expectCount: 2,
		},
		{
			name: "empty profile list",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}))
			},
			expectCode:  http.StatusOK,
			expectCount: 0,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnError(sql.ErrConnDone)
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
			r := httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
			w := httptest.NewRecorder()

			h.HandleListProfiles(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var profiles []Profile
				if err := json.Unmarshal(w.Body.Bytes(), &profiles); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(profiles) != tt.expectCount {
					t.Errorf("got %d profiles, want %d", len(profiles), tt.expectCount)
				}
				if tt.expectCount == 2 {
					if profiles[0].Name != "BitLocker Policy" {
						t.Errorf("first profile name = %q, want %q", profiles[0].Name, "BitLocker Policy")
					}
				}
			}
		})
	}
}

// ── Tests for HandleGetProfile ────────────────────────────────────────────────

func TestHandleGetProfile(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name: "profile with settings",
			url:  "/api/profiles/prof-1",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Profile row
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow(
					"prof-1", "BitLocker Policy", "Enable BitLocker",
					"admin@example.com", time.Now(), time.Now(),
				))
				// Settings rows
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}).AddRow(
					1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
					"Enable encryption", "string", "enabled", `["enabled","disabled"]`,
				).AddRow(
					2, "./Vendor/MSFT/Policy/Config/WiFi", "WiFi",
					"Configure WiFi", "string", "home", `["home","work"]`,
				))
			},
			expectCode: http.StatusOK,
		},
		{
			name: "profile without settings",
			url:  "/api/profiles/prof-2",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow(
					"prof-2", "Empty Policy", "",
					"admin@example.com", time.Now(), time.Now(),
				))
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}))
			},
			expectCode: http.StatusOK,
		},
		{
			name: "profile not found",
			url:  "/api/profiles/nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnError(sql.ErrNoRows)
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
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			w := httptest.NewRecorder()

			h.HandleGetProfile(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var profile Profile
				if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if profile.ID == "" {
					t.Error("expected non-empty profile ID")
				}
				if tt.name == "profile with settings" && len(profile.Settings) != 2 {
					t.Errorf("got %d settings, want 2", len(profile.Settings))
				}
				if tt.name == "profile without settings" && len(profile.Settings) != 0 {
					t.Errorf("got %d settings, want 0", len(profile.Settings))
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "profile not found" {
					t.Errorf("expected error 'profile not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleCreateProfile ─────────────────────────────────────────────

func TestHandleCreateProfile(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		body       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
	{
			name:  "successful creation with settings",
			email: "admin@example.com",
			body: `{
				"name": "New Policy",
				"description": "A new configuration profile",
				"settings": [
					{"catalog_id": 1, "desired_value": "enabled"},
					{"catalog_id": 2, "desired_value": "home"}
				]
			}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				// INSERT INTO profiles
				mock.ExpectExec("INSERT INTO profiles").WillReturnResult(sqlmock.NewResult(1, 1))
				// INSERT INTO profile_settings (x2)
				mock.ExpectExec("INSERT INTO profile_settings").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec("INSERT INTO profile_settings").WillReturnResult(sqlmock.NewResult(1, 1))
				// INSERT INTO audit_log
				mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				// loadProfile: SELECT FROM profiles
				mock.ExpectQuery("SELECT.*FROM profiles WHERE id =").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow("prof-new", "New Policy", "A new configuration profile", "admin@example.com", time.Now(), time.Now()))
				// loadProfile: SELECT FROM profile_settings JOIN policy_catalog
				mock.ExpectQuery("SELECT.*FROM profile_settings.*JOIN policy_catalog").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}).AddRow(1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "", "string", "enabled", nil).
					AddRow(2, "./Vendor/MSFT/Policy/Config/WiFi", "WiFi", "", "string", "home", nil))
			},
			expectCode: http.StatusCreated,
		},
	{
			name:  "successful creation without settings",
			email: "admin@example.com",
			body: `{
				"name": "Empty Policy",
				"description": "A policy with no settings"
			}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				// INSERT INTO profiles
				mock.ExpectExec("INSERT INTO profiles").WillReturnResult(sqlmock.NewResult(1, 1))
				// INSERT INTO audit_log
				mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				// loadProfile: SELECT FROM profiles
				mock.ExpectQuery("SELECT.*FROM profiles WHERE id =").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow("prof-new", "Empty Policy", "A policy with no settings", "admin@example.com", time.Now(), time.Now()))
				// loadProfile: SELECT FROM profile_settings
				mock.ExpectQuery("SELECT.*FROM profile_settings.*JOIN policy_catalog").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}))
			},
			expectCode: http.StatusCreated,
		},
		{
			name:       "empty name",
			email:      "admin@example.com",
			body:       `{"name":"","description":"test"}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			email:      "admin@example.com",
			body:       `{invalid}`,
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPost, "/api/profiles", bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleCreateProfile(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusCreated {
				var profile Profile
				if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if profile.Name != "New Policy" && profile.Name != "Empty Policy" {
					t.Errorf("name = %q, want 'New Policy' or 'Empty Policy'", profile.Name)
				}
			}

			if tt.expectCode == http.StatusBadRequest {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] == "" {
					t.Error("expected error message")
				}
			}
		})
	}
}

// ── Tests for HandleUpdateProfile ─────────────────────────────────────────────

func TestHandleUpdateProfile(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		email      string
		body       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
	{
			name:  "successful update",
			url:   "/api/profiles/prof-1",
			email: "admin@example.com",
			body: `{
				"name": "Updated Policy",
				"description": "Updated description",
				"settings": [
					{"catalog_id": 1, "desired_value": "disabled"}
				]
			}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				// UPDATE profiles
				mock.ExpectExec("UPDATE profiles SET").WillReturnResult(sqlmock.NewResult(1, 1))
				// DELETE FROM profile_settings
				mock.ExpectExec("DELETE FROM profile_settings").WillReturnResult(sqlmock.NewResult(0, 0))
				// INSERT INTO profile_settings
				mock.ExpectExec("INSERT INTO profile_settings").WillReturnResult(sqlmock.NewResult(1, 1))
				// INSERT INTO audit_log
				mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				// loadProfile: SELECT FROM profiles
				mock.ExpectQuery("SELECT.*FROM profiles WHERE id =").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow("prof-1", "Updated Policy", "Updated description", "admin@example.com", time.Now(), time.Now()))
				// loadProfile: SELECT FROM profile_settings
				mock.ExpectQuery("SELECT.*FROM profile_settings.*JOIN policy_catalog").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}).AddRow(1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker", "", "string", "disabled", nil))
			},
			expectCode: http.StatusOK,
		},
	{
			name:  "update with empty name keeps existing",
			url:   "/api/profiles/prof-1",
			email: "admin@example.com",
			body: `{
				"name": "",
				"description": "New desc",
				"settings": []
			}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				// First query to get existing name/description (since name is empty)
				mock.ExpectQuery("SELECT name, description FROM profiles WHERE id =").WillReturnRows(sqlmock.NewRows([]string{"name", "description"}).AddRow("Original Name", "Original desc"))
				// UPDATE profiles
				mock.ExpectExec("UPDATE profiles SET").WillReturnResult(sqlmock.NewResult(1, 1))
				// DELETE FROM profile_settings
				mock.ExpectExec("DELETE FROM profile_settings").WillReturnResult(sqlmock.NewResult(0, 0))
				// INSERT INTO audit_log
				mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				// loadProfile: SELECT FROM profiles
				mock.ExpectQuery("SELECT.*FROM profiles WHERE id =").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow("prof-1", "Original Name", "Original desc", "admin@example.com", time.Now(), time.Now()))
				// loadProfile: SELECT FROM profile_settings
				mock.ExpectQuery("SELECT.*FROM profile_settings.*JOIN policy_catalog").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}))
			},
			expectCode: http.StatusOK,
		},
		{
			name:  "profile not found",
			url:   "/api/profiles/nonexistent",
			email: "admin@example.com",
			body:  `{"name":"Updated","description":"desc","settings":[]}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectRollback()
			},
			expectCode: http.StatusNotFound,
		},
		{
			name:       "invalid JSON",
			url:        "/api/profiles/prof-1",
			email:      "admin@example.com",
			body:       `{invalid}`,
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPut, tt.url, bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleUpdateProfile(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var profile Profile
				if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if profile.ID != "prof-1" {
					t.Errorf("profile ID = %q, want %q", profile.ID, "prof-1")
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "profile not found" {
					t.Errorf("expected error 'profile not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleDeleteProfile ─────────────────────────────────────────────

func TestHandleDeleteProfile(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		email      string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name:  "successful delete",
			url:   "/api/profiles/prof-1",
			email: "admin@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusOK,
		},
		{
			name:  "profile not found",
			url:   "/api/profiles/nonexistent",
			email: "admin@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusNotFound,
		},
		{
			name:  "database error",
			url:   "/api/profiles/prof-1",
			email: "admin@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnError(sql.ErrConnDone)
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
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodDelete, tt.url, nil)
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleDeleteProfile(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["status"] != "deleted" {
					t.Errorf("status = %q, want %q", resp["status"], "deleted")
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "profile not found" {
					t.Errorf("expected error 'profile not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for loadProfile helper ──────────────────────────────────────────────

func TestLoadProfile(t *testing.T) {
	tests := []struct {
		name      string
		profileID string
		setupMock func(sqlmock.Sqlmock)
		expectErr bool
	}{
		{
			name:      "profile with settings and allowed values",
			profileID: "prof-1",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow(
					"prof-1", "Test Profile", "Description", "admin@example.com",
					time.Now(), time.Now(),
				))
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}).AddRow(
					1, "./Vendor/MSFT/Policy/Config/BitLocker", "BitLocker",
					"Encrypt drives", "string", "enabled", `["enabled","disabled"]`,
				))
			},
			expectErr: false,
		},
		{
			name:      "profile not found",
			profileID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnError(sql.ErrNoRows)
			},
			expectErr: true,
		},
		{
			name:      "profile without settings",
			profileID: "prof-empty",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_by", "created_at", "updated_at",
				}).AddRow(
					"prof-empty", "Empty Profile", "", "admin@example.com",
					time.Now(), time.Now(),
				))
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"catalog_id", "oma_uri", "display_name", "description", "data_type",
					"desired_value", "allowed_values",
				}))
			},
			expectErr: false,
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
			ctx := context.Background()
			r := httptest.NewRequest(http.MethodGet, "/api/profiles/"+tt.profileID, nil)
			r = r.WithContext(ctx)

			profile, err := h.loadProfile(r, tt.profileID)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if profile.ID != tt.profileID && profile.ID != "prof-empty" {
				// For "profile with settings" test, the ID should match
				if tt.name == "profile with settings and allowed values" && profile.ID != "prof-1" {
					t.Errorf("profile.ID = %q, want %q", profile.ID, "prof-1")
				}
			}
			if tt.name == "profile with settings and allowed values" && len(profile.Settings) != 1 {
				t.Errorf("got %d settings, want 1", len(profile.Settings))
			}
			if tt.name == "profile without settings" && len(profile.Settings) != 0 {
				t.Errorf("got %d settings, want 0", len(profile.Settings))
			}
		})
	}
}
