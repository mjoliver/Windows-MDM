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

// ── Tests for HandleListGroups ────────────────────────────────────────────────

func TestHandleListGroups(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(sqlmock.Sqlmock)
		expectCode  int
		expectCount int
	}{
		{
			name: "list groups with members and profiles",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_at", "device_count", "profile_count",
				}).AddRow(
					"group-1", "Engineering", "Engineering devices", time.Now(), 5, 2,
				).AddRow(
					"group-2", "HR", "HR devices", time.Now(), 3, 1,
				))
			},
			expectCode:  http.StatusOK,
			expectCount: 2,
		},
		{
			name: "empty group list",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "description", "created_at", "device_count", "profile_count",
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

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			r := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
			w := httptest.NewRecorder()

			h.HandleListGroups(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var groups []Group
				if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(groups) != tt.expectCount {
					t.Errorf("got %d groups, want %d", len(groups), tt.expectCount)
				}
				if tt.expectCount == 2 {
					if groups[0].Name != "Engineering" {
						t.Errorf("first group name = %q, want %q", groups[0].Name, "Engineering")
					}
					if groups[0].DeviceCount != 5 {
						t.Errorf("first group device_count = %d, want 5", groups[0].DeviceCount)
					}
					if groups[1].ProfileCount != 1 {
						t.Errorf("second group profile_count = %d, want 1", groups[1].ProfileCount)
					}
				}
			}
		})
	}
}

// ── Tests for HandleCreateGroup ───────────────────────────────────────────────

func TestHandleCreateGroup(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		body       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name:  "successful creation",
			email: "admin@example.com",
			body:  `{"name":"Test Group","description":"A test group"}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusCreated,
		},
		{
			name:       "empty name",
			email:      "admin@example.com",
			body:       `{"name":"","description":"A test group"}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			email:      "admin@example.com",
			body:       `{invalid}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "missing body",
			email:      "admin@example.com",
			body:       ``,
			expectCode: http.StatusBadRequest,
		},
		{
			name:  "database error",
			email: "admin@example.com",
			body:  `{"name":"Test Group","description":"A test group"}`,
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

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPost, "/api/groups", bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleCreateGroup(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusCreated {
				var resp Group
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.Name != "Test Group" {
					t.Errorf("name = %q, want %q", resp.Name, "Test Group")
				}
				if resp.Description != "A test group" {
					t.Errorf("description = %q, want %q", resp.Description, "A test group")
				}
				if resp.ID == "" {
					t.Error("expected non-empty ID")
				}
			}

			if tt.expectCode == http.StatusBadRequest {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] == "" {
					t.Error("expected error message in response")
				}
			}
		})
	}
}

// ── Tests for HandleUpdateGroup ───────────────────────────────────────────────

func TestHandleUpdateGroup(t *testing.T) {
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
			url:   "/api/groups/group-1",
			email: "admin@example.com",
			body:  `{"name":"Updated Group","description":"Updated description"}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusOK,
		},
		{
			name:  "group not found",
			url:   "/api/groups/nonexistent",
			email: "admin@example.com",
			body:  `{"name":"Updated Group","description":"Updated description"}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusNotFound,
		},
		{
			name:       "invalid JSON",
			url:        "/api/groups/group-1",
			email:      "admin@example.com",
			body:       `{invalid}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:  "database error",
			url:   "/api/groups/group-1",
			email: "admin@example.com",
			body:  `{"name":"Updated Group","description":"Updated description"}`,
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

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPut, tt.url, bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleUpdateGroup(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["status"] != "updated" {
					t.Errorf("status = %q, want %q", resp["status"], "updated")
				}
			}

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "group not found" {
					t.Errorf("expected error 'group not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleDeleteGroup ───────────────────────────────────────────────

func TestHandleDeleteGroup(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		email      string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name:  "successful delete",
			url:   "/api/groups/group-1",
			email: "admin@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusOK,
		},
		{
			name:  "group not found",
			url:   "/api/groups/nonexistent",
			email: "admin@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusNotFound,
		},
		{
			name:  "database error",
			url:   "/api/groups/group-1",
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

			h.HandleDeleteGroup(w, r)

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
				if resp["error"] != "group not found" {
					t.Errorf("expected error 'group not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleAssignDeviceToGroup ───────────────────────────────────────

func TestHandleAssignDeviceToGroup(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		email      string
		body       string
		setupMock  func(sqlmock.Sqlmock)
		expectCode int
	}{
		{
			name:  "add devices successfully",
			url:   "/api/groups/group-1/devices",
			email: "admin@example.com",
			body:  `{"device_ids":["dev-1","dev-2"],"action":"add"}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusOK,
		},
		{
			name:  "remove devices successfully",
			url:   "/api/groups/group-1/devices",
			email: "admin@example.com",
			body:  `{"device_ids":["dev-1"],"action":"remove"}`,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(".").WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectCode: http.StatusOK,
		},
		{
			name:       "invalid action",
			url:        "/api/groups/group-1/devices",
			email:      "admin@example.com",
			body:       `{"device_ids":["dev-1"],"action":"invalid"}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			url:        "/api/groups/group-1/devices",
			email:      "admin@example.com",
			body:       `{invalid}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:  "group not found",
			url:   "/api/groups/nonexistent/devices",
			email: "admin@example.com",
			body:  `{"device_ids":["dev-1"],"action":"add"}`,
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

			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPut, tt.url, bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleAssignDeviceToGroup(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["status"] != "ok" {
					t.Errorf("status = %v, want %q", resp["status"], "ok")
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

			if tt.expectCode == http.StatusNotFound {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != "group not found" {
					t.Errorf("expected error 'group not found', got %q", resp["error"])
				}
			}
		})
	}
}

// ── Tests for HandleAssignProfileToGroup ──────────────────────────────────────

func TestHandleAssignProfileToGroup(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		email      string
		body       string
		expectCode int
	}{
		{
			name:       "add profiles",
			url:        "/api/groups/group-1/profiles",
			email:      "admin@example.com",
			body:       `{"profile_ids":["prof-1","prof-2"],"action":"add"}`,
			expectCode: http.StatusOK,
		},
		{
			name:       "remove profiles",
			url:        "/api/groups/group-1/profiles",
			email:      "admin@example.com",
			body:       `{"profile_ids":["prof-1"],"action":"remove"}`,
			expectCode: http.StatusOK,
		},
		{
			name:       "invalid action",
			url:        "/api/groups/group-1/profiles",
			email:      "admin@example.com",
			body:       `{"profile_ids":["prof-1"],"action":"invalid"}`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			url:        "/api/groups/group-1/profiles",
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

			if tt.expectCode == http.StatusOK {
				// Expect 2 exec calls (one per profile) + audit log
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec(".").WithArgs().WillReturnResult(sqlmock.NewResult(1, 1))
			}

			h := NewHandler(db)
			ctx := contextWithAuth(context.Background(), tt.email, "admin")
			r := httptest.NewRequest(http.MethodPut, tt.url, bytes.NewReader([]byte(tt.body)))
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleAssignProfileToGroup(w, r)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectCode, w.Body.String())
			}

			if tt.expectCode == http.StatusOK {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["status"] != "ok" {
					t.Errorf("status = %q, want %q", resp["status"], "ok")
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
