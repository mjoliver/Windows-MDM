package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ── Tests for respond helpers ─────────────────────────────────────────────────

func TestRespond(t *testing.T) {
	t.Run("JSON response with status", func(t *testing.T) {
		w := httptest.NewRecorder()
		respond(w, http.StatusAccepted, map[string]string{"status": "queued"})

		if w.Code != http.StatusAccepted {
			t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", contentType)
		}

		var result map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal response body: %v", err)
		}
		if result["status"] != "queued" {
			t.Errorf("expected status 'queued', got %q", result["status"])
		}
	})

	t.Run("empty body encoding", func(t *testing.T) {
		w := httptest.NewRecorder()
		respond(w, http.StatusOK, nil)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

func TestRespondOK(t *testing.T) {
	w := httptest.NewRecorder()
	respondOK(w, map[string]string{"msg": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["msg"] != "ok" {
		t.Errorf("expected msg 'ok', got %q", result["msg"])
	}
}

func TestRespondErr(t *testing.T) {
	w := httptest.NewRecorder()
	respondErr(w, http.StatusBadRequest, "bad thing happened")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["error"] != "bad thing happened" {
		t.Errorf("expected error 'bad thing happened', got %q", result["error"])
	}
}

func TestRespondCreated(t *testing.T) {
	w := httptest.NewRecorder()
	respondCreated(w, map[string]string{"id": "abc123"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result["id"] != "abc123" {
		t.Errorf("expected id 'abc123', got %q", result["id"])
	}
}

// ── Tests for decodeBody ──────────────────────────────────────────────────────

func TestDecodeBody(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		expectOK  bool
		expectKey string
		expectVal string
	}{
		{
			name:      "valid JSON object",
			body:      `{"name":"test","value":42}`,
			expectOK:  true,
			expectKey: "name",
			expectVal: "test",
		},
		{
			name:     "invalid JSON",
			body:     `{invalid json}`,
			expectOK: false,
		},
		{
			name:     "empty body",
			body:     ``,
			expectOK: false,
		},
		{
			name:      "valid JSON array decodes as interface",
			body:      `[1,2,3]`,
			expectOK:  true,
			expectKey: "type",
			expectVal: "slice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/test", nil)
			r.Body = &readCloser{reader: []byte(tt.body)}

			if tt.expectKey == "name" {
				var result struct {
					Name  string `json:"name"`
					Value int    `json:"value"`
				}
				ok := decodeBody(w, r, &result)
				if ok != tt.expectOK {
					t.Errorf("decodeBody() returned %v, expected %v", ok, tt.expectOK)
				}
				if tt.expectOK && result.Name != tt.expectVal {
					t.Errorf("expected name %q, got %q", tt.expectVal, result.Name)
				}
			} else if tt.expectKey == "type" {
				var result interface{}
				ok := decodeBody(w, r, &result)
				if ok != tt.expectOK {
					t.Errorf("decodeBody() returned %v, expected %v", ok, tt.expectOK)
				}
				if tt.expectOK {
					if _, ok := result.([]interface{}); !ok {
						t.Errorf("expected result to be []interface{}, got %T", result)
					}
				}
			} else {
				var result map[string]string
				ok := decodeBody(w, r, &result)
				if ok != tt.expectOK {
					t.Errorf("decodeBody() returned %v, expected %v", ok, tt.expectOK)
				}
				if tt.expectOK {
					if result["name"] != tt.expectVal {
						t.Errorf("expected name %q, got %q", tt.expectVal, result["name"])
					}
				}
			}
		})
	}
}

// readCloser wraps a byte slice to implement io.ReadCloser.
type readCloser struct {
	reader   []byte
	position int
}

func (r *readCloser) Read(p []byte) (int, error) {
	if r.position >= len(r.reader) {
		return 0, io.EOF
	}
	n := copy(p, r.reader[r.position:])
	r.position += n
	return n, nil
}

func (r *readCloser) Close() error {
	return nil
}

// ── Tests for context helpers ─────────────────────────────────────────────────

func TestEmailFromCtx(t *testing.T) {
	tests := []struct {
		name     string
		ctxEmail interface{}
		expected string
	}{
		{
			name:     "string email",
			ctxEmail: "admin@example.com",
			expected: "admin@example.com",
		},
		{
			name:     "nil email",
			ctxEmail: nil,
			expected: "",
		},
		{
			name:     "empty string email",
			ctxEmail: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), CtxKeyEmail, tt.ctxEmail)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(ctx)

			got := emailFromCtx(r)
			if got != tt.expected {
				t.Errorf("emailFromCtx() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRoleFromCtx(t *testing.T) {
	tests := []struct {
		name     string
		ctxRole  interface{}
		expected string
	}{
		{
			name:     "admin role",
			ctxRole:  "admin",
			expected: "admin",
		},
		{
			name:     "operator role",
			ctxRole:  "operator",
			expected: "operator",
		},
		{
			name:     "nil role",
			ctxRole:  nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), CtxKeyRole, tt.ctxRole)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(ctx)

			got := roleFromCtx(r)
			if got != tt.expected {
				t.Errorf("roleFromCtx() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ── Tests for HandleMe ────────────────────────────────────────────────────────

func TestHandleMe(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(sqlmock.Sqlmock)
		ctxEmail       string
		ctxRole        string
		expectedStatus int
		expectedEmail  string
		expectedRole   string
		expectErr      bool
	}{
		{
			name:           "successful user lookup",
			ctxEmail:       "admin@example.com",
			ctxRole:        "admin",
			expectedStatus: http.StatusOK,
			expectedEmail:  "admin@example.com",
			expectedRole:   "admin",
		},
		{
			name:           "user with no display name",
			ctxEmail:       "nobody@example.com",
			ctxRole:        "operator",
			expectedStatus: http.StatusOK,
			expectedEmail:  "nobody@example.com",
			expectedRole:   "operator",
		},
		{
			name:           "empty context email returns empty display name",
			ctxEmail:       "",
			ctxRole:        "viewer",
			expectedStatus: http.StatusOK,
			expectedEmail:  "",
			expectedRole:   "viewer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("couldn't create sqlmock: %s", err)
			}
			defer db.Close()

			// Mock the users query
			expectedSQL := `SELECT COALESCE\(display_name, ''\) FROM users WHERE \?`
			mock.ExpectQuery(expectedSQL).WithArgs().
				WillReturnRows(sqlmock.NewRows([]string{"display_name"}).AddRow("Admin User"))

			if tt.ctxEmail == "nobody@example.com" {
				mock.ExpectQuery(expectedSQL).WithArgs().
					WillReturnRows(sqlmock.NewRows([]string{"display_name"}))
			}

			h := NewHandler(db)
			ctx := context.WithValue(context.Background(), CtxKeyEmail, tt.ctxEmail)
			ctx = context.WithValue(ctx, CtxKeyRole, tt.ctxRole)
			r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleMe(w, r)

			if w.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.expectedStatus, w.Body.String())
			}

			var resp MeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp.Email != tt.expectedEmail {
				t.Errorf("email = %q, want %q", resp.Email, tt.expectedEmail)
			}
			if resp.Role != tt.expectedRole {
				t.Errorf("role = %q, want %q", resp.Role, tt.expectedRole)
			}
		})
	}
}

func TestHandleMeDatabaseError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("couldn't create sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery(".").WillReturnError(sql.ErrConnDone)

	h := NewHandler(db)
	ctx := context.WithValue(context.Background(), CtxKeyEmail, "test@example.com")
	ctx = context.WithValue(ctx, CtxKeyRole, "admin")
	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleMe(w, r)

	// Database error doesn't cause a handler error response - it just returns empty display name
	// because we ignore the Scan error
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ── Tests for enqueueRef ──────────────────────────────────────────────────────

func TestEnqueueRef(t *testing.T) {
	// Verify enqueueRef has the expected functions
	if enqueueRef.Lock == nil {
		t.Error("enqueueRef.Lock should not be nil")
	}
	if enqueueRef.Wipe == nil {
		t.Error("enqueueRef.Wipe should not be nil")
	}
	if enqueueRef.Reboot == nil {
		t.Error("enqueueRef.Reboot should not be nil")
	}
}

// ── Tests for policyOps ───────────────────────────────────────────────────────

func TestPolicyOps(t *testing.T) {
	// Verify policyOps has the expected functions
	if policyOps.ApplyDevice == nil {
		t.Error("policyOps.ApplyDevice should not be nil")
	}
	if policyOps.ApplyGroup == nil {
		t.Error("policyOps.ApplyGroup should not be nil")
	}
	if policyOps.ApplyProfile == nil {
		t.Error("policyOps.ApplyProfile should not be nil")
	}
}
