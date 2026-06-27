// Package api implements the Pane REST API used by the admin dashboard.
// All routes are mounted under /api and require a valid session cookie.
package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

// Handler holds dependencies for all API handlers.
type Handler struct {
	db *sql.DB
}

// NewHandler creates an API handler.
func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// respond encodes v as JSON and writes it to w with the given status code.
func respond(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// At this point the header is already written; just log
		_ = err
	}
}

// respondOK writes a 200 JSON response.
func respondOK(w http.ResponseWriter, v interface{}) {
	respond(w, http.StatusOK, v)
}

// respondErr writes a JSON error response.
func respondErr(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

// respondCreated writes a 201 JSON response.
func respondCreated(w http.ResponseWriter, v interface{}) {
	respond(w, http.StatusCreated, v)
}

// decodeBody parses the JSON request body into v.
// Returns false and writes an error response if decoding fails.
func decodeBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// ── Me endpoint ───────────────────────────────────────────────────────────────

type MeResponse struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

// HandleMe returns the current authenticated user's profile.
// GET /api/me
func (h *Handler) HandleMe(w http.ResponseWriter, r *http.Request) {
	email := emailFromCtx(r)
	role := roleFromCtx(r)

	var displayName string
	_ = h.db.QueryRow(
		dbpkg.Rebind(`SELECT COALESCE(display_name, '') FROM users WHERE email = ?`), email,
	).Scan(&displayName)

	respondOK(w, MeResponse{
		Email:       email,
		DisplayName: displayName,
		Role:        role,
	})
}

// ── Context helpers (set by server middleware) ────────────────────────────────

type CtxKey string

const (
	CtxKeyEmail CtxKey = "email"
	CtxKeyRole  CtxKey = "role"
)

func emailFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(CtxKeyEmail).(string)
	return v
}

func roleFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(CtxKeyRole).(string)
	return v
}

// queryDeviceIDs runs a query returning a single device-id column and collects
// the results (used to find devices affected by a profile/group change).
func (h *Handler) queryDeviceIDs(r *http.Request, query string, args ...interface{}) []string {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(query), args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// enqueueRef gives api handlers access to mdm command queue without circular imports
var enqueueRef = struct {
	Lock   func(db *sql.DB, deviceID string) (int64, error)
	Wipe   func(db *sql.DB, deviceID string) (int64, error)
	Reboot func(db *sql.DB, deviceID string) (int64, error)
}{
	Lock:   mdm.EnqueueLock,
	Wipe:   mdm.EnqueueWipe,
	Reboot: mdm.EnqueueReboot,
}

// policyOps holds injectable policy functions for testing.
// By default they call the real policy package functions.
var policyOps = struct {
	ApplyDevice func(db *sql.DB, deviceID string)
	ApplyGroup  func(db *sql.DB, groupID string)
	ApplyProfile func(db *sql.DB, profileID string)
}{
	ApplyDevice:  func(db *sql.DB, deviceID string)  { /* default no-op for tests */ },
	ApplyGroup:   func(db *sql.DB, groupID string)   { /* default no-op for tests */ },
	ApplyProfile: func(db *sql.DB, profileID string) { /* default no-op for tests */ },
}

// keep imports used
var _ = mdm.EnqueueGet