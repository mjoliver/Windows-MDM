// Package api implements the Pane REST API used by the admin dashboard.
// All routes are mounted under /api and require a valid session cookie.
package api

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
	"github.com/latchzmdm/latchz/internal/msi"
	"github.com/latchzmdm/latchz/internal/policy"
	"github.com/latchzmdm/latchz/internal/vault"
	"github.com/latchzmdm/latchz/internal/winget"
	"github.com/latchzmdm/latchz/internal/wns"
)

// Handler holds dependencies for all API handlers.
type Handler struct {
	db              *sql.DB
	wns             *wns.Client
	vault           *vault.Vault
	winget          *winget.Client
	deviceCAPool    *x509.CertPool
	proxyCertHeader string
	contentBaseURL  string
	contentSecret   []byte
	contentClient   *http.Client
	packagesDir     string
}

// NewHandler creates an API handler.
func NewHandler(db *sql.DB) *Handler {
	return &Handler{
		db:            db,
		winget:        winget.NewClient(),
		contentClient: msi.NewIdentityHTTPClient(0),
	}
}

// SetWNSClient attaches an optional WNS push client for instant device wake-ups.
func (h *Handler) SetWNSClient(c *wns.Client) {
	h.wns = c
}

// ConfigureContentRelay enables HMAC-signed, identity-encoding MSI content relay
// URLs (/mdm/apps/{id}/content.msi) so Windows 11 Delivery Optimization (DoSvc)
// receives uncompressed HTTP 206 byte-range slices even when upstream CDNs
// (such as dl.google.com) serve Content-Encoding: gzip on Range requests.
func (h *Handler) ConfigureContentRelay(publicBaseURL string, signingSecret []byte) {
	h.contentBaseURL = strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if len(signingSecret) > 0 {
		key := make([]byte, len(signingSecret))
		copy(key, signingSecret)
		h.contentSecret = key
	}
}

// SetContentHTTPClient overrides the upstream HTTP client used by the MSI
// content relay (intended for offline unit tests).
func (h *Handler) SetContentHTTPClient(c *http.Client) {
	if c != nil {
		h.contentClient = c
	}
}

// SetPackagesDir configures the local storage directory where drag-and-drop
// uploaded Win32 .msi packages are stored and served from.
func (h *Handler) SetPackagesDir(dir string) {
	h.packagesDir = strings.TrimSpace(dir)
}

// SetVault configures the AES-256-GCM secret vault used for BitLocker recovery
// key escrow and managed local administrator credentials.
func (h *Handler) SetVault(v *vault.Vault) {
	h.vault = v
}

// SetDeviceAuth configures X.509 client-certificate trust so enrolled devices
// can authenticate directly to mTLS escrow endpoints.
func (h *Handler) SetDeviceAuth(caPool *x509.CertPool, proxyHeader string) {
	h.deviceCAPool = caPool
	h.proxyCertHeader = proxyHeader
}

func (h *Handler) wakeDevice(deviceID string) {
	if h.wns != nil && h.wns.Enabled() {
		h.wns.NotifyAsync(deviceID)
	}
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
	Lock           func(db *sql.DB, deviceID string) (int64, error)
	Wipe           func(db *sql.DB, deviceID string) (int64, error)
	Reboot         func(db *sql.DB, deviceID string) (int64, error)
	Rename         func(db *sql.DB, deviceID, hostname string) (int64, error)
	Retire         func(db *sql.DB, deviceID string) (int64, error)
	PostureRefresh func(db *sql.DB, deviceID string) (int, error)
}{
	Lock:           mdm.EnqueueLock,
	Wipe:           mdm.EnqueueWipe,
	Reboot:         mdm.EnqueueReboot,
	Rename:         mdm.EnqueueRenameDevice,
	Retire:         mdm.EnqueueRetireDevice,
	PostureRefresh: mdm.EnqueuePostureRefresh,
}

// policyOps holds injectable policy functions for testing.
// By default they call the real policy package functions.
var policyOps = struct {
	ApplyDevice           func(db *sql.DB, deviceID string)
	ApplyGroup            func(db *sql.DB, groupID string)
	ApplyProfile          func(db *sql.DB, profileID string)
	ResyncDevices         func(db *sql.DB, deviceIDs []string)
	ReconcileDynamicGroup func(db *sql.DB, groupID string) (int, int)
}{
	ApplyDevice:           policy.ApplyDevice,
	ApplyGroup:            policy.ApplyGroup,
	ApplyProfile:          policy.ApplyProfile,
	ResyncDevices:         policy.ResyncDevices,
	ReconcileDynamicGroup: policy.ReconcileDynamicGroup,
}

// keep imports used
var _ = mdm.EnqueueGet
