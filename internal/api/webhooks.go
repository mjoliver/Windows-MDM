package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/webhooks"
)

// WebhookEndpoint represents an outbound SIEM / chat alerting webhook configuration.
type WebhookEndpoint struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Format    string    `json:"format"`
	HasSecret bool      `json:"has_secret"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WebhookDeliveryItem exposes a recent delivery log entry.
type WebhookDeliveryItem struct {
	ID          int64     `json:"id"`
	WebhookID   string    `json:"webhook_id"`
	WebhookName string    `json:"webhook_name"`
	EventType   string    `json:"event_type"`
	StatusCode  int       `json:"status_code"`
	Success     bool      `json:"success"`
	Error       string    `json:"error"`
	DeliveredAt time.Time `json:"delivered_at"`
}

// ComplianceAutomationSettings exposes fleet drift auto-remediation settings.
type ComplianceAutomationSettings struct {
	AutoRemediate    bool       `json:"auto_remediate"`
	RemediationCount int        `json:"remediation_count"`
	LastRemediatedAt *time.Time `json:"last_remediated_at"`
	UpdatedBy        string     `json:"updated_by"`
	UpdatedAt        *time.Time `json:"updated_at"`
}

func splitEventsCSV(csv string) []string {
	trimmed := strings.TrimSpace(csv)
	if trimmed == "" || trimmed == "*" {
		return []string{"*"}
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// HandleListWebhooks returns configured webhook endpoints and supported event types.
// GET /api/webhooks
func (h *Handler) HandleListWebhooks(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, name, url, format, has_secret, events_csv, enabled, created_by, created_at, updated_at
		FROM webhook_endpoints
		ORDER BY created_at DESC
	`)
	if err != nil {
		slog.Error("api: listing webhooks", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	defer rows.Close()

	endpoints := []WebhookEndpoint{}
	for rows.Next() {
		var ep WebhookEndpoint
		var hasSec, en int
		var evCSV string
		if err := rows.Scan(
			&ep.ID, &ep.Name, &ep.URL, &ep.Format, &hasSec, &evCSV, &en,
			&ep.CreatedBy, &ep.CreatedAt, &ep.UpdatedAt,
		); err != nil {
			continue
		}
		ep.HasSecret = hasSec != 0
		ep.Enabled = en != 0
		ep.Events = splitEventsCSV(evCSV)
		endpoints = append(endpoints, ep)
	}

	respondOK(w, map[string]interface{}{
		"endpoints":        endpoints,
		"supported_events": webhooks.SupportedEvents,
	})
}

// HandleCreateWebhook creates a new HMAC-SHA256-signed webhook endpoint.
// POST /api/webhooks
func (h *Handler) HandleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Name    string   `json:"name"`
		URL     string   `json:"url"`
		Format  string   `json:"format"`
		Secret  string   `json:"secret"`
		Events  []string `json:"events"`
		Enabled *bool    `json:"enabled"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		respondErr(w, http.StatusBadRequest, "name is required (max 80 chars)")
		return
	}
	cleanURL, err := webhooks.ValidateEndpointURL(body.URL)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	format, err := webhooks.NormalizeFormat(body.Format)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}
	evCSV, err := webhooks.NormalizeEventsCSV(body.Events)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	id := uuid.New().String()
	rawSecret := strings.TrimSpace(body.Secret)
	encSecret := ""
	hasSecret := 0
	if rawSecret != "" {
		if h.vault == nil {
			respondErr(w, http.StatusServiceUnavailable, "secret vault is not configured (set server.master_secret)")
			return
		}
		enc, err := h.vault.Encrypt(rawSecret, webhooks.VaultAADPrefix+id)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to encrypt webhook secret")
			return
		}
		encSecret = enc
		hasSecret = 1
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	now := time.Now().UTC()

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO webhook_endpoints (
			id, name, url, format, secret_encrypted, has_secret, events_csv, enabled, created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`), id, name, cleanURL, format, encSecret, hasSecret, evCSV, boolToSQLInt(enabled), actor, now, now)
	if err != nil {
		slog.Error("api: creating webhook endpoint", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}

	h.audit(r, actor, "webhook.create", "webhook", id,
		fmt.Sprintf(`{"name":%q,"format":%q,"has_secret":%t}`, name, format, hasSecret == 1))

	respondCreated(w, WebhookEndpoint{
		ID:        id,
		Name:      name,
		URL:       cleanURL,
		Format:    format,
		HasSecret: hasSecret == 1,
		Events:    splitEventsCSV(evCSV),
		Enabled:   enabled,
		CreatedBy: actor,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

// HandleDeleteWebhook deletes a webhook endpoint and its delivery history.
// DELETE /api/webhooks/{id}
func (h *Handler) HandleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM webhook_endpoints WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "webhook not found")
		return
	}

	h.audit(r, actor, "webhook.delete", "webhook", id, "")
	respondOK(w, map[string]interface{}{"deleted": true, "id": id})
}

// HandleTestWebhook sends a live signed test event ('webhook.test') and returns the HTTP result.
// POST /api/webhooks/{id}/test
func (h *Handler) HandleTestWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	if h.webhooks == nil {
		respondErr(w, http.StatusServiceUnavailable, "webhook dispatcher is not initialized")
		return
	}

	deliv, err := h.webhooks.DeliverOne(r.Context(), id, webhooks.Event{
		Type:     "webhook.test",
		Actor:    actor,
		TargetID: id,
		Summary:  fmt.Sprintf("Test webhook ping triggered by %s", actor),
		Data: map[string]interface{}{
			"test": true,
		},
	})
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "webhook not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondOK(w, deliv)
}

// HandleListWebhookDeliveries returns the 50 most recent webhook delivery attempts.
// GET /api/webhooks/deliveries
func (h *Handler) HandleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT wd.id, wd.webhook_id, COALESCE(we.name, wd.webhook_id), wd.event_type,
		       wd.status_code, wd.success, wd.error, wd.delivered_at
		FROM webhook_deliveries wd
		LEFT JOIN webhook_endpoints we ON we.id = wd.webhook_id
		ORDER BY wd.id DESC
		LIMIT 50
	`)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list webhook deliveries")
		return
	}
	defer rows.Close()

	out := []WebhookDeliveryItem{}
	for rows.Next() {
		var it WebhookDeliveryItem
		var succ int
		if err := rows.Scan(
			&it.ID, &it.WebhookID, &it.WebhookName, &it.EventType,
			&it.StatusCode, &succ, &it.Error, &it.DeliveredAt,
		); err != nil {
			continue
		}
		it.Success = succ != 0
		out = append(out, it)
	}
	respondOK(w, out)
}

// HandleGetComplianceAutomation returns fleet drift auto-remediation settings.
// GET /api/compliance/automation
func (h *Handler) HandleGetComplianceAutomation(w http.ResponseWriter, r *http.Request) {
	out := ComplianceAutomationSettings{}
	var auto int
	var lastRem sql.NullTime
	var updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT auto_remediate, remediation_count, last_remediated_at, updated_by, updated_at
		FROM compliance_automation_settings
		WHERE id = ?
	`), webhooks.AutomationSingletonID).Scan(&auto, &out.RemediationCount, &lastRem, &out.UpdatedBy, &updatedAt)
	if err == nil {
		out.AutoRemediate = auto != 0
		if lastRem.Valid {
			t := lastRem.Time
			out.LastRemediatedAt = &t
		}
		u := updatedAt
		out.UpdatedAt = &u
	}
	respondOK(w, out)
}

// HandleUpdateComplianceAutomation updates fleet drift auto-remediation settings.
// PUT /api/compliance/automation
func (h *Handler) HandleUpdateComplianceAutomation(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		AutoRemediate bool `json:"auto_remediate"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	now := time.Now().UTC()
	_, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO compliance_automation_settings (id, auto_remediate, remediation_count, updated_by, updated_at)
		VALUES (?, ?, 0, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			auto_remediate = EXCLUDED.auto_remediate,
			updated_by     = EXCLUDED.updated_by,
			updated_at     = EXCLUDED.updated_at
	`), webhooks.AutomationSingletonID, boolToSQLInt(body.AutoRemediate), actor, now)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to save compliance automation settings")
		return
	}

	h.audit(r, actor, "compliance.automation_update", "compliance_automation", webhooks.AutomationSingletonID,
		fmt.Sprintf(`{"auto_remediate":%t}`, body.AutoRemediate))

	h.HandleGetComplianceAutomation(w, r)
}
