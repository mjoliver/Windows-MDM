// Package webhooks dispatches HMAC-SHA256-signed MDM security & compliance
// events to SIEM, Slack, Microsoft Teams, Discord, and generic JSON endpoints.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/vault"
)

const (
	VaultAADPrefix         = "webhook:"
	SignatureHeader        = "X-Latchz-Signature-256"
	EventHeader            = "X-Latchz-Event"
	DeliveryHeader         = "X-Latchz-Delivery"
	AutomationSingletonID  = "default"
	defaultDeliveryTimeout = 6 * time.Second
)

// SupportedEvents lists all subscribable MDM security & lifecycle webhook event types.
var SupportedEvents = []string{
	"device.enroll",
	"compliance.non_compliant",
	"compliance.auto_remediated",
	"bitlocker.reveal_key",
	"laps.reveal_password",
	"device.retire",
	"device.wipe",
}

// Event describes an MDM lifecycle or security event emitted to configured webhooks.
type Event struct {
	Type     string                 `json:"event"`
	Actor    string                 `json:"actor,omitempty"`
	TargetID string                 `json:"target_id,omitempty"`
	Summary  string                 `json:"summary"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// DeliveryResult summarizes a single HTTP delivery attempt.
type DeliveryResult struct {
	WebhookID   string    `json:"webhook_id"`
	EventType   string    `json:"event_type"`
	StatusCode  int       `json:"status_code"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	DeliveredAt time.Time `json:"delivered_at"`
}

// Dispatcher manages outbound event formatting, HMAC-SHA256 signing, and delivery logging.
type Dispatcher struct {
	db     *sql.DB
	vault  *vault.Vault
	client *http.Client
}

// NewDispatcher creates a webhook dispatcher.
func NewDispatcher(db *sql.DB, v *vault.Vault) *Dispatcher {
	return &Dispatcher{
		db:    db,
		vault: v,
		client: &http.Client{
			Timeout: defaultDeliveryTimeout,
		},
	}
}

// SetVault updates the AES-256-GCM vault used to decrypt endpoint signing secrets.
func (d *Dispatcher) SetVault(v *vault.Vault) {
	d.vault = v
}

// SetHTTPClient overrides the HTTP client (used in offline tests).
func (d *Dispatcher) SetHTTPClient(c *http.Client) {
	if c != nil {
		d.client = c
	}
}

// ValidateEndpointURL ensures a webhook destination uses http:// or https:// with a host.
func ValidateEndpointURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("webhook url must be a valid http:// or https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("webhook url scheme must be http or https")
	}
	return u.String(), nil
}

// NormalizeFormat validates webhook payload format ('json', 'slack', 'teams', 'discord').
func NormalizeFormat(raw string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(raw))
	if f == "" {
		return "json", nil
	}
	switch f {
	case "json", "slack", "teams", "discord":
		return f, nil
	default:
		return "", fmt.Errorf("unsupported format %q (expected json, slack, teams, or discord)", raw)
	}
}

// NormalizeEventsCSV validates a list of event names (empty or '*' subscribes to all events).
func NormalizeEventsCSV(events []string) (string, error) {
	if len(events) == 0 {
		return "*", nil
	}
	known := make(map[string]bool, len(SupportedEvents))
	for _, e := range SupportedEvents {
		known[e] = true
	}
	seen := make(map[string]bool)
	var out []string
	for _, raw := range events {
		for _, part := range strings.Split(raw, ",") {
			ev := strings.TrimSpace(part)
			if ev == "" {
				continue
			}
			if ev == "*" {
				return "*", nil
			}
			if !known[ev] {
				return "", fmt.Errorf("unknown webhook event %q", ev)
			}
			if !seen[ev] {
				seen[ev] = true
				out = append(out, ev)
			}
		}
	}
	if len(out) == 0 {
		return "*", nil
	}
	return strings.Join(out, ","), nil
}

// ComputeHMACSignature returns "sha256=<hex>" over body using secret.
func ComputeHMACSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMACSignature checks an X-Latchz-Signature-256 header in constant time.
func VerifyHMACSignature(secret, header string, body []byte) bool {
	if secret == "" || !strings.HasPrefix(header, "sha256=") {
		return false
	}
	want := ComputeHMACSignature(secret, body)
	return hmac.Equal([]byte(want), []byte(strings.TrimSpace(header)))
}

// FormatPayload renders an Event for 'json', 'slack', 'teams', or 'discord'.
func FormatPayload(format, deliveryID string, now time.Time, evt Event) ([]byte, error) {
	ts := now.UTC().Format(time.RFC3339)
	summary := strings.TrimSpace(evt.Summary)
	if summary == "" {
		summary = fmt.Sprintf("Event %s on %s", evt.Type, evt.TargetID)
	}

	switch format {
	case "slack":
		return json.Marshal(map[string]interface{}{
			"text": fmt.Sprintf("*[Latchz MDM • `%s`]* %s", evt.Type, summary),
		})
	case "discord":
		return json.Marshal(map[string]interface{}{
			"username": "Latchz MDM",
			"content":  fmt.Sprintf("**[Latchz MDM • `%s`]** %s", evt.Type, summary),
		})
	case "teams":
		return json.Marshal(map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"themeColor": "6366F1",
			"summary":    summary,
			"title":      fmt.Sprintf("Latchz MDM — %s", evt.Type),
			"text":       summary,
		})
	default:
		return json.Marshal(map[string]interface{}{
			"id":        deliveryID,
			"event":     evt.Type,
			"timestamp": ts,
			"actor":     evt.Actor,
			"target_id": evt.TargetID,
			"summary":   summary,
			"data":      evt.Data,
		})
	}
}

type storedEndpoint struct {
	id              string
	url             string
	format          string
	secretEncrypted string
	hasSecret       bool
	eventsCSV       string
	enabled         bool
}

func matchesEvent(eventsCSV, eventType string) bool {
	if eventType == "webhook.test" || strings.TrimSpace(eventsCSV) == "" || strings.TrimSpace(eventsCSV) == "*" {
		return true
	}
	for _, p := range strings.Split(eventsCSV, ",") {
		if strings.EqualFold(strings.TrimSpace(p), eventType) {
			return true
		}
	}
	return false
}

func (d *Dispatcher) deliverEndpoint(ctx context.Context, ep storedEndpoint, evt Event) DeliveryResult {
	now := time.Now().UTC()
	res := DeliveryResult{
		WebhookID:   ep.id,
		EventType:   evt.Type,
		DeliveredAt: now,
	}

	deliveryID := uuid.New().String()
	body, err := FormatPayload(ep.format, deliveryID, now, evt)
	if err != nil {
		res.Error = err.Error()
		d.recordDelivery(res)
		return res
	}

	var plainSecret string
	if ep.hasSecret && ep.secretEncrypted != "" {
		if d.vault == nil {
			res.Error = "secret vault is not initialized"
			d.recordDelivery(res)
			return res
		}
		plainSecret, err = d.vault.Decrypt(ep.secretEncrypted, VaultAADPrefix+ep.id)
		if err != nil {
			res.Error = "failed to decrypt webhook signing secret"
			d.recordDelivery(res)
			return res
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.url, bytes.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		d.recordDelivery(res)
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Latchz-MDM-Webhook/1.0")
	req.Header.Set(EventHeader, evt.Type)
	req.Header.Set(DeliveryHeader, deliveryID)
	if plainSecret != "" {
		req.Header.Set(SignatureHeader, ComputeHMACSignature(plainSecret, body))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		res.Error = err.Error()
		d.recordDelivery(res)
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	res.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res.Success = true
	} else {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	d.recordDelivery(res)
	return res
}

func (d *Dispatcher) recordDelivery(r DeliveryResult) {
	if d == nil || d.db == nil {
		return
	}
	succInt := 0
	if r.Success {
		succInt = 1
	}
	_, err := d.db.Exec(dbpkg.Rebind(`
		INSERT INTO webhook_deliveries (webhook_id, event_type, status_code, success, error, delivered_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`), r.WebhookID, r.EventType, r.StatusCode, succInt, r.Error, r.DeliveredAt)
	if err != nil {
		slog.Warn("webhooks: recording delivery", "webhook_id", r.WebhookID, "err", err)
	}
}

// DeliverOne sends a synchronous event to a specific webhook endpoint (used for Test Ping).
func (d *Dispatcher) DeliverOne(ctx context.Context, endpointID string, evt Event) (DeliveryResult, error) {
	if d == nil || d.db == nil {
		return DeliveryResult{}, errors.New("webhook dispatcher unavailable")
	}
	var ep storedEndpoint
	var hasSec, enabled int
	err := d.db.QueryRowContext(ctx, dbpkg.Rebind(`
		SELECT id, url, format, secret_encrypted, has_secret, events_csv, enabled
		FROM webhook_endpoints WHERE id = ?
	`), endpointID).Scan(&ep.id, &ep.url, &ep.format, &ep.secretEncrypted, &hasSec, &ep.eventsCSV, &enabled)
	if err != nil {
		return DeliveryResult{}, err
	}
	ep.hasSecret = hasSec != 0
	ep.enabled = enabled != 0
	return d.deliverEndpoint(ctx, ep, evt), nil
}

// Emit synchronously dispatches evt to all enabled endpoints subscribed to evt.Type.
func (d *Dispatcher) Emit(ctx context.Context, evt Event) int {
	if d == nil || d.db == nil {
		return 0
	}
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, url, format, secret_encrypted, has_secret, events_csv, enabled
		FROM webhook_endpoints
		WHERE enabled = 1
	`)
	if err != nil {
		return 0
	}
	var eps []storedEndpoint
	for rows.Next() {
		var ep storedEndpoint
		var hasSec, en int
		if rows.Scan(&ep.id, &ep.url, &ep.format, &ep.secretEncrypted, &hasSec, &ep.eventsCSV, &en) == nil {
			ep.hasSecret = hasSec != 0
			ep.enabled = en != 0
			if matchesEvent(ep.eventsCSV, evt.Type) {
				eps = append(eps, ep)
			}
		}
	}
	rows.Close()

	sent := 0
	for _, ep := range eps {
		res := d.deliverEndpoint(ctx, ep, evt)
		if res.Success {
			sent++
		}
	}
	return sent
}

// EmitAsync dispatches evt in a background goroutine so API/OMA-DM handlers never block on slow webhooks.
func (d *Dispatcher) EmitAsync(evt Event) {
	if d == nil || d.db == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultDeliveryTimeout*2)
		defer cancel()
		d.Emit(ctx, evt)
	}()
}

// IsAutoRemediateEnabled reports whether compliance drift auto-remediation is enabled.
func IsAutoRemediateEnabled(db *sql.DB) bool {
	if db == nil {
		return false
	}
	var auto int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT auto_remediate FROM compliance_automation_settings WHERE id = ?
	`), AutomationSingletonID).Scan(&auto)
	return err == nil && auto != 0
}

// RecordAutoRemediation increments the fleet auto-remediation counter.
func RecordAutoRemediation(db *sql.DB) {
	if db == nil {
		return
	}
	_, _ = db.Exec(dbpkg.Rebind(`
		UPDATE compliance_automation_settings
		SET remediation_count = remediation_count + 1,
		    last_remediated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`), AutomationSingletonID)
}
