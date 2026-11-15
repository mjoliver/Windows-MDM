// Package wns implements Windows Push Notification Services (WNS) OAuth2 token
// exchange and raw push delivery (wns/raw) for instant OMA-DM device wake-ups.
package wns

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

const (
	defaultTokenURL = "https://login.live.com/accesstoken.srf"
	wnsScope        = "notify.windows.com"
	wnsHostSuffix   = ".notify.windows.com"
)

// ErrInvalidChannelURI indicates a device-supplied ChannelURI failed SSRF /
// domain validation.
var ErrInvalidChannelURI = errors.New("invalid WNS channel URI")

// ValidateChannelURI enforces strict SSRF protection on ChannelURI values
// reported by enrolled devices before storing or sending Bearer tokens to them.
// Only HTTPS URLs under *.notify.windows.com without credentials are accepted.
func ValidateChannelURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: empty URI", ErrInvalidChannelURI)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidChannelURI, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be https", ErrInvalidChannelURI)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not allowed", ErrInvalidChannelURI)
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("%w: unexpected port %q", ErrInvalidChannelURI, port)
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil {
		return fmt.Errorf("%w: IP literal host not allowed", ErrInvalidChannelURI)
	}
	if !strings.HasSuffix(host, wnsHostSuffix) || len(host) <= len(wnsHostSuffix) {
		return fmt.Errorf("%w: host %q is outside *%s", ErrInvalidChannelURI, host, wnsHostSuffix)
	}
	return nil
}

// PushResult describes the outcome of a WNS wake-up push attempt.
type PushResult struct {
	Status    string `json:"status"`               // sent, no_channel, expired_channel, wns_disabled, failed
	WNSStatus string `json:"wns_status,omitempty"` // X-WNS-Status header (e.g. received, dropped)
	HTTPCode  int    `json:"http_code,omitempty"`
}

// Client manages Microsoft Live OAuth2 token caching and WNS wns/raw pushes.
type Client struct {
	db                *sql.DB
	packageFamilyName string
	packageSID        string
	clientSecret      string
	tokenURL          string
	allowTestHosts    bool
	httpClient        *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// NewClient creates a WNS push client backed by db.
func NewClient(db *sql.DB, packageFamilyName, packageSID, clientSecret string) *Client {
	return &Client{
		db:                db,
		packageFamilyName: strings.TrimSpace(packageFamilyName),
		packageSID:        strings.TrimSpace(packageSID),
		clientSecret:      strings.TrimSpace(clientSecret),
		tokenURL:          defaultTokenURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow redirects: prevents leaking the WNS Bearer token across origins.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Enabled reports whether this client has complete WNS credentials configured.
func (c *Client) Enabled() bool {
	return c != nil && c.packageFamilyName != "" && c.packageSID != "" && c.clientSecret != ""
}

// PFN returns the configured Microsoft Partner Center Package Family Name.
func (c *Client) PFN() string {
	if c == nil {
		return ""
	}
	return c.packageFamilyName
}

// NotifyAsync fires a non-blocking WNS raw wake-up push for deviceID if an
// active channel URI is stored in device_wns_channels.
func (c *Client) NotifyAsync(deviceID string) {
	if !c.Enabled() || deviceID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, err := c.PushRaw(ctx, deviceID)
		if err != nil {
			slog.Warn("wns: wake push failed", "device_id", deviceID, "err", err)
			return
		}
		if res != nil && res.Status == "sent" {
			slog.Info("wns: wake push delivered", "device_id", deviceID, "wns_status", res.WNSStatus)
		}
	}()
}

// PushRaw sends an immediate WNS wns/raw notification to wake Windows DMClient
// on deviceID and trigger an OMA-DM SyncML session.
func (c *Client) PushRaw(ctx context.Context, deviceID string) (*PushResult, error) {
	if !c.Enabled() {
		return &PushResult{Status: "wns_disabled"}, nil
	}

	var channelURI string
	err := c.db.QueryRowContext(
		ctx,
		dbpkg.Rebind(`SELECT channel_uri FROM device_wns_channels WHERE device_id = ?`),
		deviceID,
	).Scan(&channelURI)
	if errors.Is(err, sql.ErrNoRows) || strings.TrimSpace(channelURI) == "" {
		return &PushResult{Status: "no_channel"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading WNS channel: %w", err)
	}

	if !c.allowTestHosts {
		if err := ValidateChannelURI(channelURI); err != nil {
			// Purge invalid URI so it cannot linger in DB.
			_, _ = c.db.ExecContext(ctx, dbpkg.Rebind(`DELETE FROM device_wns_channels WHERE device_id = ?`), deviceID)
			return &PushResult{Status: "failed"}, err
		}
	}

	token, err := c.getAccessToken(ctx, false)
	if err != nil {
		return &PushResult{Status: "failed"}, err
	}

	resp, err := c.sendRawRequest(ctx, channelURI, token)
	if err != nil {
		return &PushResult{Status: "failed"}, err
	}
	_ = resp.Body.Close()

	// On 401 Unauthorized, clear cached token and retry once.
	if resp.StatusCode == http.StatusUnauthorized {
		token, err = c.getAccessToken(ctx, true)
		if err != nil {
			return &PushResult{Status: "failed", HTTPCode: http.StatusUnauthorized}, err
		}
		resp, err = c.sendRawRequest(ctx, channelURI, token)
		if err != nil {
			return &PushResult{Status: "failed"}, err
		}
		_ = resp.Body.Close()
	}

	wnsStatus := resp.Header.Get("X-WNS-Status")
	now := time.Now().UTC()

	switch resp.StatusCode {
	case http.StatusOK:
		statusLabel := "sent"
		if wnsStatus != "" {
			statusLabel = "sent:" + wnsStatus
		}
		_, _ = c.db.ExecContext(
			ctx,
			dbpkg.Rebind(`UPDATE device_wns_channels SET last_push_at = ?, last_push_status = ? WHERE device_id = ?`),
			now, statusLabel, deviceID,
		)
		return &PushResult{
			Status:    "sent",
			WNSStatus: wnsStatus,
			HTTPCode:  http.StatusOK,
		}, nil

	case http.StatusNotFound, http.StatusGone:
		// Channel expired in Microsoft WNS cloud; delete so next poll re-queries Push/ChannelURI.
		_, _ = c.db.ExecContext(
			ctx,
			dbpkg.Rebind(`DELETE FROM device_wns_channels WHERE device_id = ?`),
			deviceID,
		)
		slog.Info("wns: purged expired channel URI", "device_id", deviceID, "http_code", resp.StatusCode)
		return &PushResult{
			Status:   "expired_channel",
			HTTPCode: resp.StatusCode,
		}, nil

	default:
		statusLabel := fmt.Sprintf("http_%d", resp.StatusCode)
		_, _ = c.db.ExecContext(
			ctx,
			dbpkg.Rebind(`UPDATE device_wns_channels SET last_push_at = ?, last_push_status = ? WHERE device_id = ?`),
			now, statusLabel, deviceID,
		)
		return &PushResult{
			Status:    "failed",
			WNSStatus: wnsStatus,
			HTTPCode:  resp.StatusCode,
		}, fmt.Errorf("wns push returned HTTP %d", resp.StatusCode)
	}
}

func (c *Client) sendRawRequest(ctx context.Context, channelURI, bearerToken string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, channelURI, bytes.NewReader([]byte("sync")))
	if err != nil {
		return nil, fmt.Errorf("building WNS request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-WNS-Type", "wns/raw")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-WNS-Cache-Policy", "cache")
	return c.httpClient.Do(req)
}

func (c *Client) getAccessToken(ctx context.Context, forceRefresh bool) (string, error) {
	c.mu.Lock()
	if !forceRefresh && c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		tok := c.accessToken
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.packageSID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", wnsScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building WNS token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting WNS access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("reading WNS token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WNS token endpoint returned HTTP %d", resp.StatusCode)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("invalid WNS token payload")
	}

	ttl := 23 * time.Hour
	if parsed.ExpiresIn > 120 {
		ttl = time.Duration(parsed.ExpiresIn-60) * time.Second
	} else if parsed.ExpiresIn > 0 {
		ttl = time.Duration(parsed.ExpiresIn) * time.Second
	}

	c.mu.Lock()
	c.accessToken = parsed.AccessToken
	c.tokenExpiry = time.Now().Add(ttl)
	c.mu.Unlock()

	return parsed.AccessToken, nil
}
