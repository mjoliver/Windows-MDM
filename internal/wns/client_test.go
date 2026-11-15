package wns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestValidateChannelURI(t *testing.T) {
	valid := []string{
		"https://wns2-bl2p.notify.windows.com/?token=AwYAAAC12345",
		"https://db5p.notify.windows.com/?token=xyz",
		"https://hk2.notify.windows.com:443/?token=abc",
	}
	for _, u := range valid {
		if err := ValidateChannelURI(u); err != nil {
			t.Errorf("ValidateChannelURI(%q) unexpected error: %v", u, err)
		}
	}

	invalid := []string{
		"",
		"http://wns2-bl2p.notify.windows.com/?token=abc",        // non-HTTPS
		"https://notify.windows.com/?token=abc",                 // missing regional subdomain
		"https://evil-notify.windows.com.attacker.io/?token=x",  // suffix spoof
		"https://user:pass@wns2-bl2p.notify.windows.com/?token", // userinfo
		"https://wns2-bl2p.notify.windows.com:8443/?token=abc",  // non-443 port
		"https://127.0.0.1/?token=abc",                          // loopback SSRF
		"https://169.254.169.254/latest/meta-data",              // cloud metadata SSRF
	}
	for _, u := range invalid {
		if err := ValidateChannelURI(u); err == nil {
			t.Errorf("ValidateChannelURI(%q) expected error, got nil", u)
		}
	}
}

func TestClient_PushRaw_TokenCacheRetryAndExpiryCleanup(t *testing.T) {
	database := testutil.DB(t)
	devID := testutil.SeedDevice(t, database, "HW-WNS-1")

	var tokenCalls atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := tokenCalls.Add(1)
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" || r.FormValue("scope") != "notify.windows.com" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + string(rune('0'+n)),
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	var pushMode atomic.Int32 // 0 = 200 OK, 1 = 401 once then 200, 2 = 410 Gone
	var seen401 atomic.Bool
	wnsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WNS-Type") != "wns/raw" || r.Header.Get("Content-Type") != "application/octet-stream" {
			http.Error(w, "bad headers", http.StatusBadRequest)
			return
		}
		mode := pushMode.Load()
		if mode == 1 && !seen401.Swap(true) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if mode == 2 {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.Header().Set("X-WNS-Status", "received")
		w.WriteHeader(http.StatusOK)
	}))
	defer wnsSrv.Close()

	c := NewClient(database.DB, "Latchz.MDM_8wekyb3d8bbwe", "ms-app://s-1-15-2-999", "secret")
	c.tokenURL = tokenSrv.URL
	c.allowTestHosts = true

	// 1. No channel row yet -> no_channel
	res, err := c.PushRaw(context.Background(), devID)
	if err != nil || res.Status != "no_channel" {
		t.Fatalf("expected no_channel, got res=%+v err=%v", res, err)
	}

	// Seed channel URI
	if _, err := database.Exec(`INSERT INTO device_wns_channels (device_id, channel_uri) VALUES (?, ?)`, devID, wnsSrv.URL+"/?token=1"); err != nil {
		t.Fatal(err)
	}

	// 2. First push -> fetches token #1 and succeeds (200 received)
	res, err = c.PushRaw(context.Background(), devID)
	if err != nil || res.Status != "sent" || res.WNSStatus != "received" {
		t.Fatalf("expected sent/received, got res=%+v err=%v", res, err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected 1 token call, got %d", tokenCalls.Load())
	}

	// 3. Second push -> reuses cached token (#1)
	res, err = c.PushRaw(context.Background(), devID)
	if err != nil || res.Status != "sent" {
		t.Fatalf("expected cached push sent, got res=%+v err=%v", res, err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected cached token reuse (1 call), got %d", tokenCalls.Load())
	}

	// 4. 401 from WNS -> refreshes token (#2) and succeeds
	pushMode.Store(1)
	res, err = c.PushRaw(context.Background(), devID)
	if err != nil || res.Status != "sent" {
		t.Fatalf("expected 401 retry to succeed, got res=%+v err=%v", res, err)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("expected token refresh on 401 (2 calls), got %d", tokenCalls.Load())
	}

	// 5. 410 Gone -> purges expired channel from DB
	pushMode.Store(2)
	res, err = c.PushRaw(context.Background(), devID)
	if err != nil || res.Status != "expired_channel" {
		t.Fatalf("expected expired_channel on 410, got res=%+v err=%v", res, err)
	}
	var remaining int
	_ = database.QueryRow(`SELECT COUNT(*) FROM device_wns_channels WHERE device_id = ?`, devID).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("expected expired channel row to be deleted, still found %d", remaining)
	}
}
