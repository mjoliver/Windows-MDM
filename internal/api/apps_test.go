package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/msi"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestMSIAppLifecycleAndDeployment(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	dev1 := testutil.SeedDevice(t, database, "HW-APP-1")
	dev2 := testutil.SeedDevice(t, database, "HW-APP-2")

	// Stub msiInspectURL so auto-inspect works deterministically offline
	origInspect := msiInspectURL
	msiInspectURL = func(_ context.Context, rawURL string) (*msi.Metadata, error) {
		return &msi.Metadata{
			ProductCode:    "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}",
			ProductName:    "Google Chrome",
			ProductVersion: "157.0.8103.79",
			Manufacturer:   "Google LLC",
			UpgradeCode:    "{C1DFDF69-5945-32F2-A35E-EE94C99C7CF4}",
			SHA256:         "385A8817EC8513536E57E7177ACF226104E7F13910D83EA1BBFE39C3D9AC2D03",
			FileSizeBytes:  171630592,
		}, nil
	}
	t.Cleanup(func() { msiInspectURL = origInspect })

	// 1. Reject non-HTTPS content_url
	wBad := httptest.NewRecorder()
	h.HandleCreateApp(wBad, withRoute("POST", "/api/apps", `{"content_url":"http://dl.google.com/chrome.msi"}`, ""))
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for http:// MSI URL, got %d", wBad.Code)
	}

	// 2. Create app via auto-inspect with only content_url
	chromeURL := "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
	wCreate := httptest.NewRecorder()
	h.HandleCreateApp(wCreate, withRoute("POST", "/api/apps", `{"content_url":"`+chromeURL+`"}`, ""))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create app: want 201, got %d body=%s", wCreate.Code, wCreate.Body.String())
	}
	var created MSIApp
	if err := json.Unmarshal(wCreate.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "Google Chrome" || created.ProductCode != "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}" || created.CommandLine != "/quiet /norestart" {
		t.Fatalf("unexpected created app: %+v", created)
	}

	// 3. Duplicate ProductCode returns 409 Conflict
	wDup := httptest.NewRecorder()
	h.HandleCreateApp(wDup, withRoute("POST", "/api/apps", `{"content_url":"`+chromeURL+`"}`, ""))
	if wDup.Code != http.StatusConflict {
		t.Fatalf("duplicate app: want 409, got %d", wDup.Code)
	}

	// 4. Direct install on dev1 queues Add + Exec + 3 Gets
	wInst := httptest.NewRecorder()
	h.HandleInstallAppOnDevices(wInst, withRoute("POST", "/api/apps/"+created.ID+"/install", `{"device_ids":["`+dev1+`"]}`, created.ID))
	if wInst.Code != http.StatusOK {
		t.Fatalf("install on dev1: want 200, got %d body=%s", wInst.Code, wInst.Body.String())
	}

	var execPayload string
	if err := database.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND command_type = 'Exec'`, dev1).Scan(&execPayload); err != nil {
		t.Fatalf("expected Exec command in queue: %v", err)
	}
	if !strings.Contains(execPayload, `<MsiInstallJob id="{B3DB5E18-7FDA-3432-9931-2E60D41BD242}">`) {
		t.Fatalf("unexpected Exec payload: %s", execPayload)
	}

	// 5. Group assignment queues install on dev2, removal queues Delete uninstall
	if _, err := database.Exec(`INSERT INTO device_groups (id, name) VALUES ('grp-eng', 'Engineering')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO device_group_members (device_id, group_id) VALUES (?, 'grp-eng')`, dev2); err != nil {
		t.Fatal(err)
	}
	wGrpAdd := httptest.NewRecorder()
	h.HandleAssignAppGroups(wGrpAdd, withRoute("PUT", "/api/apps/"+created.ID+"/groups", `{"group_ids":["grp-eng"],"action":"add"}`, created.ID))
	if wGrpAdd.Code != http.StatusOK {
		t.Fatalf("assign group add: want 200, got %d body=%s", wGrpAdd.Code, wGrpAdd.Body.String())
	}
	var dev2Pending int
	if err := database.QueryRow(`SELECT COUNT(*) FROM command_queue WHERE device_id = ? AND status = 'pending'`, dev2).Scan(&dev2Pending); err != nil || dev2Pending != 5 {
		t.Fatalf("expected 5 pending commands on dev2 after group assign, got %d (err=%v)", dev2Pending, err)
	}

	// Check GET /api/devices/{id}/apps
	wDevApps := httptest.NewRecorder()
	h.HandleGetDeviceApps(wDevApps, withRoute("GET", "/api/devices/"+dev1+"/apps", "", dev1))
	if wDevApps.Code != http.StatusOK || !strings.Contains(wDevApps.Body.String(), "Google Chrome") {
		t.Fatalf("device apps: code=%d body=%s", wDevApps.Code, wDevApps.Body.String())
	}

	// Uninstall from dev1 queues Delete on product URI
	wUninst := httptest.NewRecorder()
	h.HandleUninstallAppOnDevices(wUninst, withRoute("POST", "/api/apps/"+created.ID+"/uninstall", `{"device_ids":["`+dev1+`"]}`, created.ID))
	if wUninst.Code != http.StatusOK {
		t.Fatalf("uninstall on dev1: want 200, got %d", wUninst.Code)
	}
	var delURI string
	if err := database.QueryRow(`SELECT oma_uri FROM command_queue WHERE device_id = ? AND command_type = 'Delete'`, dev1).Scan(&delURI); err != nil {
		t.Fatalf("expected Delete command on dev1: %v", err)
	}
	if !strings.Contains(delURI, "%7BB3DB5E18-7FDA-3432-9931-2E60D41BD242%7D") {
		t.Fatalf("unexpected Delete URI: %s", delURI)
	}

	// Delete app from catalog
	wDel := httptest.NewRecorder()
	h.HandleDeleteApp(wDel, withRoute("DELETE", "/api/apps/"+created.ID, "", created.ID))
	if wDel.Code != http.StatusOK {
		t.Fatalf("delete app: want 200, got %d", wDel.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestMSIContentRelayStripsAcceptEncodingAndSupportsRange(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)
	h.ConfigureContentRelay("https://mdm.lab.local", []byte("0123456789abcdef0123456789abcdef"))
	devID := testutil.SeedDevice(t, database, "HW-RELAY-1")

	rawMSI := []byte("D0CF11E0-FAKE-MSI-BINARY-PAYLOAD")
	upstreamURL := "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"

	h.SetContentHTTPClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if ae := req.Header.Get("Accept-Encoding"); ae != "" {
				t.Fatalf("upstream request must omit Accept-Encoding, got %q", ae)
			}
			if req.URL.String() != upstreamURL {
				t.Fatalf("unexpected upstream URL %q", req.URL.String())
			}
			hdr := make(http.Header)
			hdr.Set("Accept-Ranges", "bytes")
			hdr.Set("ETag", `"chrome-etag"`)

			if req.Method == http.MethodHead {
				hdr.Set("Content-Length", fmt.Sprintf("%d", len(rawMSI)))
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     hdr,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}

			if rng := req.Header.Get("Range"); rng == "bytes=9-16" {
				slice := rawMSI[9:17]
				hdr.Set("Content-Length", fmt.Sprintf("%d", len(slice)))
				hdr.Set("Content-Range", fmt.Sprintf("bytes 9-16/%d", len(rawMSI)))
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header:     hdr,
					Body:       io.NopCloser(bytes.NewReader(slice)),
				}, nil
			}

			hdr.Set("Content-Length", fmt.Sprintf("%d", len(rawMSI)))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     hdr,
				Body:       io.NopCloser(bytes.NewReader(rawMSI)),
			}, nil
		}),
	})

	origInspect := msiInspectURL
	msiInspectURL = func(_ context.Context, _ string) (*msi.Metadata, error) {
		return &msi.Metadata{
			ProductCode:    "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}",
			ProductName:    "Google Chrome",
			ProductVersion: "157.0.8103.79",
			Manufacturer:   "Google LLC",
			SHA256:         "385A8817EC8513536E57E7177ACF226104E7F13910D83EA1BBFE39C3D9AC2D03",
			FileSizeBytes:  int64(len(rawMSI)),
		}, nil
	}
	t.Cleanup(func() { msiInspectURL = origInspect })

	wCreate := httptest.NewRecorder()
	h.HandleCreateApp(wCreate, withRoute("POST", "/api/apps", `{"content_url":"`+upstreamURL+`"}`, ""))
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("create app: got %d %s", wCreate.Code, wCreate.Body.String())
	}
	var app MSIApp
	if err := json.Unmarshal(wCreate.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}

	wInst := httptest.NewRecorder()
	h.HandleInstallAppOnDevices(wInst, withRoute("POST", "/api/apps/"+app.ID+"/install", `{"device_ids":["`+devID+`"]}`, app.ID))
	if wInst.Code != http.StatusOK {
		t.Fatalf("install app: got %d", wInst.Code)
	}

	var execXML string
	if err := database.QueryRow(`SELECT payload FROM command_queue WHERE device_id = ? AND command_type = 'Exec'`, devID).Scan(&execXML); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(execXML, "<ContentURL>https://mdm.lab.local/mdm/apps/"+app.ID+"/") {
		t.Fatalf("expected signed relay URL first in Exec XML, got: %s", execXML)
	}

	r := chi.NewRouter()
	r.Get("/mdm/apps/{id}/{exp}/{sig}/package.msi", h.HandleServeAppContent)
	r.Head("/mdm/apps/{id}/{exp}/{sig}/package.msi", h.HandleServeAppContent)

	signed := h.SignedAppContentURL(app.ID, time.Now().UTC().Add(time.Hour))
	u, err := url.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}

	// 1. HEAD probe
	headReq := httptest.NewRequest(http.MethodHead, u.Path, nil)
	headReq.Header.Set("Accept-Encoding", "gzip, deflate")
	wHead := httptest.NewRecorder()
	r.ServeHTTP(wHead, headReq)
	if wHead.Code != http.StatusOK || wHead.Header().Get("Accept-Ranges") != "bytes" || wHead.Body.Len() != 0 {
		t.Fatalf("HEAD failed: code=%d headers=%v bodyLen=%d", wHead.Code, wHead.Header(), wHead.Body.Len())
	}

	// 2. Partial Range GET (simulating DoSvc with Accept-Encoding: gzip, deflate)
	rngReq := httptest.NewRequest(http.MethodGet, u.Path, nil)
	rngReq.Header.Set("Accept-Encoding", "gzip, deflate")
	rngReq.Header.Set("Range", "bytes=9-16")
	wRng := httptest.NewRecorder()
	r.ServeHTTP(wRng, rngReq)
	if wRng.Code != http.StatusPartialContent {
		t.Fatalf("Range GET: want 206, got %d body=%s", wRng.Code, wRng.Body.String())
	}
	if wRng.Header().Get("Content-Encoding") != "" {
		t.Fatalf("expected empty Content-Encoding, got %q", wRng.Header().Get("Content-Encoding"))
	}
	if wRng.Body.String() != "FAKE-MSI" {
		t.Fatalf("Range slice mismatch: got %q, want %q", wRng.Body.String(), "FAKE-MSI")
	}

	// 3. Tampered signature -> 403 Forbidden
	badPath := strings.Replace(u.Path, "/package.msi", "00/package.msi", 1)
	wBad := httptest.NewRecorder()
	r.ServeHTTP(wBad, httptest.NewRequest(http.MethodGet, badPath, nil))
	if wBad.Code != http.StatusForbidden {
		t.Fatalf("tampered sig: want 403, got %d", wBad.Code)
	}

	// 4. Expired token -> 403 Forbidden
	expiredURL, _ := url.Parse(h.SignedAppContentURL(app.ID, time.Now().UTC().Add(-time.Minute)))
	wExp := httptest.NewRecorder()
	r.ServeHTTP(wExp, httptest.NewRequest(http.MethodGet, expiredURL.Path, nil))
	if wExp.Code != http.StatusForbidden {
		t.Fatalf("expired sig: want 403, got %d", wExp.Code)
	}
}
