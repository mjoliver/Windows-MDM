package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateAppru(t *testing.T) {
	p := &Provider{baseURL: "https://mdm.example.com"}

	allowed := []string{
		"ms-app://windows.immersivecontrolpanel",
		"ms-appx-web://something",
		"ms-aad-brokerplugin://x",
		"https://mdm.example.com/return?a=b",
	}
	for _, a := range allowed {
		if _, ok := appruAllowed(a, p.baseURL); !ok {
			t.Errorf("expected appru %q to be allowed", a)
		}
	}

	rejected := []string{
		"https://evil.example/steal", // foreign origin
		"http://mdm.example.com/x",   // not https
		"javascript:alert(1)",
		"",
		"//evil.example",
		"data:text/html,x",
	}
	for _, a := range rejected {
		if _, ok := appruAllowed(a, p.baseURL); ok {
			t.Errorf("expected appru %q to be rejected", a)
		}
	}
}

func TestEnrollmentCallback_RejectsForeignAppru_NoTokenLeak(t *testing.T) {
	p := &Provider{
		jwtSecret: []byte("0123456789012345678901234567890123"),
		baseURL:   "https://mdm.example.com",
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/auth/callback", nil)
	p.handleEnrollmentCallback(w, req, "user@example.com", "https://evil.example/steal")

	if w.Code != 400 {
		t.Fatalf("expected 400 for foreign appru, got %d", w.Code)
	}
	// A JWT begins with the base64url header "eyJ"; it must NOT appear in the
	// rejection page (the token must not be exfiltrated).
	if strings.Contains(w.Body.String(), "eyJ") {
		t.Fatal("enrollment token leaked into the rejected-appru page")
	}
}

func TestEnrollmentCallback_ValidAppru(t *testing.T) {
	p := &Provider{
		jwtSecret: []byte("0123456789012345678901234567890123"),
		baseURL:   "https://mdm.example.com",
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/auth/callback", nil)
	p.handleEnrollmentCallback(w, req, "user@example.com", "ms-app://windows.immersivecontrolpanel")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "wresult") {
		t.Fatal("expected the token-posting form")
	}
}

func TestRenderEnrollMismatch_EscapesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	renderEnrollMismatch(w, "<script>alert(1)</script>", "a@b.com")
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("login_hint reflected unescaped (reflected XSS)")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("expected the value to be HTML-escaped")
	}
}

func TestRenderAccessDenied_EscapesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	renderAccessDenied(w, "<img src=x onerror=alert(1)>@evil")
	if strings.Contains(w.Body.String(), "<img src=x") {
		t.Fatal("email reflected unescaped (reflected XSS)")
	}
}
