package enrollment

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/testutil"
)

func wstepEnvelope(enrollToken, csrB64, hwid string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <s:Header>
    <a:MessageID>urn:uuid:test-message-id</a:MessageID>
    <wsse:Security><wsse:BinarySecurityToken>%s</wsse:BinarySecurityToken></wsse:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:TokenType>tok</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="base64binary">%s</wsse:BinarySecurityToken>
      <ac:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ac:ContextItem Name="HWDevID"><ac:Value>%s</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="DeviceName"><ac:Value>Test PC</ac:Value></ac:ContextItem>
      </ac:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, enrollToken, csrB64, hwid)
}

func TestHandleWSTEP_IssuesCertAndCreatesDevice(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	h := NewHandler("mdm.example.com", "example.com")

	_, csrDER := testutil.GenerateKeyCSR(t, "PaneMDMClient")
	body := wstepEnvelope("enroll-token", base64.StdEncoding.EncodeToString(csrDER), "HW-WSTEP")

	validate := func(tok string) (string, error) { return "user@example.com", nil }
	req := httptest.NewRequest("POST", "/wstep", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleWSTEP(ca, database.DB, validate)(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "RequestSecurityTokenResponse") {
		t.Fatalf("missing RSTR in response: %s", w.Body.String())
	}

	var enrolledBy string
	if err := database.QueryRow(`SELECT enrolled_by FROM devices WHERE hardware_id = 'HW-WSTEP'`).Scan(&enrolledBy); err != nil {
		t.Fatalf("device not created: %v", err)
	}
	if enrolledBy != "user@example.com" {
		t.Fatalf("enrolled_by = %q", enrolledBy)
	}
	var certs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM certificates WHERE cert_type = 'device'`).Scan(&certs); err != nil {
		t.Fatal(err)
	}
	if certs != 1 {
		t.Fatalf("expected 1 issued device cert, got %d", certs)
	}
}

func TestHandleWSTEP_RejectsInvalidToken(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	h := NewHandler("mdm.example.com", "example.com")
	_, csrDER := testutil.GenerateKeyCSR(t, "x")
	body := wstepEnvelope("bad", base64.StdEncoding.EncodeToString(csrDER), "HW-X")

	validate := func(tok string) (string, error) { return "", fmt.Errorf("invalid") }
	req := httptest.NewRequest("POST", "/wstep", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleWSTEP(ca, database.DB, validate)(w, req)

	if !strings.Contains(w.Body.String(), "Fault") {
		t.Fatalf("expected a SOAP fault, got: %s", w.Body.String())
	}
	var n int
	database.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
	if n != 0 {
		t.Fatalf("no device should be created on invalid token, got %d", n)
	}
}

func TestHandleDiscovery(t *testing.T) {
	h := NewHandler("mdm.example.com", "example.com")
	body := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header><a:MessageID>urn:uuid:id</a:MessageID></s:Header>
  <s:Body>
    <Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
      <request><EmailAddress>user@example.com</EmailAddress><DeviceType>CIMClient_Windows</DeviceType></request>
    </Discover>
  </s:Body>
</s:Envelope>`
	req := httptest.NewRequest("POST", "/EnterpriseEnrollment/Enrollment.svc", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleDiscovery(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	out := w.Body.String()
	for _, want := range []string{"/xcep", "/wstep", "Federated"} {
		if !strings.Contains(out, want) {
			t.Fatalf("discovery response missing %q: %s", want, out)
		}
	}
}

// wstepRenewalEnvelope omits the WS-Security enrollment token (renewal path).
func wstepRenewalEnvelope(csrB64, hwid string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <s:Header><a:MessageID>urn:uuid:renew</a:MessageID></s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:RequestType>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep/Renew</wst:RequestType>
      <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="base64binary">%s</wsse:BinarySecurityToken>
      <ac:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ac:ContextItem Name="HWDevID"><ac:Value>%s</ac:Value></ac:ContextItem>
      </ac:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`, csrB64, hwid)
}

func TestHandleWSTEP_Renewal(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-RENEW2")
	cert := testutil.IssueClientCert(t, ca, deviceID, "old") // existing cert
	h := NewHandler("mdm.example.com", "example.com")

	// The token validator must NOT be consulted for a cert renewal.
	validate := func(string) (string, error) { return "", fmt.Errorf("token path must not run for renewal") }
	newRenewalReq := func() *http.Request {
		_, csrDER := testutil.GenerateKeyCSR(t, "new")
		body := wstepRenewalEnvelope(base64.StdEncoding.EncodeToString(csrDER), "HW-RENEW2")
		return httptest.NewRequest("POST", "/wstep", strings.NewReader(body))
	}
	deviceCerts := func() int {
		var n int
		database.QueryRow(`SELECT COUNT(*) FROM certificates WHERE cert_type = 'device' AND device_id = ?`, deviceID).Scan(&n)
		return n
	}

	t.Run("direct mTLS renewal issues a new cert (proof-of-possession)", func(t *testing.T) {
		req := newRenewalReq()
		req.TLS = testutil.ClientTLSState(cert)
		w := httptest.NewRecorder()
		h.HandleWSTEP(ca, database.DB, validate)(w, req)
		if w.Code != 200 {
			t.Fatalf("mTLS renewal failed: status %d body=%s", w.Code, w.Body.String())
		}
		if deviceCerts() != 2 {
			t.Fatalf("expected original + renewed cert (2), got %d", deviceCerts())
		}
	})

	t.Run("proxy-header-only renewal is rejected (no proof-of-possession)", func(t *testing.T) {
		// An attacker holding only the (public) cert PEM cannot mint a new cert:
		// renewal requires direct mTLS, so the header is ignored and no token is
		// present → SOAP fault, no additional cert issued.
		before := deviceCerts()
		req := newRenewalReq()
		req.Header.Set("X-Forwarded-Client-Cert",
			url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))))
		w := httptest.NewRecorder()
		h.HandleWSTEP(ca, database.DB, validate)(w, req)
		if !strings.Contains(w.Body.String(), "Fault") {
			t.Fatalf("expected a SOAP fault for proxy-header renewal, got: %s", w.Body.String())
		}
		if deviceCerts() != before {
			t.Fatalf("no cert should be minted via the proxy header (forgery), before=%d after=%d", before, deviceCerts())
		}
	})
}

func FuzzParseSOAPEnvelope(f *testing.F) {
	f.Add([]byte(`<s:Envelope xmlns:s="x"><s:Body/></s:Envelope>`))
	f.Add([]byte(`<Discover><request><EmailAddress>a</EmailAddress></request></Discover>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req := httptest.NewRequest("POST", "/x", bytes.NewReader(data))
		_, _ = parseSOAPEnvelope(req) // must never panic
	})
}
