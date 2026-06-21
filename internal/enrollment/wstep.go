package enrollment

import (
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/pki"
)

const (
	wstepAction         = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
	wstepNS             = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	wstepTokenType      = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken"
	wstepCertValueType  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	wstepCSRValueType   = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
	wstepKeyIdValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#ThumbprintSHA1"
	wstepProvisionDocValueType = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
	wstepEncodingType          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"

	// OMA-DM provisioning XML injected into the enrollment response.
	// This is the initial management payload Windows installs after enrollment.
	provisioningXMLTemplate = `<wap-provisioningdoc version="1.1">
  <characteristic type="CertificateStore">
    <characteristic type="Root">
      <characteristic type="System">
        <characteristic type="%s">
          <parm name="EncodedCertificate" value="%s"/>
        </characteristic>
      </characteristic>
    </characteristic>
    <characteristic type="My">
      <characteristic type="User">
        <characteristic type="%s">
          <parm name="EncodedCertificate" value="%s"/>
        </characteristic>
      </characteristic>
    </characteristic>
  </characteristic>
  <characteristic type="APPLICATION">
    <parm name="APPID" value="w7"/>
    <parm name="PROVIDER-ID" value="PaneMDM"/>
    <parm name="NAME" value="Latchz MDM"/>
    <parm name="ADDR" value="%s"/>
    <parm name="CONNRETRYFREQ" value="6"/>
    <parm name="INITIALBACKOFFTIME" value="30000"/>
    <parm name="MAXBACKOFFTIME" value="120000"/>
    <parm name="BACKCOMPATRETRYDISABLED" value=""/>
    <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml"/>
    <characteristic type="APPAUTH">
      <parm name="AAUTHLEVEL" value="CLIENT"/>
      <parm name="AAUTHTYPE" value="DIGEST"/>
      <parm name="AAUTHNAME" value="PaneMDM"/>
      <parm name="AAUTHSECRET" value="PaneMDM"/>
      <parm name="AAUTHDATA" value="nonce"/>
    </characteristic>
    <characteristic type="APPAUTH">
      <parm name="AAUTHLEVEL" value="APPSRV"/>
      <parm name="AAUTHTYPE" value="DIGEST"/>
      <parm name="AAUTHNAME" value="%s"/>
      <parm name="AAUTHSECRET" value="%s"/>
      <parm name="AAUTHDATA" value="nonce"/>
    </characteristic>
  </characteristic>
  <characteristic type="DMClient">
    <characteristic type="Provider">
      <characteristic type="PaneMDM">
        <parm name="EntDeviceName" value="%s"/>
        <parm name="RequireMessageSigning" value="false" datatype="boolean"/>
        <characteristic type="Poll">
          <parm name="NumberOfFirstRetries" value="8" datatype="integer"/>
          <parm name="IntervalForFirstSetOfRetries" value="15" datatype="integer"/>
          <parm name="NumberOfSecondRetries" value="5" datatype="integer"/>
          <parm name="IntervalForSecondSetOfRetries" value="3" datatype="integer"/>
          <parm name="NumberOfRemainingScheduledRetries" value="0" datatype="integer"/>
          <parm name="IntervalForRemainingScheduledRetries" value="1560" datatype="integer"/>
        </characteristic>
      </characteristic>
    </characteristic>
  </characteristic>
</wap-provisioningdoc>`

	// wstepResponseTemplate is the "Template Bomb": a byte-perfect SOAP response
	// that bypasses Go's xml.Marshal to satisfy the fragile Windows WCF parser.
	wstepResponseTemplate = `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` +
		`<s:Header>` +
		`<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>` +
		`<a:RelatesTo>%s</a:RelatesTo>` +
		`<a:To s:mustUnderstand="1">http://www.w3.org/2005/08/addressing/anonymous</a:To>` +
		`<o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">` +
		`<u:Timestamp u:Id="_0">` +
		`<u:Created>%s</u:Created>` +
		`<u:Expires>%s</u:Expires>` +
		`</u:Timestamp>` +
		`</o:Security>` +
		`</s:Header>` +
		`<s:Body>` +
		`<RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">` +
		`<RequestSecurityTokenResponse%s>` +
		`<TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>` +
		`<DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>` +
		`<RequestedSecurityToken>` +
		`<BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">%s</BinarySecurityToken>` +
		`</RequestedSecurityToken>` +
		`<RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>` +
		`</RequestSecurityTokenResponse>` +
		`</RequestSecurityTokenResponseCollection>` +
		`</s:Body>` +
		`</s:Envelope>`
)

// DeviceInfo holds metadata extracted from the WSTEP AdditionalContext.
type DeviceInfo struct {
	DeviceType        string
	DeviceName        string
	HardwareID        string
	OSVersion         string
	OSEdition         string
	Manufacturer      string
	Model             string
	SerialNumber      string
	EnrolledUserEmail string
}

// HandleWSTEP handles the MS-WSTEP RequestSecurityToken SOAP request.
// This is the critical enrollment step:
//  1. Validates the enrollment token (from OIDC login)
//  2. Parses the device's CSR
//  3. Signs the CSR with our internal CA
//  4. Creates the device record in the database
//  5. Returns the signed certificate + OMA-DM server URL as a provisioning doc
//
// POST /wstep
func (h *Handler) HandleWSTEP(ca *pki.CA, db *sql.DB, validateToken func(token string) (email string, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		env, err := parseSOAPEnvelope(r)
		if err != nil {
			slog.Error("wstep: parsing SOAP request", "err", err)
			writeSoapFault(w, "invalid SOAP request")
			return
		}

		// ── Step 1: Validate the enrollment token ─────────────────────────
		if env.Header.Security == nil || env.Header.Security.BinarySecurityToken == nil {
			slog.Error("wstep: missing security token in header (device not authenticated)")
			writeSoapFault(w, "missing security token")
			return
		}

		tokenStr := strings.TrimSpace(env.Header.Security.BinarySecurityToken.Value)
		slog.Info("wstep: raw security token received", "tokenStr", tokenStr)
		
		tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
		if err == nil {
			tokenStr = string(tokenBytes)
		}

		userEmail, err := validateToken(tokenStr)
		if err != nil {
			slog.Warn("wstep: invalid enrollment token", "err", err)
			writeSoapFault(w, "invalid enrollment token")
			return
		}

		// ── Step 2: Parse the CSR from the request body ───────────────────
		rst := env.Body.RequestSecurityTokenRequest
		if rst == nil || rst.BinarySecurityToken == nil {
			slog.Error("wstep: missing RequestSecurityToken or BinarySecurityToken")
			writeSoapFault(w, "missing CSR")
			return
		}

		csrDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rst.BinarySecurityToken.Value))
		if err != nil {
			csrDER, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(rst.BinarySecurityToken.Value))
		}
		if err != nil {
			slog.Error("wstep: decoding CSR", "err", err)
			writeSoapFault(w, "invalid CSR encoding")
			return
		}

		// ── Step 3: Extract device info from AdditionalContext ────────────
		info := extractDeviceInfo(rst.AdditionalContext)
		info.EnrolledUserEmail = userEmail

		// ── Step 4: Create/update device record in DB ─────────────────────
		deviceID := uuid.New().String()
		_, err = db.ExecContext(r.Context(), dbpkg.Rebind(`
			INSERT INTO devices (id, hardware_id, device_name, os_version, manufacturer, model, serial_number, enrolled_by, compliance_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
			ON CONFLICT(hardware_id) DO UPDATE SET
				device_name = excluded.device_name,
				os_version = excluded.os_version,
				enrolled_by = excluded.enrolled_by,
				enrolled_at = CURRENT_TIMESTAMP,
				is_active = 1
		`),
			deviceID, info.HardwareID, info.DeviceName, info.OSVersion,
			info.Manufacturer, info.Model, info.SerialNumber, userEmail,
		)
		if err != nil {
			slog.Error("wstep: saving device to database", "err", err)
			writeSoapFault(w, "internal error saving device")
			return
		}

		// Fetch actual device ID
		var actualDeviceID string
		err = db.QueryRowContext(r.Context(),
			dbpkg.Rebind(`SELECT id FROM devices WHERE hardware_id = ?`), info.HardwareID,
		).Scan(&actualDeviceID)
		if err != nil {
			slog.Error("wstep: fetching device id", "err", err)
			writeSoapFault(w, "internal error")
			return
		}

		// ── Step 5: Sign the CSR with our CA ──────────────────────────────
		certPEM, err := ca.IssueDeviceCertFromDER(actualDeviceID, info.DeviceName, csrDER)
		if err != nil {
			slog.Error("wstep: issuing device certificate", "err", err, "device_id", actualDeviceID)
			writeSoapFault(w, "certificate issuance failed")
			return
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			writeSoapFault(w, "internal error")
			return
		}

		// ── Step 6: Build the provisioning document ───────────────────────
		omaDMURL := "https://" + h.domain + "/omadm?hwid=" + info.HardwareID
		caCertDER := ca.CertDER()
		caCertB64 := base64.StdEncoding.EncodeToString(caCertDER)
		caThumbprint := fmt.Sprintf("%X", sha1Bytes(caCertDER))

		deviceCertDER := block.Bytes
		deviceCertB64 := base64.StdEncoding.EncodeToString(deviceCertDER)
		deviceThumbprint := fmt.Sprintf("%X", sha1Bytes(deviceCertDER))

		provisioningXML := fmt.Sprintf(provisioningXMLTemplate,
			caThumbprint,     // Root CA Store Key
			caCertB64,        // Root CA Cert
			deviceThumbprint, // My Store Key
			deviceCertB64,    // Device Cert
			omaDMURL,         // APPLICATION ADDR
			info.HardwareID,  // APPAUTH APPSRV AAUTHNAME (using hardware ID as username)
			"dummy-secret",   // APPAUTH APPSRV AAUTHSECRET
			info.DeviceName,  // EntDeviceName
		)
		provisioningB64 := base64.StdEncoding.EncodeToString([]byte(provisioningXML))

		// ── Step 7: Build & Send WSTEP response (Template Bomb) ───────────
		now := time.Now().UTC()
		expires := now.Add(5 * time.Minute)

		contextAttr := ""
		if rst.Context != "" {
			contextAttr = fmt.Sprintf(` Context="%s"`, rst.Context)
		}

		rstr := fmt.Sprintf(wstepResponseTemplate,
			env.Header.MessageID,
			now.Format("2006-01-02T15:04:05.000Z"),
			expires.Format("2006-01-02T15:04:05.000Z"),
			contextAttr,
			provisioningB64,
		)

		slog.Info("Sending WSTEP response (Template Bomb)",
			"remote_addr", r.RemoteAddr,
			"hardware_id", info.HardwareID,
		)

		rstrBytes := []byte(rstr)
		w.Header().Set("Content-Type", `application/soap+xml; charset=utf-8; action="http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rstrBytes)))
		w.WriteHeader(http.StatusOK)
		w.Write(rstrBytes)
	}
}

// extractDeviceInfo pulls device metadata from the WSTEP AdditionalContext element.
func extractDeviceInfo(ctx AdditionalContext) DeviceInfo {
	info := DeviceInfo{}
	for _, item := range ctx.ContextItem {
		switch item.Name {
		case "DeviceType":
			info.DeviceType = item.Value
		case "DeviceName":
			info.DeviceName = item.Value
		case "HWDevID":
			info.HardwareID = item.Value
		case "OSVersion":
			info.OSVersion = item.Value
		case "OSEdition":
			info.OSEdition = item.Value
		case "Manufacturer":
			info.Manufacturer = item.Value
		case "Model":
			info.Model = item.Value
		case "SerialNumber":
			info.SerialNumber = item.Value
		}
	}

	// Fallback hardware ID
	if info.HardwareID == "" {
		info.HardwareID = uuid.New().String()
	}
	// Fallback device name
	if info.DeviceName == "" {
		info.DeviceName = "Unknown-Device"
	}

	return info
}

// sha1Bytes calculates the SHA-1 hash of a byte slice.
func sha1Bytes(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// keep xml import used
var _ = xml.Header
