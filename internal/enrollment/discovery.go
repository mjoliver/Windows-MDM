package enrollment

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

const (
	enrollNS        = "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
	soapNS          = "http://www.w3.org/2003/05/soap-envelope"
	addrNS          = "http://www.w3.org/2005/08/addressing"
	wsuNS           = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	wsseNS          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	wstNS           = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
	discoveryAction = "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse"
)

// Handler handles all MS-MDE2 enrollment SOAP endpoints.
type Handler struct {
	domain           string
	enrollmentDomain string
}

// NewHandler creates an enrollment handler for the given domain.
func NewHandler(domain, enrollmentDomain string) *Handler {
	return &Handler{
		domain:           domain,
		enrollmentDomain: enrollmentDomain,
	}
}

// HandleDiscovery handles the MS-MDE2 discovery SOAP request.
// Windows sends this first to find our enrollment endpoints.
// POST /EnterpriseEnrollment/Enrollment.svc
func (h *Handler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	// Windows sometimes sends a GET request to verify the endpoint is alive
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		slog.Error("discovery: reading request body", "err", err)
		writeSoapFault(w, "failed to read request body")
		return
	}

	// Parse the inbound SOAP envelope
	var envelope SOAPEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		slog.Error("discovery: parsing SOAP envelope", "err", err)
		writeSoapFault(w, "invalid SOAP envelope")
		return
	}

	req := envelope.Body.DiscoverRequest
	if req == nil {
		slog.Error("discovery: missing Discover element in body")
		writeSoapFault(w, "missing Discover element")
		return
	}

	slog.Info("discovery request received",
		"email", req.Request.EmailAddress,
		"device_type", req.Request.DeviceType,
		"request_version", req.Request.RequestVersion,
		"os_edition", req.Request.OSEdition,
	)

	// Build URLs for this server
	base := "https://" + h.domain
	resp := SOAPEnvelope{
		XMLName: xml.Name{Local: "s:Envelope"},
		XmlnsS:  soapNS,
		XmlnsA:  addrNS,
		Header: SOAPHeader{
			Action:    discoveryAction,
			RelatesTo: envelope.Header.MessageID,
		},
		Body: SOAPBody{
			DiscoverResponse: &DiscoverResponse{
				Xmlns: enrollNS,
				DiscoverResult: DiscoverResult{
					// Federated = OIDC webview login
					AuthPolicy:                 "Federated",
					EnrollmentVersion:          "4.0",
					EnrollmentPolicyServiceUrl: base + "/xcep",
					EnrollmentServiceUrl:       base + "/wstep",
					AuthenticationServiceUrl:   base + "/auth/login?flow=enroll",
				},
			},
		},
	}

	writeSoapResponse(w, resp, discoveryAction)
}

// ── SOAP helpers ──────────────────────────────────────────────────────────────

// writeSoapResponse serialises and sends a SOAP envelope as the HTTP response.
func writeSoapResponse(w http.ResponseWriter, envelope SOAPEnvelope, action string) {
	data, err := xml.Marshal(envelope)
	if err != nil {
		slog.Error("serialising SOAP response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// ── WCF SOAP Prefix Hack ─────────────────────────────────────────────────
	// Go's encoding/xml package cannot elegantly unmarshal generic namespaces while
	// marshaling strict legacy prefixes. MS-MDE2 strictly enforces these precise
	// prefixes on outbound XML. We manually inject them here to guarantee compliance.
	xmlStr := string(data)
	replacements := map[string]string{
		"<Envelope":                 "<s:Envelope",
		"</Envelope>":               "</s:Envelope>",
		"<Header>":                  "<s:Header>",
		"</Header>":                 "</s:Header>",
		"<Body>":                    "<s:Body>",
		"</Body>":                   "</s:Body>",
		"<Fault>":                   "<s:Fault>",
		"</Fault>":                  "</s:Fault>",
		"<Code>":                    "<s:Code>",
		"</Code>":                   "</s:Code>",
		"<Value>":                   "<s:Value>",
		"</Value>":                  "</s:Value>",
		"<Reason>":                  "<s:Reason>",
		"</Reason>":                 "</s:Reason>",
		"<Text>":                    "<s:Text>",
		"</Text>":                   "</s:Text>",
		"<Action>":                  `<a:Action s:mustUnderstand="1">`,
		"</Action>":                 "</a:Action>",
		"<RelatesTo>":               "<a:RelatesTo>",
		"</RelatesTo>":              "</a:RelatesTo>",
		"<MessageID>":               "<a:MessageID>",
		"</MessageID>":              "</a:MessageID>",
		"<ActivityId":               "<a:ActivityId",
		"</ActivityId>":             "</a:ActivityId>",
		"<To>":                      `<a:To s:mustUnderstand="1">`,
		"</To>":                     "</a:To>",
		"<Security>":                `<o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">`,
		"</Security>":               "</o:Security>",
		"<Timestamp":                "<u:Timestamp",
		"</Timestamp>":              "</u:Timestamp>",
		"<Created>":                 "<u:Created>",
		"</Created>":                "</u:Created>",
		"<Expires>":                 "<u:Expires>",
		"</Expires>":                "</u:Expires>",
		"<SecurityTokenReference":   "<wsse:SecurityTokenReference",
		"</SecurityTokenReference>": "</wsse:SecurityTokenReference>",
		"<KeyIdentifier":            "<wsse:KeyIdentifier",
		"</KeyIdentifier>":          "</wsse:KeyIdentifier>",
		"<BinarySecurityToken":      "<BinarySecurityToken",
		"</BinarySecurityToken>":    "</BinarySecurityToken>",
		"Base64Binary":              "base64binary",

		// XCEP Policies (px)
		"<GetPoliciesResponse":         "<px:GetPoliciesResponse",
		"</GetPoliciesResponse>":       "</px:GetPoliciesResponse>",
		"<response>":                   "<px:response>",
		"</response>":                  "</px:response>",
		"<policyID>":                   "<px:policyID>",
		"</policyID>":                  "</px:policyID>",
		"<policyFriendlyName>":         "<px:policyFriendlyName>",
		"</policyFriendlyName>":        "</px:policyFriendlyName>",
		"<nextUpdateHours>":            "<px:nextUpdateHours>",
		"</nextUpdateHours>":           "</px:nextUpdateHours>",
		"<policies>":                   "<px:policies>",
		"</policies>":                  "</px:policies>",
		"<policy>":                     "<px:policy>",
		"</policy>":                    "</px:policy>",
		"<oidReference>":               "<px:oidReference>",
		"</oidReference>":              "</px:oidReference>",
		"<cAs>":                        "<px:cAs>",
		"</cAs>":                       "</px:cAs>",
		"<cA>":                         "<px:cA>",
		"</cA>":                        "</px:cA>",
		"<attributes>":                 "<px:attributes>",
		"</attributes>":                "</px:attributes>",
		"<commonName>":                 "<px:commonName>",
		"</commonName>":                "</px:commonName>",
		"<policySchema>":               "<px:policySchema>",
		"</policySchema>":              "</px:policySchema>",
		"<certificateValidity>":        "<px:certificateValidity>",
		"</certificateValidity>":       "</px:certificateValidity>",
		"<validityPeriodSeconds>":      "<px:validityPeriodSeconds>",
		"</validityPeriodSeconds>":     "</px:validityPeriodSeconds>",
		"<renewalPeriodSeconds>":       "<px:renewalPeriodSeconds>",
		"</renewalPeriodSeconds>":      "</px:renewalPeriodSeconds>",
		"<permission>":                 "<px:permission>",
		"</permission>":                "</px:permission>",
		"<enroll>":                     "<px:enroll>",
		"</enroll>":                    "</px:enroll>",
		"<autoEnroll>":                 "<px:autoEnroll>",
		"</autoEnroll>":                "</px:autoEnroll>",
		"<privateKeyAttributes>":       "<px:privateKeyAttributes>",
		"</privateKeyAttributes>":      "</px:privateKeyAttributes>",
		"<minimalKeyLength>":           "<px:minimalKeyLength>",
		"</minimalKeyLength>":          "</px:minimalKeyLength>",
		"<keySpec>":                    "<px:keySpec>",
		"</keySpec>":                   "</px:keySpec>",
		"<keyUsageProperty>":           "<px:keyUsageProperty>",
		"</keyUsageProperty>":          "</px:keyUsageProperty>",
		"<permissions>":                "<px:permissions>",
		"</permissions>":               "</px:permissions>",
		"<allowedKeyUsage>":            "<px:allowedKeyUsage>",
		"</allowedKeyUsage>":           "</px:allowedKeyUsage>",
		"<algorithmOIDReference>":      "<px:algorithmOIDReference>",
		"</algorithmOIDReference>":     "</px:algorithmOIDReference>",
		"<hashAlgorithmOIDReference>":  "<px:hashAlgorithmOIDReference>",
		"</hashAlgorithmOIDReference>": "</px:hashAlgorithmOIDReference>",
		"<uriReference>":               "<px:uriReference>",
		"</uriReference>":              "</px:uriReference>",
		"<renewal>":                    "<px:renewal>",
		"</renewal>":                   "</px:renewal>",
		"<cARThumbs>":                  "<px:cARThumbs>",
		"</cARThumbs>":                 "</px:cARThumbs>",
		"<thumbprint>":                 "<px:thumbprint>",
		"</thumbprint>":                "</px:thumbprint>",

		// WSTEP (wst)
		"<RequestSecurityTokenResponseCollection":   "<wst:RequestSecurityTokenResponseCollection",
		"</RequestSecurityTokenResponseCollection>": "</wst:RequestSecurityTokenResponseCollection>",
		"<RequestSecurityTokenResponse>":            "<wst:RequestSecurityTokenResponse>",
		"</RequestSecurityTokenResponse>":           "</wst:RequestSecurityTokenResponse>",
		"<TokenType>":                               "<wst:TokenType>",
		"</TokenType>":                              "</wst:TokenType>",
		"<DispositionMessage>":                      "<px:DispositionMessage>",
		"</DispositionMessage>":                     "</px:DispositionMessage>",
		"<RequestID>":                               "<px:RequestID>",
		"</RequestID>":                              "</px:RequestID>",
		"<RequestedSecurityToken>":                  "<wst:RequestedSecurityToken>",
		"</RequestedSecurityToken>":                 "</wst:RequestedSecurityToken>",
		"<RequestedUnattachedReference>":            "<wst:RequestedUnattachedReference>",
		"</RequestedUnattachedReference>":           "</wst:RequestedUnattachedReference>",
	}
	for src, target := range replacements {
		xmlStr = strings.ReplaceAll(xmlStr, src, target)
	}

	// Set headers and write
	responseBytes := []byte(xmlStr)
	w.Header().Set("Content-Type", fmt.Sprintf("application/soap+xml; charset=utf-8; action=\"%s\"", action))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(responseBytes)))
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)

	// Opt-in debug dump of the last SOAP response (off by default). Writing on
	// every request would race across goroutines, leak certificate material to
	// disk, and pollute the working directory.
	if os.Getenv("LATCHZ_DEBUG_SOAP") != "" {
		_ = os.WriteFile("last_soap_response.xml", responseBytes, 0600)
	}
}

// writeSoapFault sends a SOAP fault response (protocol-level error to the device).
func writeSoapFault(w http.ResponseWriter, reason string) {
	fault := SOAPEnvelope{
		XMLName: xml.Name{Local: "s:Envelope"},
		XmlnsS:  soapNS,
		XmlnsA:  addrNS,
		Header:  SOAPHeader{Action: "http://schemas.microsoft.com/ws/2005/05/envelope/none"},
		Body: SOAPBody{
			Fault: &SOAPFault{
				Code:   FaultCode{Value: FaultSubCode{Value: "s:Receiver"}},
				Reason: FaultReason{Text: reason},
			},
		},
	}
	writeSoapResponse(w, fault, "http://schemas.microsoft.com/ws/2005/05/envelope/none")
}

// parseSOAPEnvelope reads and parses a SOAP request body.
func parseSOAPEnvelope(r *http.Request) (*SOAPEnvelope, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	var env SOAPEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parsing SOAP: %w", err)
	}
	return &env, nil
}
