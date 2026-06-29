// Package enrollment implements the MS-MDE2 Windows device enrollment protocol.
// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2
package enrollment

import "encoding/xml"

// ── SOAP envelope types ───────────────────────────────────────────────────────

// SOAPEnvelope is the outer SOAP wrapper for all MS-MDE2 messages.
type SOAPEnvelope struct {
	XMLName   xml.Name
	XmlnsS    string     `xml:"xmlns:s,attr"`
	XmlnsA    string     `xml:"xmlns:a,attr"`
	XmlnsU    string     `xml:"xmlns:u,attr,omitempty"`
	XmlnsWSSE string     `xml:"xmlns:wsse,attr,omitempty"`
	XmlnsWST  string     `xml:"xmlns:wst,attr,omitempty"`
	XmlnsAC   string     `xml:"xmlns:ac,attr,omitempty"`
	XmlnsXCEP string     `xml:"xmlns:px,attr,omitempty"`
	XmlnsXSI  string     `xml:"xmlns:xsi,attr,omitempty"`
	XmlnsXSD  string     `xml:"xmlns:xsd,attr,omitempty"`
	Header    SOAPHeader `xml:"Header"`
	Body      SOAPBody   `xml:"Body"`
}

// SOAPHeader carries WS-Addressing and security headers.
type SOAPHeader struct {
	Action    string      `xml:"Action"`
	RelatesTo string      `xml:"RelatesTo,omitempty"`
	MessageID string      `xml:"MessageID,omitempty"`
	To        string      `xml:"To,omitempty"`
	Security  *WSSecurity `xml:"Security,omitempty"`
}

// WSSecurity is the WS-Security header element.
type WSSecurity struct {
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken,omitempty"`
	Timestamp           *WSTimestamp         `xml:"Timestamp,omitempty"`
}

// WSTimestamp is a WS-Security timestamp for message freshness.
type WSTimestamp struct {
	Id      string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	Created string `xml:"Created"`
	Expires string `xml:"Expires"`
}

// BinarySecurityToken holds the actual payload (cert or provision doc).
type BinarySecurityToken struct {
	Xmlns        string `xml:"xmlns,attr,omitempty"`
	ValueType    string `xml:"ValueType,attr"`
	EncodingType string `xml:"EncodingType,attr"`
	Value        string `xml:",chardata"`
}

// SOAPBody wraps the message payload. Only one field will be set per message.
type SOAPBody struct {
	// Inbound (parsed from Windows device)
	DiscoverRequest             *DiscoverRequest             `xml:"Discover"`
	GetPoliciesRequest          *GetPoliciesRequest          `xml:"GetPolicies"`
	RequestSecurityTokenRequest *RequestSecurityTokenRequest `xml:"RequestSecurityToken"`

	// Outbound (sent to Windows device)
	DiscoverResponse                       *DiscoverResponse                       `xml:"DiscoverResponse,omitempty"`
	GetPoliciesResponse                    *GetPoliciesResponse                    `xml:"GetPoliciesResponse,omitempty"`
	RequestSecurityTokenResponseCollection *RequestSecurityTokenResponseCollection `xml:"RequestSecurityTokenResponseCollection,omitempty"`

	// Fault
	Fault *SOAPFault `xml:"Fault,omitempty"`
}

// SOAPFault is returned when the server encounters an error.
type SOAPFault struct {
	Code   FaultCode   `xml:"Code"`
	Reason FaultReason `xml:"Reason"`
}

type FaultCode struct {
	Value FaultSubCode `xml:"Value"`
}

type FaultSubCode struct {
	Value string `xml:",chardata"`
}

type FaultReason struct {
	Text string `xml:"Text"`
}

// ── Discovery types (MS-MDE2 §3.1) ───────────────────────────────────────────

// DiscoverRequest is sent by Windows to find the MDM enrollment endpoints.
type DiscoverRequest struct {
	XMLName struct{}       `xml:"Discover"`
	Xmlns   string         `xml:"xmlns,attr"`
	Request DiscoverReqMsg `xml:"request"`
}

// DiscoverReqMsg contains the details of the discovery request.
type DiscoverReqMsg struct {
	EmailAddress       string `xml:"EmailAddress"`
	RequestVersion     string `xml:"RequestVersion"`
	DeviceType         string `xml:"DeviceType"`
	ApplicationVersion string `xml:"ApplicationVersion"`
	OSEdition          string `xml:"OSEdition"`
}

// DiscoverResponse tells Windows where our enrollment endpoints are.
type DiscoverResponse struct {
	XMLName        struct{}       `xml:"DiscoverResponse"`
	Xmlns          string         `xml:"xmlns,attr"`
	DiscoverResult DiscoverResult `xml:"DiscoverResult"`
}

// DiscoverResult contains the enrollment endpoint URLs and auth policy.
type DiscoverResult struct {
	// AuthPolicy tells Windows how to authenticate the user.
	// "Federated" = OIDC (we redirect to Google/Okta, they come back with a token)
	// "OnPremise"  = username/password form hosted on our server
	AuthPolicy string `xml:"AuthPolicy"`

	EnrollmentVersion string `xml:"EnrollmentVersion"`

	// EnrollmentPolicyServiceUrl: MS-XCEP endpoint (cert policy)
	EnrollmentPolicyServiceUrl string `xml:"EnrollmentPolicyServiceUrl"`

	// EnrollmentServiceUrl: MS-WSTEP endpoint (cert issuance)
	EnrollmentServiceUrl string `xml:"EnrollmentServiceUrl"`

	// AuthenticationServiceUrl: shown to user in webview for OIDC login
	// Only used when AuthPolicy=Federated
	AuthenticationServiceUrl string `xml:"AuthenticationServiceUrl,omitempty"`
}

// ── MS-XCEP types (Get certificate enrollment policy) ────────────────────────

// GetPoliciesRequest is the device asking "what kind of cert should I request?"
type GetPoliciesRequest struct {
	XMLName struct{}   `xml:"GetPolicies"`
	Xmlns   string     `xml:"xmlns,attr"`
	Client  XCEPClient `xml:"client"`
}

// XCEPClient identifies the client software version.
type XCEPClient struct {
	LastUpdate        string `xml:"lastUpdate"`
	PreferredLanguage string `xml:"preferredLanguage"`
}

// GetPoliciesResponse tells the device what cert parameters to use in its CSR.
type GetPoliciesResponse struct {
	XMLName  struct{}     `xml:"GetPoliciesResponse"`
	Xmlns    string       `xml:"xmlns,attr"`
	Response XCEPResponse `xml:"response"`
	CAs      *XCEPCAs     `xml:"cAs,omitempty"`
}

// XCEPResponse contains the certificate issuance policies.
type XCEPResponse struct {
	PolicyID           string       `xml:"policyID"`
	PolicyFriendlyName string       `xml:"policyFriendlyName"`
	NextUpdateHours    int          `xml:"nextUpdateHours"`
	Policies           XCEPPolicies `xml:"policies"`
}

// XCEPPolicies wraps the list of certificate policies.
type XCEPPolicies struct {
	Policy []XCEPPolicy `xml:"policy"`
}

// XCEPPolicy defines the certificate template parameters.
type XCEPPolicy struct {
	OIDReference int               `xml:"oidReference"`
	CAs          XCEPPolicyCAs     `xml:"cAs"`
	Attributes   XCEPPolicyAttribs `xml:"attributes"`
}

// XCEPPolicyCAs references which CAs can issue this certificate type.
type XCEPPolicyCAs struct {
	CA []int `xml:"cA"`
}

// XCEPPolicyAttribs describes the certificate requirements.
type XCEPPolicyAttribs struct {
	CommonName                string         `xml:"commonName"`
	PolicySchema              int            `xml:"policySchema"`
	CertificateValidity       XCEPValidity   `xml:"certificateValidity"`
	Permission                XCEPPermission `xml:"permission"`
	PrivateKeyAttributes      XCEPPrivKey    `xml:"privateKeyAttributes"`
	HashAlgorithmOIDReference int            `xml:"hashAlgorithmOIDReference"`
}

// XCEPValidity sets the certificate lifetime.
type XCEPValidity struct {
	ValidityPeriodSeconds int `xml:"validityPeriodSeconds"`
	RenewalPeriodSeconds  int `xml:"renewalPeriodSeconds"`
}

// XCEPPermission defines who can request this certificate type.
type XCEPPermission struct {
	Enroll     bool `xml:"enroll"`
	AutoEnroll bool `xml:"autoEnroll"`
}

// XCEPPrivKey describes the private key requirements.
type XCEPPrivKey struct {
	MinimalKeyLength      int                `xml:"minimalKeyLength"`
	KeySpec               int                `xml:"keySpec"`
	KeyUsageProperty      int                `xml:"keyUsageProperty"`
	Permissions           XCEPKeyPermissions `xml:"permissions"`
	AlgorithmOIDReference int                `xml:"algorithmOIDReference"`
}

// XCEPKeyPermissions defines key permissions.
type XCEPKeyPermissions struct {
	AllowedKeyUsage int `xml:"allowedKeyUsage"`
}

// XCEPCAs lists the CA certificates trusted for enrollment.
type XCEPCAs struct {
	CA []XCEPCAEntry `xml:"cA"`
}

// XCEPCAEntry represents a CA certificate with its thumbprint.
type XCEPCAEntry struct {
	UriReference string     `xml:"uriReference"`
	Renewal      string     `xml:"renewal"`
	PolicyID     string     `xml:"policyID"`
	CarThumbs    XCEPThumbs `xml:"cARThumbs"`
}

// XCEPThumbs holds the CA certificate thumbprint.
type XCEPThumbs struct {
	Thumbprint string `xml:"thumbprint"`
}

// ── MS-WSTEP types (WS-Trust certificate enrollment) ─────────────────────────

// RequestSecurityTokenRequest is the device's CSR submission.
type RequestSecurityTokenRequest struct {
	Context             string               `xml:"Context,attr,omitempty"`
	TokenType           string               `xml:"TokenType"`
	RequestType         string               `xml:"RequestType"`
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken"` // the CSR
	AdditionalContext   AdditionalContext    `xml:"AdditionalContext"`
}

// AdditionalContext contains device metadata sent during enrollment.
type AdditionalContext struct {
	Xmlns       string        `xml:"xmlns,attr"`
	ContextItem []ContextItem `xml:"ContextItem"`
}

// ContextItem is a key-value pair of device info.
type ContextItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value"`
}

// RequestSecurityTokenResponseCollection wraps the enrollment response.
type RequestSecurityTokenResponseCollection struct {
	XMLName                      struct{}                       `xml:"RequestSecurityTokenResponseCollection"`
	Xmlns                        string                         `xml:"xmlns,attr"`
	RequestSecurityTokenResponse []RequestSecurityTokenResponse `xml:"RequestSecurityTokenResponse"`
}

// RequestSecurityTokenResponse contains the device certificate and OMA-DM URL.
type RequestSecurityTokenResponse struct {
	Context                      string              `xml:"Context,attr,omitempty"`
	TokenType                    string              `xml:"TokenType"`
	DispositionMessage           *DispositionMessage `xml:"DispositionMessage,omitempty"`
	RequestedSecurityToken       *RequestedSecToken  `xml:"RequestedSecurityToken"`
	RequestID                    *RequestID          `xml:"RequestID,omitempty"`
	RequestedUnattachedReference *UnattachedRef      `xml:"RequestedUnattachedReference,omitempty"`
}

type DispositionMessage struct {
	Xmlns string `xml:"xmlns,attr"`
	Value string `xml:",chardata"`
}

type RequestID struct {
	Xmlns string `xml:"xmlns,attr"`
	Value int    `xml:",chardata"`
}

// RequestedSecToken wraps the signed certificate.
type RequestedSecToken struct {
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken"`
}

// UnattachedRef provides a reference to the issued token (cert thumbprint).
type UnattachedRef struct {
	SecurityTokenReference SecurityTokenRef `xml:"SecurityTokenReference"`
}

// SecurityTokenRef identifies the token by its thumbprint.
type SecurityTokenRef struct {
	TokenType     string        `xml:"TokenType,attr"`
	KeyIdentifier KeyIdentifier `xml:"KeyIdentifier"`
}

// KeyIdentifier holds a certificate thumbprint.
type KeyIdentifier struct {
	ValueType string `xml:"ValueType,attr"`
	Value     string `xml:",chardata"`
}
