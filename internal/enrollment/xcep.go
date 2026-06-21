package enrollment

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/latchzmdm/latchz/internal/pki"
)

const (
	xcepNS       = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
	xcepAction   = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"

	// Key usage values
	keySpecKeyExchange = 1
	keyUsageEncrypt    = 32
)

// HandleXCEP handles the MS-XCEP GetPolicies SOAP request.
// Windows calls this after discovery to learn what kind of certificate to request.
// We return a policy requiring a 2048-bit RSA key for client auth.
// POST /xcep
func (h *Handler) HandleXCEP(ca *pki.CA) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		env, err := parseSOAPEnvelope(r)
		if err != nil {
			slog.Error("xcep: parsing request", "err", err)
			writeSoapFault(w, "invalid SOAP request")
			return
		}

		if env.Body.GetPoliciesRequest == nil {
			slog.Error("xcep: missing GetPolicies element")
			writeSoapFault(w, "missing GetPolicies element")
			return
		}

		// Extract the enrollment token from the WS-Security header
		// Windows sends the token it received after OIDC login here
		if env.Header.Security == nil || env.Header.Security.BinarySecurityToken == nil {
			slog.Warn("xcep: request has no security token")
			// Don't fail here — XCEP doesn't strictly require auth in all implementations
			// WSTEP will enforce auth
		}

		slog.Info("xcep: GetPolicies request received")

		// Get our CA's certificate thumbprint to include in the response
		caCertPEM := ca.CertPEM()
		caThumbprint := fmt.Sprintf("%x", sha1OfPEM(caCertPEM))

		resp := SOAPEnvelope{
			XMLName:  xml.Name{Local: "s:Envelope"},
			XmlnsS:   soapNS,
			XmlnsA:   addrNS,
			XmlnsXCEP: xcepNS,
			Header: SOAPHeader{
				Action:    xcepAction,
				RelatesTo: env.Header.MessageID,
			},
			Body: SOAPBody{
				GetPoliciesResponse: &GetPoliciesResponse{
					Xmlns: xcepNS,
					Response: XCEPResponse{
						PolicyID:           "{B3C1DDA9-E2BA-4D69-B01C-65A1F3AE1C80}",
						PolicyFriendlyName: "Latchz MDM Client Certificate",
						NextUpdateHours:    24,
						Policies: XCEPPolicies{
							Policy: []XCEPPolicy{
								{
									OIDReference: 0,
									CAs:          XCEPPolicyCAs{CA: []int{0}},
									Attributes: XCEPPolicyAttribs{
										CommonName:   "PaneMDMClient",
										PolicySchema: 3,
										CertificateValidity: XCEPValidity{
											ValidityPeriodSeconds: 365 * 24 * 3600,      // 1 year
											RenewalPeriodSeconds:  30 * 24 * 3600,        // renew 30 days before expiry
										},
										Permission: XCEPPermission{
											Enroll:     true,
											AutoEnroll: false,
										},
										PrivateKeyAttributes: XCEPPrivKey{
											MinimalKeyLength:      2048,
											KeySpec:               keySpecKeyExchange,
											KeyUsageProperty:      keyUsageEncrypt,
											AlgorithmOIDReference: 0, // RSA
											Permissions: XCEPKeyPermissions{
												AllowedKeyUsage: 0xA0, // AT_KEYEXCHANGE | AT_SIGNATURE
											},
										},
										HashAlgorithmOIDReference: 1, // SHA-256
									},
								},
							},
						},
					},
					CAs: &XCEPCAs{
						CA: []XCEPCAEntry{
							{
								UriReference: "https://" + h.domain + "/pki/ca.pem",
								Renewal:      "0",
								PolicyID:     "{B3C1DDA9-E2BA-4D69-B01C-65A1F3AE1C80}",
								CarThumbs:    XCEPThumbs{Thumbprint: caThumbprint},
							},
						},
					},
				},
			},
		}

		writeSoapResponse(w, resp, xcepAction)
	}
}

// HandleCADownload serves the root CA certificate in PEM format.
// Clients can download and install this to trust our CA.
// GET /pki/ca.pem
func (h *Handler) HandleCADownload(ca *pki.CA) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="pane-ca.pem"`)
		w.Write(ca.CertPEM())
	}
}
