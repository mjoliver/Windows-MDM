// Package mdm implements the OMA-DM / SyncML device management protocol.
// Reference: OMA-ERELD-DM-V1_2, MS-MDM spec
//
// Protocol summary:
//
//	Device → POST /omadm  (SyncML XML, mTLS with device cert)
//	Pane   → SyncML response (status ACKs + pending commands)
//	Device executes commands, reports results in next check-in
package mdm

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

const (
	syncMLNS    = "SYNCML:SYNCML1.2"
	syncMLDTD   = "1.2"
	syncMLProto = "DM/1.2"
	metInfNS    = "syncml:metinf"

	// Alert codes — what the device is telling us
	AlertCodeSession        = "1201" // Generic DM session
	AlertCodeClientInitMgmt = "1202" // Client-initiated management
	AlertCodeFirstSession   = "1200" // First session after enrollment (bootstrap)

	// Status codes
	StatusOK            = "200"
	StatusCreated       = "201"
	StatusAccepted      = "202"
	StatusNoContent     = "204"
	StatusNotModified   = "304"
	StatusBadRequest    = "400"
	StatusUnauthorized  = "401"
	StatusNotFound      = "404"
	StatusAlreadyExists = "418"
	StatusCommandFailed = "500"
	StatusNotExecuted   = "215"
	StatusAtomicFailed  = "507"
)

// SyncML is the root element of every OMA-DM message.
type SyncML struct {
	XMLName  xml.Name `xml:"SyncML"`
	Xmlns    string   `xml:"xmlns,attr,omitempty"`
	SyncHdr  SyncHdr  `xml:"SyncHdr"`
	SyncBody SyncBody `xml:"SyncBody"`
}

// SyncHdr identifies the message session, source and destination.
type SyncHdr struct {
	VerDTD    string `xml:"VerDTD"`   // Always "1.2"
	VerProto  string `xml:"VerProto"` // Always "DM/1.2"
	SessionID string `xml:"SessionID"`
	MsgID     string `xml:"MsgID"`
	Target    LocURI `xml:"Target"`
	Source    LocURI `xml:"Source"`
	RespURI   string `xml:"RespURI,omitempty"` // device tells us where to respond
}

// LocURI identifies a party (device or server) by URI.
type LocURI struct {
	LocURI string `xml:"LocURI"`
}

// SyncBody contains the sequence of commands and status responses.
type SyncBody struct {
	// Inbound from device
	Alerts   []Alert   `xml:"Alert"`
	Statuses []Status  `xml:"Status"`
	Results  []Results `xml:"Results"`
	Gets     []Get     `xml:"Get"`

	// Outbound to device
	Commands []interface{} `xml:",omitempty"` // mix of Get, Replace, Exec, Add, Delete

	Final *struct{} `xml:"Final"`
}

// Alert is sent by the device to indicate session type or important events.
type Alert struct {
	CmdID string `xml:"CmdID"`
	Data  string `xml:"Data"` // alert code e.g. "1201"
	Items []Item `xml:"Item,omitempty"`
}

// Status is an acknowledgement of a previous command or header.
type Status struct {
	MsgRef    string `xml:"MsgRef"` // which message this ACKs
	CmdRef    string `xml:"CmdRef"` // which command within that message
	CmdID     string `xml:"CmdID"`
	Cmd       string `xml:"Cmd"` // command name: "SyncHdr", "Get", "Replace", etc.
	TargetRef string `xml:"TargetRef,omitempty"`
	SourceRef string `xml:"SourceRef,omitempty"`
	Data      string `xml:"Data"` // status code: "200", "404", etc.
}

// Results carries the device's responses to Get commands.
type Results struct {
	MsgRef string `xml:"MsgRef"`
	CmdRef string `xml:"CmdRef"`
	CmdID  string `xml:"CmdID"`
	Items  []Item `xml:"Item"`
}

// Item is a leaf element containing an OMA-URI address and data.
type Item struct {
	Source *LocURI `xml:"Source,omitempty"`
	Target *LocURI `xml:"Target,omitempty"`
	Meta   *Meta   `xml:"Meta,omitempty"`
	Data   string  `xml:"Data,omitempty"`
	RawXML bool    `xml:"-"`
}

// MarshalXML emits escaped character data by default (required for ADMX-backed
// Policy CSP values like "<enabled/>"), or raw inner XML when RawXML is set
// (required by EnterpriseDesktopAppManagement CSP <MsiInstallJob> payloads).
func (i Item) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if !i.RawXML {
		type plainItem Item
		return e.EncodeElement(plainItem(i), start)
	}
	type rawData struct {
		Inner string `xml:",innerxml"`
	}
	aux := struct {
		Source *LocURI  `xml:"Source,omitempty"`
		Target *LocURI  `xml:"Target,omitempty"`
		Meta   *Meta    `xml:"Meta,omitempty"`
		Data   *rawData `xml:"Data,omitempty"`
	}{
		Source: i.Source,
		Target: i.Target,
		Meta:   i.Meta,
	}
	if i.Data != "" {
		aux.Data = &rawData{Inner: i.Data}
	}
	return e.EncodeElement(aux, start)
}

// Meta describes the format and type of item data.
type Meta struct {
	Format *MetaFormat `xml:"Format,omitempty"`
	Type   string      `xml:"Type,omitempty"`
}

type MetaFormat struct {
	Xmlns string `xml:"xmlns,attr"`
	Value string `xml:",chardata"`
}

// ── Outbound command types ────────────────────────────────────────────────────

// Get requests the current value of an OMA-URI from the device.
type Get struct {
	XMLName xml.Name `xml:"Get"`
	CmdID   string   `xml:"CmdID"`
	Items   []Item   `xml:"Item"`
}

// Replace sets the value of an OMA-URI on the device.
type Replace struct {
	XMLName xml.Name `xml:"Replace"`
	CmdID   string   `xml:"CmdID"`
	Items   []Item   `xml:"Item"`
}

// Add creates a new OMA-URI node on the device (used for app deployment).
type Add struct {
	XMLName xml.Name `xml:"Add"`
	CmdID   string   `xml:"CmdID"`
	Items   []Item   `xml:"Item"`
}

// Delete removes an OMA-URI node from the device.
type Delete struct {
	XMLName xml.Name `xml:"Delete"`
	CmdID   string   `xml:"CmdID"`
	Items   []Item   `xml:"Item"`
}

// Exec triggers an action on the device (remote lock, wipe, reboot, etc.)
type Exec struct {
	XMLName xml.Name `xml:"Exec"`
	CmdID   string   `xml:"CmdID"`
	Items   []Item   `xml:"Item"`
}

// ── Well-known OMA-URIs used by Latchz ───────────────────────────────────────

const (
	// DevInfo — populated on first check-in
	OMADevInfoDevID = "./DevInfo/DevId"
	OMADevInfoMan   = "./DevInfo/Man"
	OMADevInfoMod   = "./DevInfo/Mod"
	OMADevInfoLang  = "./DevInfo/Lang"

	// DevDetail — OS and hardware detail
	OMADevDetailSwV          = "./DevDetail/SwV" // OS version e.g. "10.0.22621.1"
	OMADevDetailHwV          = "./DevDetail/HwV" // BIOS/firmware version
	OMADevDetailOSPlatform   = "./DevDetail/Ext/Microsoft/OSPlatform"
	OMADevDetailOSBuild      = "./DevDetail/Ext/Microsoft/OSBuild"
	OMADevDetailComputerName = "./DevDetail/Ext/Microsoft/DNSComputerName"
	OMADevDetailLocalTime    = "./DevDetail/Ext/Microsoft/LocalTime"
	OMADevDetailSMBIOSSerial = "./DevDetail/Ext/Microsoft/SMBIOSSerialNumber"
	OMADevDetailTotalRAM     = "./DevDetail/Ext/Microsoft/TotalRAM"
	OMADevDetailTotalStorage = "./DevDetail/Ext/Microsoft/TotalStorage"
	OMADevDetailFreeStorage  = "./DevDetail/Ext/Microsoft/FreeStorage"

	// DeviceStatus & BitLocker CSPs — hardware & security posture telemetry
	OMADeviceStatusSecureBoot    = "./Device/Vendor/MSFT/DeviceStatus/SecureBootState"
	OMADeviceStatusTPMVersion    = "./Device/Vendor/MSFT/DeviceStatus/TPM/SpecificationVersion"
	OMADeviceStatusAntivirus     = "./Device/Vendor/MSFT/DeviceStatus/Antivirus/Status"
	OMADeviceStatusFirewall      = "./Device/Vendor/MSFT/DeviceStatus/Firewall/Status"
	OMABitLockerEncryptionStatus = "./Device/Vendor/MSFT/BitLocker/Status/DeviceEncryptionStatus"

	// DMClient — management server polling schedule & WNS push configuration
	OMADMClientPollNumRemaining = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Poll/NumberOfRemainingScheduledRetries"
	OMADMClientPollFrequency    = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Poll/IntervalForRemainingScheduledRetries"
	OMADMClientPollOnLogin      = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Poll/PollOnLogin"
	OMADMClientPushPFN          = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Push/PFN"
	OMADMClientPushChannelURI   = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Push/ChannelURI"
	OMADMClientPushStatus       = "./Device/Vendor/MSFT/DMClient/Provider/LatchzMDM/Push/Status"

	// Policy CSPs
	OMAPolicyPrefix = "./Device/Vendor/MSFT/Policy/Config"

	// EnterpriseDesktopAppManagement CSP — Win32 MSI deployment
	OMAEnterpriseDesktopMSIPrefix = "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI"

	// Remote actions
	OMAExecWipe   = "./Vendor/MSFT/RemoteWipe/doWipe"
	OMAExecLock   = "./Vendor/MSFT/RemoteLock/Lock"
	OMAExecReboot = "./Device/Vendor/MSFT/Reboot/RebootNow"
)

// CanonicalMSIProductCode normalizes an MSI ProductCode into "{UPPER-GUID}".
func CanonicalMSIProductCode(productCode string) string {
	s := strings.ToUpper(strings.TrimSpace(productCode))
	s = strings.ReplaceAll(s, "%7B", "{")
	s = strings.ReplaceAll(s, "%7D", "}")
	if s != "" && !strings.HasPrefix(s, "{") {
		s = "{" + s
	}
	if s != "" && !strings.HasSuffix(s, "}") {
		s = s + "}"
	}
	return s
}

// EncodeMSIProductURI builds an EnterpriseDesktopAppManagement MSI LocURI with
// curly braces encoded as %7B / %7D per the MS-MDM specification.
func EncodeMSIProductURI(productCode, leaf string) string {
	canon := CanonicalMSIProductCode(productCode)
	encoded := strings.ReplaceAll(strings.ReplaceAll(canon, "{", "%7B"), "}", "%7D")
	base := OMAEnterpriseDesktopMSIPrefix + "/" + encoded
	if leaf == "" {
		return base
	}
	return base + "/" + strings.TrimPrefix(leaf, "/")
}

// ParseMSIProductURI extracts the canonical "{UPPER-GUID}" ProductCode and
// trailing leaf node (e.g. "Status", "LastError", "LastErrorDesc", or "") from
// an EnterpriseDesktopAppManagement MSI LocURI.
func ParseMSIProductURI(rawURI string) (productCode, leaf string, ok bool) {
	u := strings.TrimSpace(rawURI)
	if !strings.HasPrefix(u, "./") {
		u = "./" + u
	}
	if strings.HasPrefix(u, "./Vendor/MSFT/") {
		u = strings.Replace(u, "./Vendor/", "./Device/Vendor/", 1)
	}
	prefix := OMAEnterpriseDesktopMSIPrefix + "/"
	if len(u) <= len(prefix) || !strings.EqualFold(u[:len(prefix)], prefix) {
		return "", "", false
	}
	rest := u[len(prefix):]
	seg := rest
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		seg = rest[:slash]
		leaf = rest[slash+1:]
	}
	if unesc, err := url.PathUnescape(seg); err == nil {
		seg = unesc
	}
	canon := CanonicalMSIProductCode(seg)
	if len(canon) < 3 {
		return "", "", false
	}
	return canon, leaf, true
}

// MSIStatusLabel maps an EnterpriseDesktopAppManagement CSP Status integer to
// a human-readable deployment state.
func MSIStatusLabel(code int) string {
	switch code {
	case 0:
		return "Uninstalled"
	case 10:
		return "Initialized"
	case 20:
		return "Downloading"
	case 25:
		return "Download Queued"
	case 30:
		return "Download Failed"
	case 40:
		return "Downloaded"
	case 48:
		return "Pending User Session"
	case 50:
		return "Installing"
	case 55:
		return "Pending Reboot"
	case 60:
		return "Install Failed"
	case 70:
		return "Installed"
	default:
		return fmt.Sprintf("Status %d", code)
	}
}

// FirstCheckInURIs is the set of device info and security posture URIs we Get
// on initial sessions (and on-demand posture refreshes).
var FirstCheckInURIs = []string{
	OMADevInfoDevID,
	OMADevInfoMan,
	OMADevInfoMod,
	OMADevDetailSwV,
	OMADevDetailHwV,
	OMADevDetailOSPlatform,
	OMADevDetailOSBuild,
	OMADevDetailComputerName,
	OMADevDetailSMBIOSSerial,
	OMADevDetailTotalRAM,
	OMADevDetailTotalStorage,
	OMADevDetailFreeStorage,
	OMADeviceStatusSecureBoot,
	OMADeviceStatusTPMVersion,
	OMADeviceStatusAntivirus,
	OMADeviceStatusFirewall,
	OMABitLockerEncryptionStatus,
}
