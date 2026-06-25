// Package mdm implements the OMA-DM / SyncML device management protocol.
// Reference: OMA-ERELD-DM-V1_2, MS-MDM spec
//
// Protocol summary:
//
//	Device → POST /omadm  (SyncML XML, mTLS with device cert)
//	Pane   → SyncML response (status ACKs + pending commands)
//	Device executes commands, reports results in next check-in
package mdm

import "encoding/xml"

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
	StatusNotModified   = "304"
	StatusBadRequest    = "400"
	StatusUnauthorized  = "401"
	StatusNotFound      = "404"
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

// ── Well-known OMA-URIs used by Pane ─────────────────────────────────────────

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
	OMADevDetailFreeStorage  = "./DevDetail/Ext/Microsoft/LocalTime"

	// DMClient — management server configuration
	OMADMClientPollFrequency = "./Vendor/MSFT/DMClient/Provider/PaneMDM/Poll/IntervalForRemainingScheduledRetries"

	// Policy CSPs
	OMAPolicyPrefix = "./Device/Vendor/MSFT/Policy/Config"

	// Remote actions
	OMAExecWipe   = "./Vendor/MSFT/RemoteWipe/doWipe"
	OMAExecLock   = "./Vendor/MSFT/RemoteLock/Lock"
	OMAExecReboot = "./Vendor/MSFT/Reboot/RebootNow"
)

// FirstCheckInURIs is the set of device info URIs we Get on the first session.
// This populates the device record with real hardware/OS info.
var FirstCheckInURIs = []string{
	OMADevInfoDevID,
	OMADevInfoMan,
	OMADevInfoMod,
	OMADevDetailSwV,
	OMADevDetailHwV,
	OMADevDetailOSPlatform,
	OMADevDetailOSBuild,
	OMADevDetailComputerName,
}
