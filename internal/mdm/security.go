package mdm

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// Defender Policy CSP nodes (all <Format>int</Format>)
	OMADefenderRealtimeMonitoring = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring"
	OMADefenderBehaviorMonitoring = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowBehaviorMonitoring"
	OMADefenderCloudProtection    = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection"
	OMADefenderCloudBlockLevel    = "./Device/Vendor/MSFT/Policy/Config/Defender/CloudBlockLevel"
	OMADefenderPUAProtection      = "./Device/Vendor/MSFT/Policy/Config/Defender/PUAProtection"
	OMADefenderNetworkProtection  = "./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection"
	OMADefenderCheckSigsBefore    = "./Device/Vendor/MSFT/Policy/Config/Defender/CheckForSignaturesBeforeRunningScan"

	// Defender CSP action nodes (<Exec>)
	OMADefenderExecScan            = "./Device/Vendor/MSFT/Defender/Scan"
	OMADefenderExecUpdateSignature = "./Device/Vendor/MSFT/Defender/UpdateSignature"

	// Firewall CSP profile nodes
	OMAFirewallDomainEnable   = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall"
	OMAFirewallPrivateEnable  = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall"
	OMAFirewallPublicEnable   = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall"
	OMAFirewallDomainInbound  = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DefaultInboundAction"
	OMAFirewallPrivateInbound = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DefaultInboundAction"
	OMAFirewallPublicInbound  = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DefaultInboundAction"
	OMAFirewallRulesPrefix    = "./Vendor/MSFT/Firewall/MdmStore/FirewallRules"
)

var validFirewallRuleKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// EndpointSecuritySpec describes desired Microsoft Defender Antivirus and
// Windows Defender Firewall baseline enforcement on a Windows 10/11 device.
type EndpointSecuritySpec struct {
	AllowRealtimeMonitoring bool
	AllowBehaviorMonitoring bool
	AllowCloudProtection    bool
	CloudBlockLevel         int // 0=Default, 2=High, 4=High+, 6=Zero Tolerance
	PUAProtection           int // 0=Disabled, 1=Block, 2=Audit
	EnableNetworkProtection int // 0=Disabled, 1=Block, 2=Audit
	CheckSigsBeforeScan     bool

	FirewallDomainEnabled  bool
	FirewallPrivateEnabled bool
	FirewallPublicEnabled  bool
	BlockInboundDomain     bool
	BlockInboundPrivate    bool
	BlockInboundPublic     bool
}

// FirewallRuleSpec describes a custom inbound or outbound Windows Firewall rule
// provisioned atomically under ./Vendor/MSFT/Firewall/MdmStore/FirewallRules/{RuleKey}.
type FirewallRuleSpec struct {
	RuleKey          string
	Name             string
	Description      string
	Direction        string // "IN" or "OUT"
	Action           int    // 0 = Block, 1 = Allow
	Protocol         int    // 6 = TCP, 17 = UDP, 1 = ICMPv4, 256 = Any
	LocalPortRanges  string // e.g. "443" or "8000-8080" (only valid for TCP/UDP)
	RemotePortRanges string
	Profiles         int // bitmask: 1=Domain, 2=Private, 4=Public, 7=All
	Enabled          bool
}

func boolIntStr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func boolWordStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// ValidCloudBlockLevel validates Microsoft Defender CloudBlockLevel values.
func ValidCloudBlockLevel(v int) bool {
	switch v {
	case 0, 2, 4, 6:
		return true
	default:
		return false
	}
}

// EnqueueEndpointSecurityBaseline queues OMA-DM Replace commands for Microsoft
// Defender Antivirus and Windows Defender Firewall profile baselines.
func EnqueueEndpointSecurityBaseline(dbConn *sql.DB, deviceID string, spec EndpointSecuritySpec) (int, error) {
	cbl := spec.CloudBlockLevel
	if !ValidCloudBlockLevel(cbl) {
		cbl = 2
	}
	pua := spec.PUAProtection
	if pua < 0 || pua > 2 {
		pua = 1
	}
	np := spec.EnableNetworkProtection
	if np < 0 || np > 2 {
		np = 1
	}

	items := []struct {
		uri string
		val string
	}{
		{OMADefenderRealtimeMonitoring, boolIntStr(spec.AllowRealtimeMonitoring)},
		{OMADefenderBehaviorMonitoring, boolIntStr(spec.AllowBehaviorMonitoring)},
		{OMADefenderCloudProtection, boolIntStr(spec.AllowCloudProtection)},
		{OMADefenderCloudBlockLevel, strconv.Itoa(cbl)},
		{OMADefenderPUAProtection, strconv.Itoa(pua)},
		{OMADefenderNetworkProtection, strconv.Itoa(np)},
		{OMADefenderCheckSigsBefore, boolIntStr(spec.CheckSigsBeforeScan)},
		{OMAFirewallDomainEnable, boolWordStr(spec.FirewallDomainEnabled)},
		{OMAFirewallPrivateEnable, boolWordStr(spec.FirewallPrivateEnabled)},
		{OMAFirewallPublicEnable, boolWordStr(spec.FirewallPublicEnabled)},
		{OMAFirewallDomainInbound, boolIntStr(spec.BlockInboundDomain)},
		{OMAFirewallPrivateInbound, boolIntStr(spec.BlockInboundPrivate)},
		{OMAFirewallPublicInbound, boolIntStr(spec.BlockInboundPublic)},
	}

	var queued int
	for _, it := range items {
		if _, err := EnqueueReplace(dbConn, deviceID, it.uri, it.val); err != nil {
			return queued, err
		}
		queued++
	}
	if _, err := EnqueueGet(dbConn, deviceID, OMADeviceStatusAntivirus); err == nil {
		queued++
	}
	if _, err := EnqueueGet(dbConn, deviceID, OMADeviceStatusFirewall); err == nil {
		queued++
	}
	return queued, nil
}

// RetractEndpointSecurityBaseline removes MDM Defender Policy CSP overrides from a device.
func RetractEndpointSecurityBaseline(dbConn *sql.DB, deviceID string) (int, error) {
	uris := []string{
		OMADefenderRealtimeMonitoring,
		OMADefenderBehaviorMonitoring,
		OMADefenderCloudProtection,
		OMADefenderCloudBlockLevel,
		OMADefenderPUAProtection,
		OMADefenderNetworkProtection,
		OMADefenderCheckSigsBefore,
	}
	var queued int
	for _, u := range uris {
		if _, err := EnqueueDelete(dbConn, deviceID, u); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

// EnqueueDefenderScan queues an immediate Microsoft Defender Antivirus Quick (1)
// or Full (2) scan via ./Device/Vendor/MSFT/Defender/Scan <Exec>.
func EnqueueDefenderScan(dbConn *sql.DB, deviceID, scanType string) (int, error) {
	payload := "1"
	if strings.EqualFold(strings.TrimSpace(scanType), "full") {
		payload = "2"
	}
	if _, err := EnqueueExec(dbConn, deviceID, OMADefenderExecScan, payload); err != nil {
		return 0, err
	}
	queued := 1
	if _, err := EnqueueGet(dbConn, deviceID, OMADeviceStatusAntivirus); err == nil {
		queued++
	}
	return queued, nil
}

// EnqueueDefenderSignatureUpdate queues an immediate security intelligence
// update via ./Device/Vendor/MSFT/Defender/UpdateSignature <Exec>.
func EnqueueDefenderSignatureUpdate(dbConn *sql.DB, deviceID string) (int, error) {
	if _, err := EnqueueExec(dbConn, deviceID, OMADefenderExecUpdateSignature, ""); err != nil {
		return 0, err
	}
	queued := 1
	if _, err := EnqueueGet(dbConn, deviceID, OMADeviceStatusAntivirus); err == nil {
		queued++
	}
	return queued, nil
}

// SanitizeFirewallRuleKey normalizes a human rule name into a safe Firewall CSP URI segment.
func SanitizeFirewallRuleKey(raw string) string {
	s := strings.TrimSpace(raw)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 48 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "LatchzRule"
	}
	return out
}

// BuildFirewallRuleAtomicOps builds the transactional <Atomic> child operations
// required by Microsoft's ./Vendor/MSFT/Firewall/MdmStore/FirewallRules/{RuleKey} CSP.
func BuildFirewallRuleAtomicOps(spec FirewallRuleSpec) ([]AtomicSubCommand, error) {
	key := strings.TrimSpace(spec.RuleKey)
	if !validFirewallRuleKeyRE.MatchString(key) {
		return nil, fmt.Errorf("invalid firewall rule_key %q", key)
	}
	dir := strings.ToUpper(strings.TrimSpace(spec.Direction))
	if dir != "IN" && dir != "OUT" {
		dir = "IN"
	}
	act := 0
	if spec.Action == 1 {
		act = 1
	}
	profiles := spec.Profiles
	if profiles <= 0 || profiles > 7 {
		profiles = 7
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = key
	}

	base := OMAFirewallRulesPrefix + "/" + key
	ops := []AtomicSubCommand{
		{CommandType: "Add", OMAURI: base + "/Name", Payload: name, Format: "chr"},
		{CommandType: "Add", OMAURI: base + "/Direction", Payload: dir, Format: "chr"},
		{CommandType: "Add", OMAURI: base + "/Profiles", Payload: strconv.Itoa(profiles), Format: "int"},
		{CommandType: "Add", OMAURI: base + "/Enabled", Payload: boolWordStr(spec.Enabled), Format: "bool"},
		{CommandType: "Add", OMAURI: base + "/Action/Type", Payload: strconv.Itoa(act), Format: "int"},
	}
	if desc := strings.TrimSpace(spec.Description); desc != "" {
		ops = append(ops, AtomicSubCommand{CommandType: "Add", OMAURI: base + "/Description", Payload: desc, Format: "chr"})
	}
	if spec.Protocol > 0 && spec.Protocol != 256 {
		ops = append(ops, AtomicSubCommand{CommandType: "Add", OMAURI: base + "/Protocol", Payload: strconv.Itoa(spec.Protocol), Format: "int"})
		if spec.Protocol == 6 || spec.Protocol == 17 {
			if lp := strings.TrimSpace(spec.LocalPortRanges); lp != "" {
				ops = append(ops, AtomicSubCommand{CommandType: "Add", OMAURI: base + "/LocalPortRanges", Payload: lp, Format: "chr"})
			}
			if rp := strings.TrimSpace(spec.RemotePortRanges); rp != "" {
				ops = append(ops, AtomicSubCommand{CommandType: "Add", OMAURI: base + "/RemotePortRanges", Payload: rp, Format: "chr"})
			}
		}
	}
	return ops, nil
}

// EnqueueFirewallRule queues an <Atomic> FirewallRules provisioning block on a device.
// When replaceExisting is true, a <Delete> on the rule node is queued first so
// Windows cleanly replaces any prior rule definition.
func EnqueueFirewallRule(dbConn *sql.DB, deviceID string, spec FirewallRuleSpec, replaceExisting bool) (int, error) {
	ops, err := BuildFirewallRuleAtomicOps(spec)
	if err != nil {
		return 0, err
	}
	ruleRoot := OMAFirewallRulesPrefix + "/" + spec.RuleKey
	var queued int
	if replaceExisting {
		if _, err := EnqueueDelete(dbConn, deviceID, ruleRoot); err != nil {
			return 0, err
		}
		queued++
	}
	if _, err := EnqueueAtomic(dbConn, deviceID, ruleRoot, ops); err != nil {
		return queued, err
	}
	queued++
	return queued, nil
}

// RetractFirewallRule queues a <Delete> on ./Vendor/MSFT/Firewall/MdmStore/FirewallRules/{RuleKey}.
func RetractFirewallRule(dbConn *sql.DB, deviceID, ruleKey string) (int, error) {
	if !validFirewallRuleKeyRE.MatchString(strings.TrimSpace(ruleKey)) {
		return 0, fmt.Errorf("invalid firewall rule_key %q", ruleKey)
	}
	if _, err := EnqueueDelete(dbConn, deviceID, OMAFirewallRulesPrefix+"/"+strings.TrimSpace(ruleKey)); err != nil {
		return 0, err
	}
	return 1, nil
}
