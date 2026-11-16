package mdm

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	// Defender Attack Surface Reduction (ASR) & Hardening Policy CSP nodes
	OMADefenderASRRules               = "./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules"
	OMADefenderSubmitSamplesConsent   = "./Device/Vendor/MSFT/Policy/Config/Defender/SubmitSamplesConsent"
	OMADefenderDisableLocalAdminMerge = "./Device/Vendor/MSFT/Policy/Config/Defender/DisableLocalAdminMerge"

	// SmartScreen & App Install Control Policy CSP nodes (<Format>int</Format>)
	OMASmartScreenEnableInShell     = "./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell"
	OMASmartScreenPreventOverride   = "./Device/Vendor/MSFT/Policy/Config/SmartScreen/PreventOverrideForFilesInShell"
	OMASmartScreenAppInstallControl = "./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableAppInstallControl"
)

// ASRRuleCatalogEntry describes one official Microsoft Defender Attack Surface Reduction rule.
type ASRRuleCatalogEntry struct {
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Recommended int    `json:"recommended_mode"` // 1=Block, 2=Audit
}

// OfficialASRRuleCatalog lists Microsoft's flagship Windows 10/11 Defender ASR rules.
var OfficialASRRuleCatalog = []ASRRuleCatalogEntry{
	{
		GUID:        "be9ba2d9-53ea-4cdc-84e5-9b1feed46555",
		Name:        "Block executable content from email client and webmail",
		Category:    "Email & Web",
		Recommended: 1,
	},
	{
		GUID:        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
		Name:        "Block all Office applications from creating child processes",
		Category:    "Office Hardening",
		Recommended: 1,
	},
	{
		GUID:        "3b576869-a4ec-4529-8536-b80a7769e899",
		Name:        "Block Office applications from creating executable content",
		Category:    "Office Hardening",
		Recommended: 1,
	},
	{
		GUID:        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
		Name:        "Block Office applications from injecting code into other processes",
		Category:    "Office Hardening",
		Recommended: 1,
	},
	{
		GUID:        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
		Name:        "Block Win32 API calls from Office macros",
		Category:    "Office Hardening",
		Recommended: 1,
	},
	{
		GUID:        "d3e037e1-3eb8-44c8-a917-57927947596d",
		Name:        "Block JavaScript or VBScript from launching downloaded executable content",
		Category:    "Script Execution",
		Recommended: 1,
	},
	{
		GUID:        "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
		Name:        "Block execution of potentially obfuscated scripts",
		Category:    "Script Execution",
		Recommended: 1,
	},
	{
		GUID:        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
		Name:        "Block credential stealing from the Windows local security authority subsystem (lsass.exe)",
		Category:    "Credential Protection",
		Recommended: 1,
	},
	{
		GUID:        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
		Name:        "Block untrusted and unsigned processes that run from USB",
		Category:    "Removable Media",
		Recommended: 1,
	},
	{
		GUID:        "e6db77e5-3df2-4cf1-b95a-636979351e5b",
		Name:        "Block persistence through WMI event subscription",
		Category:    "Persistence",
		Recommended: 1,
	},
}

var knownASRGUIDs = func() map[string]bool {
	m := make(map[string]bool, len(OfficialASRRuleCatalog))
	for _, r := range OfficialASRRuleCatalog {
		m[strings.ToLower(r.GUID)] = true
	}
	return m
}()

// EndpointHardeningSpec describes desired Defender ASR, SmartScreen & App Install Control settings.
type EndpointHardeningSpec struct {
	ASRRules                   map[string]int // GUID (lowercase) -> 0 (Off), 1 (Block), 2 (Audit), 6 (Warn)
	EnableSmartScreenShell     bool
	PreventSmartScreenOverride bool
	AppInstallControl          int // 0=Anywhere, 1=StoreOnly, 2=PreferStore, 3=WarnNonStore
	SubmitSamplesConsent       int // 0=Prompt, 1=SafeSamples, 2=Never, 3=AllSamples
	DisableLocalAdminMerge     bool
}

// ValidateAndNormalizeASRRules validates a map of ASR rule GUID -> mode (0, 1, 2, 6)
// against official Microsoft ASR GUIDs (or valid UUID syntax) and returns normalized lowercase keys.
func ValidateAndNormalizeASRRules(in map[string]int) (map[string]int, int, error) {
	out := make(map[string]int)
	active := 0
	for rawGUID, mode := range in {
		g := strings.ToLower(strings.TrimSpace(rawGUID))
		if g == "" {
			continue
		}
		if !knownASRGUIDs[g] && !isCanonicalUUID(g) {
			return nil, 0, fmt.Errorf("invalid ASR rule GUID %q", rawGUID)
		}
		switch mode {
		case 0:
			// omit disabled rules so pipe string only contains enforced/audited rules
		case 1, 2, 6:
			out[g] = mode
			active++
		default:
			return nil, 0, fmt.Errorf("invalid mode %d for ASR rule %s (expected 0=Off, 1=Block, 2=Audit, or 6=Warn)", mode, g)
		}
	}
	return out, active, nil
}

func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// ParseASRRulesJSON unmarshals a stored JSON map of ASR rules safely.
func ParseASRRulesJSON(raw string) map[string]int {
	if strings.TrimSpace(raw) == "" {
		return map[string]int{}
	}
	var m map[string]int
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		return map[string]int{}
	}
	norm, _, err := ValidateAndNormalizeASRRules(m)
	if err != nil {
		return map[string]int{}
	}
	return norm
}

// BuildASRRulesPipeString formats active ASR rules into Microsoft's deterministic
// pipe-separated Policy CSP format: "<guid1>=<mode1>|<guid2>=<mode2>".
func BuildASRRulesPipeString(rules map[string]int) string {
	if len(rules) == 0 {
		return ""
	}
	keys := make([]string, 0, len(rules))
	for k, v := range rules {
		if v == 1 || v == 2 || v == 6 {
			keys = append(keys, strings.ToLower(strings.TrimSpace(k)))
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, rules[k]))
	}
	return strings.Join(parts, "|")
}

// EnqueueEndpointHardening queues OMA-DM Replace/Delete commands for Defender ASR rules,
// SmartScreen Shell enforcement, App Install Control, and Local Admin Merge protection.
func EnqueueEndpointHardening(dbConn *sql.DB, deviceID string, spec EndpointHardeningSpec) (int, error) {
	aic := spec.AppInstallControl
	if aic < 0 || aic > 3 {
		aic = 0
	}
	ssc := spec.SubmitSamplesConsent
	if ssc < 0 || ssc > 3 {
		ssc = 1
	}

	var queued int
	pipeStr := BuildASRRulesPipeString(spec.ASRRules)
	if pipeStr != "" {
		if _, err := EnqueueReplace(dbConn, deviceID, OMADefenderASRRules, pipeStr); err != nil {
			return queued, err
		}
		queued++
	} else {
		if _, err := EnqueueDelete(dbConn, deviceID, OMADefenderASRRules); err != nil {
			return queued, err
		}
		queued++
	}

	intNodes := []struct {
		uri string
		val string
	}{
		{OMASmartScreenEnableInShell, boolIntStr(spec.EnableSmartScreenShell)},
		{OMASmartScreenPreventOverride, boolIntStr(spec.PreventSmartScreenOverride)},
		{OMASmartScreenAppInstallControl, strconv.Itoa(aic)},
		{OMADefenderSubmitSamplesConsent, strconv.Itoa(ssc)},
		{OMADefenderDisableLocalAdminMerge, boolIntStr(spec.DisableLocalAdminMerge)},
	}
	for _, n := range intNodes {
		if _, err := EnqueueReplace(dbConn, deviceID, n.uri, n.val); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

// RetractEndpointHardening sends <Delete> across all ASR & SmartScreen hardening Policy CSP nodes.
func RetractEndpointHardening(dbConn *sql.DB, deviceID string) (int, error) {
	uris := []string{
		OMADefenderASRRules,
		OMASmartScreenEnableInShell,
		OMASmartScreenPreventOverride,
		OMASmartScreenAppInstallControl,
		OMADefenderSubmitSamplesConsent,
		OMADefenderDisableLocalAdminMerge,
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
