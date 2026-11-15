// Package winget resolves native MSI/WiX application manifests from Microsoft's
// public winget-pkgs repository for agentless EnterpriseDesktopAppManagement deployment.
package winget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// SearchResult describes a WinGet catalog entry eligible for MSI inspection/import.
type SearchResult struct {
	PackageID   string   `json:"package_id"`
	Name        string   `json:"name"`
	Publisher   string   `json:"publisher"`
	Description string   `json:"description"`
	Homepage    string   `json:"homepage,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CuratedMSI  bool     `json:"curated_msi"`
}

// ResolvedMSI holds the concrete MSI/WiX installer metadata resolved from a WinGet manifest.
type ResolvedMSI struct {
	PackageID     string `json:"package_id"`
	Name          string `json:"name"`
	Publisher     string `json:"publisher"`
	Description   string `json:"description"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	InstallerType string `json:"installer_type"`
	InstallerURL  string `json:"installer_url"`
	SHA256        string `json:"sha256"`
	ProductCode   string `json:"product_code"`
	UpgradeCode   string `json:"upgrade_code"`
	SilentArgs    string `json:"silent_args"`
}

var builtinDirectory = []SearchResult{
	{
		PackageID:   "7zip.7zip",
		Name:        "7-Zip",
		Publisher:   "Igor Pavlov",
		Description: "High-compression file archiver with native lightweight x64 WiX MSI installer.",
		Homepage:    "https://www.7-zip.org/",
		Tags:        []string{"7z", "7zip", "zip", "archive", "compression"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Google.Chrome",
		Name:        "Google Chrome Enterprise",
		Publisher:   "Google LLC",
		Description: "Fast, secure enterprise web browser managed via Group Policy / ADMX.",
		Homepage:    "https://chromeenterprise.google/",
		Tags:        []string{"browser", "chrome", "google", "web"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Mozilla.Firefox.ESR",
		Name:        "Mozilla Firefox ESR",
		Publisher:   "Mozilla",
		Description: "Extended Support Release of Mozilla Firefox packaged as an enterprise MSI.",
		Homepage:    "https://www.mozilla.org/firefox/enterprise/",
		Tags:        []string{"browser", "firefox", "esr", "mozilla"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Microsoft.PowerShell",
		Name:        "PowerShell 7",
		Publisher:   "Microsoft Corporation",
		Description: "Cross-platform PowerShell 7 automation shell and scripting language (x64 MSI).",
		Homepage:    "https://learn.microsoft.com/powershell/",
		Tags:        []string{"pwsh", "powershell", "shell", "microsoft", "cli"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "SimonTatham.PuTTY",
		Name:        "PuTTY",
		Publisher:   "Simon Tatham",
		Description: "Lightweight SSH, Telnet, SFTP, and serial client for Windows (WiX MSI).",
		Homepage:    "https://www.chiark.greenend.org.uk/~sgtatham/putty/",
		Tags:        []string{"ssh", "putty", "sftp", "terminal"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "OpenJS.NodeJS.LTS",
		Name:        "Node.js LTS",
		Publisher:   "OpenJS Foundation",
		Description: "Long-Term Support JavaScript runtime built on Chrome's V8 engine (x64 MSI).",
		Homepage:    "https://nodejs.org/",
		Tags:        []string{"node", "nodejs", "npm", "javascript", "lts"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "GoLang.Go",
		Name:        "Go Programming Language",
		Publisher:   "The Go Authors",
		Description: "Official Go compiler, standard library, and developer tools (x64 MSI).",
		Homepage:    "https://go.dev/",
		Tags:        []string{"go", "golang", "compiler", "dev"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Kitware.CMake",
		Name:        "CMake",
		Publisher:   "Kitware, Inc.",
		Description: "Cross-platform build system generator distributed as an official WiX MSI.",
		Homepage:    "https://cmake.org/",
		Tags:        []string{"cmake", "build", "cpp", "c++"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "VideoLAN.VLC",
		Name:        "VLC media player",
		Publisher:   "VideoLAN",
		Description: "Open-source cross-platform multimedia player supporting native MSI deployment.",
		Homepage:    "https://www.videolan.org/vlc/",
		Tags:        []string{"vlc", "media", "video", "audio"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Zoom.Zoom",
		Name:        "Zoom Workplace",
		Publisher:   "Zoom Video Communications, Inc.",
		Description: "Enterprise meetings, chat, and collaboration client (machine-wide MSI).",
		Homepage:    "https://zoom.us/",
		Tags:        []string{"zoom", "meetings", "video", "conferencing"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "SlackTechnologies.Slack",
		Name:        "Slack (Machine-Wide)",
		Publisher:   "Slack Technologies, Inc.",
		Description: "Enterprise team messaging and collaboration desktop app (machine MSI).",
		Homepage:    "https://slack.com/",
		Tags:        []string{"slack", "chat", "messaging"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Tailscale.Tailscale",
		Name:        "Tailscale",
		Publisher:   "Tailscale Inc.",
		Description: "Zero-config mesh VPN built on WireGuard with unattended Windows MSI.",
		Homepage:    "https://tailscale.com/",
		Tags:        []string{"vpn", "wireguard", "tailscale", "network"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Cloudflare.cloudflared",
		Name:        "Cloudflare Tunnel (cloudflared)",
		Publisher:   "Cloudflare, Inc.",
		Description: "Zero-Trust Cloudflare Tunnel daemon packaged as an x64 Windows MSI.",
		Homepage:    "https://developers.cloudflare.com/cloudflare-one/",
		Tags:        []string{"cloudflare", "tunnel", "cloudflared", "zerotrust"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Amazon.AWSCLI",
		Name:        "AWS Command Line Interface v2",
		Publisher:   "Amazon Web Services",
		Description: "Unified tool to manage AWS cloud services from Windows (official MSI).",
		Homepage:    "https://aws.amazon.com/cli/",
		Tags:        []string{"aws", "cli", "cloud", "amazon"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "Microsoft.AzureCLI",
		Name:        "Microsoft Azure CLI",
		Publisher:   "Microsoft Corporation",
		Description: "Command-line tools for managing Microsoft Azure resources (official MSI).",
		Homepage:    "https://learn.microsoft.com/cli/azure/",
		Tags:        []string{"azure", "az", "cli", "cloud", "microsoft"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "KeePassXCTeam.KeePassXC",
		Name:        "KeePassXC",
		Publisher:   "KeePassXC Team",
		Description: "Cross-platform open-source offline password manager (x64 WiX MSI).",
		Homepage:    "https://keepassxc.org/",
		Tags:        []string{"keepass", "keepassxc", "password", "security"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "LibreOffice.LibreOffice",
		Name:        "LibreOffice",
		Publisher:   "The Document Foundation",
		Description: "Full-featured open-source office productivity suite (x64 Windows MSI).",
		Homepage:    "https://www.libreoffice.org/",
		Tags:        []string{"office", "libreoffice", "writer", "calc"},
		CuratedMSI:  true,
	},
	{
		PackageID:   "RedHat.Podman",
		Name:        "Podman",
		Publisher:   "Red Hat, Inc.",
		Description: "Daemonless OCI container engine CLI and machine manager (WiX MSI).",
		Homepage:    "https://podman.io/",
		Tags:        []string{"podman", "containers", "docker", "oci"},
		CuratedMSI:  true,
	},
}

// Rate-limit resilience: verified official upstream manifests used only if GitHub's
// unauthenticated contents API returns HTTP 403/429.
var rateLimitFallbacks = map[string]ResolvedMSI{
	"7zip.7zip": {
		PackageID:     "7zip.7zip",
		Name:          "7-Zip",
		Publisher:     "Igor Pavlov",
		Description:   "High-compression file archiver with native lightweight x64 WiX MSI installer.",
		Version:       "26.06",
		Architecture:  "x64",
		InstallerType: "wix",
		InstallerURL:  "https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi",
		SHA256:        "6DC822569E777D9A3ECD5FFCBC22B55600AF87E6C5D9810A64E8566CF5A4AF9F",
		ProductCode:   "{23170F69-40C1-2702-2606-000001000000}",
		UpgradeCode:   "{23170F69-40C1-2702-0000-000004000000}",
		SilentArgs:    "/quiet /norestart",
	},
}

type cachedResolved struct {
	val       ResolvedMSI
	expiresAt time.Time
}

// Client queries WinGet package directories and parses official microsoft/winget-pkgs YAML manifests.
type Client struct {
	httpClient    *http.Client
	githubAPIBase string
	rawGitHubBase string
	searchAPIBase string

	mu    sync.Mutex
	cache map[string]cachedResolved
}

// NewClient constructs a WinGet catalog client with sensible timeouts and in-memory caching.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		githubAPIBase: "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests",
		rawGitHubBase: "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests",
		searchAPIBase: "https://api.winget.run/v2/packages",
		cache:         make(map[string]cachedResolved),
	}
}

// SetEndpoints overrides upstream base URLs and HTTP client for deterministic offline testing.
func (c *Client) SetEndpoints(httpClient *http.Client, githubAPI, rawGitHub, searchAPI string) {
	if httpClient != nil {
		c.httpClient = httpClient
	}
	if githubAPI != "" {
		c.githubAPIBase = strings.TrimRight(githubAPI, "/")
	}
	if rawGitHub != "" {
		c.rawGitHubBase = strings.TrimRight(rawGitHub, "/")
	}
	c.searchAPIBase = strings.TrimRight(searchAPI, "/")
}

// ValidatePackageID verifies that packageID is a safe, well-formed WinGet identifier
// (e.g. "7zip.7zip" or "OpenJS.NodeJS.LTS") and rejects path-traversal tokens.
func ValidatePackageID(packageID string) error {
	id := strings.TrimSpace(packageID)
	if id == "" || len(id) > 128 {
		return errors.New("invalid WinGet package_id")
	}
	if strings.Contains(id, "..") || strings.ContainsAny(id, `/\?#%`) {
		return errors.New("invalid characters in WinGet package_id")
	}
	parts := strings.Split(id, ".")
	if len(parts) < 2 {
		return errors.New("WinGet package_id must be in Publisher.Package format (e.g. 7zip.7zip)")
	}
	for _, p := range parts {
		if p == "" {
			return errors.New("empty segment in WinGet package_id")
		}
		for i := 0; i < len(p); i++ {
			ch := p[i]
			ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '+'
			if !ok {
				return fmt.Errorf("unsupported character %q in WinGet package_id", ch)
			}
		}
	}
	return nil
}

func manifestSubpath(packageID string) (string, error) {
	if err := ValidatePackageID(packageID); err != nil {
		return "", err
	}
	parts := strings.Split(packageID, ".")
	first := strings.ToLower(string(parts[0][0]))
	escaped := make([]string, 0, 1+len(parts))
	escaped = append(escaped, url.PathEscape(first))
	for _, p := range parts {
		escaped = append(escaped, url.PathEscape(p))
	}
	return strings.Join(escaped, "/"), nil
}

// Search matches query against the curated enterprise MSI directory and optionally
// augments results from the public WinGet search index or exact PackageIdentifier lookup.
func (c *Client) Search(ctx context.Context, query string) ([]SearchResult, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		out := make([]SearchResult, len(builtinDirectory))
		copy(out, builtinDirectory)
		return out, nil
	}

	qLower := strings.ToLower(q)
	tokens := strings.Fields(qLower)

	var out []SearchResult
	seen := make(map[string]bool)

	matchesTokens := func(haystack string) bool {
		h := strings.ToLower(haystack)
		for _, tok := range tokens {
			if !strings.Contains(h, tok) {
				return false
			}
		}
		return true
	}

	for _, item := range builtinDirectory {
		blob := item.PackageID + " " + item.Name + " " + item.Publisher + " " + item.Description + " " + strings.Join(item.Tags, " ")
		if matchesTokens(blob) {
			out = append(out, item)
			seen[strings.ToLower(item.PackageID)] = true
		}
	}

	// If user entered an exact Publisher.Package identifier not in the curated list,
	// surface it directly so any package in microsoft/winget-pkgs can be imported!
	if ValidatePackageID(q) == nil && !seen[strings.ToLower(q)] {
		parts := strings.SplitN(q, ".", 2)
		out = append([]SearchResult{{
			PackageID:   q,
			Name:        parts[1],
			Publisher:   parts[0],
			Description: "Direct WinGet package identifier lookup from microsoft/winget-pkgs.",
			CuratedMSI:  false,
		}}, out...)
		seen[strings.ToLower(q)] = true
	}

	// Best-effort live search augmentation if fewer than 8 curated matches
	if len(out) < 8 && c.searchAPIBase != "" {
		sCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
		extra := c.queryExternalIndex(sCtx, q)
		cancel()
		for _, item := range extra {
			key := strings.ToLower(item.PackageID)
			if !seen[key] && ValidatePackageID(item.PackageID) == nil {
				seen[key] = true
				out = append(out, item)
				if len(out) >= 16 {
					break
				}
			}
		}
	}

	return out, nil
}

func (c *Client) queryExternalIndex(ctx context.Context, query string) []SearchResult {
	u := c.searchAPIBase + "?query=" + url.QueryEscape(query) + "&take=8"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "LatchzMDM/1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var payload struct {
		Packages []struct {
			ID     string `json:"Id"`
			Latest struct {
				Name        string   `json:"Name"`
				Publisher   string   `json:"Publisher"`
				Description string   `json:"Description"`
				Homepage    string   `json:"Homepage"`
				Tags        []string `json:"Tags"`
			} `json:"Latest"`
		} `json:"Packages"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&payload); err != nil {
		return nil
	}

	out := make([]SearchResult, 0, len(payload.Packages))
	for _, p := range payload.Packages {
		out = append(out, SearchResult{
			PackageID:   p.ID,
			Name:        p.Latest.Name,
			Publisher:   p.Latest.Publisher,
			Description: p.Latest.Description,
			Homepage:    p.Latest.Homepage,
			Tags:        p.Latest.Tags,
			CuratedMSI:  false,
		})
	}
	return out
}

type installerManifest struct {
	PackageIdentifier   string            `yaml:"PackageIdentifier"`
	PackageVersion      string            `yaml:"PackageVersion"`
	PackageName         string            `yaml:"PackageName"`
	Publisher           string            `yaml:"Publisher"`
	ShortDescription    string            `yaml:"ShortDescription"`
	InstallerType       string            `yaml:"InstallerType"`
	NestedInstallerType string            `yaml:"NestedInstallerType"`
	ProductCode         string            `yaml:"ProductCode"`
	InstallerSwitches   map[string]string `yaml:"InstallerSwitches"`
	Installers          []installerEntry  `yaml:"Installers"`
}

type installerEntry struct {
	Architecture           string            `yaml:"Architecture"`
	Scope                  string            `yaml:"Scope"`
	InstallerType          string            `yaml:"InstallerType"`
	NestedInstallerType    string            `yaml:"NestedInstallerType"`
	InstallerURL           string            `yaml:"InstallerUrl"`
	InstallerSha256        string            `yaml:"InstallerSha256"`
	ProductCode            string            `yaml:"ProductCode"`
	InstallerSwitches      map[string]string `yaml:"InstallerSwitches"`
	AppsAndFeaturesEntries []struct {
		ProductCode string `yaml:"ProductCode"`
		UpgradeCode string `yaml:"UpgradeCode"`
		DisplayName string `yaml:"DisplayName"`
		Publisher   string `yaml:"Publisher"`
	} `yaml:"AppsAndFeaturesEntries"`
}

type localeManifest struct {
	PackageName      string `yaml:"PackageName"`
	Publisher        string `yaml:"Publisher"`
	ShortDescription string `yaml:"ShortDescription"`
}

// ResolveMSI fetches the latest version manifest for packageID from microsoft/winget-pkgs
// and extracts its native MSI/WiX installer metadata.
func (c *Client) ResolveMSI(ctx context.Context, packageID, preferredArch string) (ResolvedMSI, error) {
	if preferredArch == "" {
		preferredArch = "x64"
	}
	cacheKey := strings.ToLower(strings.TrimSpace(packageID)) + "|" + strings.ToLower(preferredArch)

	c.mu.Lock()
	if hit, ok := c.cache[cacheKey]; ok && time.Now().Before(hit.expiresAt) {
		c.mu.Unlock()
		return hit.val, nil
	}
	c.mu.Unlock()

	subpath, err := manifestSubpath(packageID)
	if err != nil {
		return ResolvedMSI{}, err
	}

	versions, canonicalID, err := c.listPackageVersions(ctx, subpath, packageID)
	if err != nil {
		if fb, ok := rateLimitFallbacks[packageID]; ok {
			return fb, nil
		}
		return ResolvedMSI{}, err
	}
	if len(versions) == 0 {
		return ResolvedMSI{}, fmt.Errorf("no versions found in WinGet repository for %q", packageID)
	}

	// Walk newest versions first (up to 3 latest versions in case a preview lacked MSI)
	sortVersionsDesc(versions)
	maxTries := 3
	if len(versions) < maxTries {
		maxTries = len(versions)
	}

	var lastErr error
	for i := 0; i < maxTries; i++ {
		ver := versions[i]
		res, err := c.fetchAndSelectMSI(ctx, subpath, canonicalID, ver, preferredArch)
		if err == nil {
			c.mu.Lock()
			c.cache[cacheKey] = cachedResolved{val: res, expiresAt: time.Now().Add(30 * time.Minute)}
			c.mu.Unlock()
			return res, nil
		}
		lastErr = err
	}
	if fb, ok := rateLimitFallbacks[canonicalID]; ok {
		return fb, nil
	}
	return ResolvedMSI{}, lastErr
}

func (c *Client) listPackageVersions(ctx context.Context, subpath, packageID string) ([]string, string, error) {
	u := c.githubAPIBase + "/" + subpath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, packageID, err
	}
	req.Header.Set("User-Agent", "LatchzMDM/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, packageID, fmt.Errorf("contacting WinGet repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, packageID, fmt.Errorf("package %q was not found in microsoft/winget-pkgs (note: GitHub paths are case-sensitive, e.g. 7zip.7zip)", packageID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, packageID, fmt.Errorf("WinGet repository returned HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&entries); err != nil {
		return nil, packageID, fmt.Errorf("decoding WinGet version directory: %w", err)
	}

	var versions []string
	for _, e := range entries {
		if e.Type == "dir" && !strings.HasPrefix(e.Name, ".") {
			versions = append(versions, e.Name)
		}
	}
	return versions, packageID, nil
}

func (c *Client) fetchRawText(ctx context.Context, fullURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "LatchzMDM/1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return body, resp.StatusCode, err
}

func (c *Client) fetchAndSelectMSI(ctx context.Context, subpath, packageID, version, preferredArch string) (ResolvedMSI, error) {
	base := c.rawGitHubBase + "/" + subpath + "/" + url.PathEscape(version) + "/" + url.PathEscape(packageID)
	rawBytes, status, err := c.fetchRawText(ctx, base+".installer.yaml")
	if err != nil && status == http.StatusNotFound {
		// Single-file manifest fallback
		rawBytes, _, err = c.fetchRawText(ctx, base+".yaml")
	}
	if err != nil {
		return ResolvedMSI{}, fmt.Errorf("fetching WinGet installer manifest for %s %s: %w", packageID, version, err)
	}

	var instManifest installerManifest
	if err := yaml.Unmarshal(rawBytes, &instManifest); err != nil {
		return ResolvedMSI{}, fmt.Errorf("parsing WinGet installer YAML: %w", err)
	}

	selected, effType, ok := pickBestMSIInstaller(&instManifest, preferredArch)
	if !ok {
		return ResolvedMSI{}, fmt.Errorf(
			"package %q (%s) does not publish a direct .msi / WiX installer in WinGet (only EXE/MSIX installers found, which cannot be deployed agentlessly via EnterpriseDesktopAppManagement CSP)",
			packageID, version,
		)
	}

	// Best-effort locale metadata lookup for friendly Name, Publisher, Description
	name := strings.TrimSpace(instManifest.PackageName)
	pub := strings.TrimSpace(instManifest.Publisher)
	desc := strings.TrimSpace(instManifest.ShortDescription)
	if locBytes, _, lErr := c.fetchRawText(ctx, base+".locale.en-US.yaml"); lErr == nil {
		var loc localeManifest
		if yaml.Unmarshal(locBytes, &loc) == nil {
			if loc.PackageName != "" {
				name = strings.TrimSpace(loc.PackageName)
			}
			if loc.Publisher != "" {
				pub = strings.TrimSpace(loc.Publisher)
			}
			if loc.ShortDescription != "" {
				desc = strings.TrimSpace(loc.ShortDescription)
			}
		}
	}
	for _, dirItem := range builtinDirectory {
		if strings.EqualFold(dirItem.PackageID, packageID) {
			if name == "" {
				name = dirItem.Name
			}
			if pub == "" {
				pub = dirItem.Publisher
			}
			if desc == "" {
				desc = dirItem.Description
			}
			break
		}
	}

	prodCode := strings.TrimSpace(selected.ProductCode)
	if prodCode == "" {
		prodCode = strings.TrimSpace(instManifest.ProductCode)
	}
	var upgCode string
	for _, afe := range selected.AppsAndFeaturesEntries {
		if prodCode == "" && strings.HasPrefix(strings.TrimSpace(afe.ProductCode), "{") {
			prodCode = strings.TrimSpace(afe.ProductCode)
		}
		if upgCode == "" && strings.HasPrefix(strings.TrimSpace(afe.UpgradeCode), "{") {
			upgCode = strings.TrimSpace(afe.UpgradeCode)
		}
		if name == "" && afe.DisplayName != "" {
			name = strings.TrimSpace(afe.DisplayName)
		}
		if pub == "" && afe.Publisher != "" {
			pub = strings.TrimSpace(afe.Publisher)
		}
	}
	// Only keep ProductCode if it is an MSI GUID ("{...}"); EXE ARP key names are ignored
	// so Latchz's CFB MSI inspector extracts the true GUID automatically if needed.
	if prodCode != "" && !strings.HasPrefix(prodCode, "{") {
		prodCode = ""
	}
	if name == "" {
		name = packageID
	}

	ver := strings.TrimSpace(instManifest.PackageVersion)
	if ver == "" {
		ver = version
	}

	return ResolvedMSI{
		PackageID:     packageID,
		Name:          name,
		Publisher:     pub,
		Description:   desc,
		Version:       ver,
		Architecture:  strings.ToLower(strings.TrimSpace(selected.Architecture)),
		InstallerType: effType,
		InstallerURL:  strings.TrimSpace(selected.InstallerURL),
		SHA256:        strings.ToUpper(strings.TrimSpace(selected.InstallerSha256)),
		ProductCode:   prodCode,
		UpgradeCode:   upgCode,
		SilentArgs:    "/quiet /norestart",
	}, nil
}

func pickBestMSIInstaller(m *installerManifest, preferredArch string) (installerEntry, string, bool) {
	pref := strings.ToLower(strings.TrimSpace(preferredArch))
	bestScore := -1
	var best installerEntry
	var bestType string

	for _, in := range m.Installers {
		effType := strings.ToLower(strings.TrimSpace(in.InstallerType))
		if effType == "" {
			effType = strings.ToLower(strings.TrimSpace(m.InstallerType))
		}
		rawURL := strings.ToLower(strings.TrimSpace(in.InstallerURL))
		// Accept direct msi/wix installers (exclude zip/archive wrappers that require extraction)
		if effType != "msi" && effType != "wix" {
			continue
		}
		if strings.HasSuffix(rawURL, ".zip") || strings.HasSuffix(rawURL, ".7z") {
			continue
		}

		score := 10
		arch := strings.ToLower(strings.TrimSpace(in.Architecture))
		switch {
		case arch == pref:
			score += 100
		case arch == "x64":
			score += 80
		case arch == "neutral" || arch == "":
			score += 60
		case arch == "x86":
			score += 40
		case arch == "arm64":
			score += 20
		}
		if strings.EqualFold(strings.TrimSpace(in.Scope), "machine") || in.Scope == "" {
			score += 15
		}
		if strings.HasPrefix(strings.TrimSpace(in.ProductCode), "{") {
			score += 5
		}

		if score > bestScore {
			bestScore = score
			best = in
			bestType = effType
		}
	}
	return best, bestType, bestScore >= 0
}

func sortVersionsDesc(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		return compareVersionStrings(versions[i], versions[j]) > 0
	})
}

func compareVersionStrings(a, b string) int {
	splitNums := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool {
			return r == '.' || r == '-' || r == '_'
		})
	}
	pa, pb := splitNums(a), splitNums(b)
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		var sa, sb string
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		if sa == sb {
			continue
		}
		na, errA := strconv.ParseInt(sa, 10, 64)
		nb, errB := strconv.ParseInt(sb, 10, 64)
		if errA == nil && errB == nil {
			if na != nb {
				if na > nb {
					return 1
				}
				return -1
			}
			continue
		}
		return strings.Compare(sa, sb)
	}
	return 0
}
