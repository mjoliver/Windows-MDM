package mdm

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

const (
	// OMAEnterpriseDesktopMSIDeviceStruct queries all device-scoped MSI product
	// metadata (Name, Publisher, Version/ProductVersion, UpgradeCode, Status, etc.)
	// directly from Windows Installer via OMA-DM StructData expansion.
	OMAEnterpriseDesktopMSIDeviceStruct = "./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI?list=StructData"

	// OMAEnterpriseDesktopMSIUserStruct queries user-scoped MSI product metadata.
	OMAEnterpriseDesktopMSIUserStruct = "./User/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI?list=StructData"

	// OMAWin32AppInventoryStruct queries the full Windows Win32 & MSI installed
	// program inventory via the native agentless Win32AppInventory CSP.
	OMAWin32AppInventoryStruct = "./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram?list=StructData"

	// softwareInventoryRefreshInterval controls how frequently enrolled devices
	// automatically report full software inventory during background check-ins.
	softwareInventoryRefreshInterval = 1 * time.Hour
)

// SoftwareInventoryURIs are queried together to capture both live MSI database
// state and broader Add/Remove Programs Win32 software inventory.
var SoftwareInventoryURIs = []string{
	OMAEnterpriseDesktopMSIDeviceStruct,
	OMAEnterpriseDesktopMSIUserStruct,
	OMAWin32AppInventoryStruct,
}

var (
	trailingArchParenRE = regexp.MustCompile(`(?i)\s*\((?:x64|x86|64-bit(?:\s+x64)?|32-bit(?:\s+x86)?|arm64|en-us|machine|user|msi)\)\s*$`)
	trailingArchWordRE  = regexp.MustCompile(`(?i)\s+(?:x64|x86|64-bit|32-bit|arm64)\s*$`)
	trailingVerTokenRE  = regexp.MustCompile(`(?i)\s+v?\d+(?:\.\d+)+(?:[-+._a-z0-9]*)?\s*$`)
	versionTokenSplitRE = regexp.MustCompile(`[^0-9]+`)
	msiGUIDCheckRE      = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
)

// InventoryRecord represents a single discovered Win32 or MSI program on a device.
type InventoryRecord struct {
	AppKey          string
	Name            string
	Publisher       string
	Version         string
	Source          string // "msi" or "win32"
	ProductCode     string
	UpgradeCode     string
	InstallDate     string
	InstallLocation string
}

// EnqueueSoftwareInventorySync queues deduplicated OMA-DM Get commands for
// EnterpriseDesktopAppManagement MSI StructData and Win32AppInventory StructData.
func EnqueueSoftwareInventorySync(dbConn *sql.DB, deviceID string) (int, error) {
	var queued int
	for _, uri := range SoftwareInventoryURIs {
		if _, err := EnqueueGet(dbConn, deviceID, uri); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

// CompareAppVersions compares two Windows software version strings numerically
// segment-by-segment, normalizing trailing zero segments so "26.06.00.0" and
// "26.06" compare as equal (0). Returns -1 if a < b, 0 if equal, +1 if a > b.
func CompareAppVersions(a, b string) int {
	sa := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(a), "v"), "V"))
	sb := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(b), "v"), "V"))
	if sa == "" && sb == "" {
		return 0
	}
	if sa == "" {
		return -1
	}
	if sb == "" {
		return 1
	}
	if strings.EqualFold(sa, sb) {
		return 0
	}

	pa, oka := parseNumericVersionSegments(sa)
	pb, okb := parseNumericVersionSegments(sb)
	if !oka || !okb {
		al, bl := strings.ToLower(sa), strings.ToLower(sb)
		if al < bl {
			return -1
		}
		if al > bl {
			return 1
		}
		return 0
	}

	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var va, vb uint64
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

func parseNumericVersionSegments(s string) ([]uint64, bool) {
	rawParts := versionTokenSplitRE.Split(s, -1)
	var nums []uint64
	for _, p := range rawParts {
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		nums = append(nums, v)
	}
	if len(nums) == 0 {
		return nil, false
	}
	for len(nums) > 1 && nums[len(nums)-1] == 0 {
		nums = nums[:len(nums)-1]
	}
	return nums, true
}

// CanonicalAppBaseName strips architecture suffixes like "(x64)" or "(64-bit)"
// and trailing version numbers like "26.06" so "7-Zip 26.06 (x64)" canonicalizes
// to "7-zip" while preserving distinct product names ("microsoft edge" vs
// "microsoft edge webview2 runtime").
func CanonicalAppBaseName(raw string) string {
	s := strings.TrimSpace(raw)
	for i := 0; i < 4; i++ {
		prev := s
		s = trailingArchParenRE.ReplaceAllString(s, "")
		s = trailingArchWordRE.ReplaceAllString(s, "")
		s = trailingVerTokenRE.ReplaceAllString(s, "")
		s = strings.TrimSpace(s)
		if s == prev {
			break
		}
	}
	s = strings.Join(strings.Fields(strings.ToLower(s)), " ")
	return s
}

func appNamesCompatible(a, b string) bool {
	ca, cb := CanonicalAppBaseName(a), CanonicalAppBaseName(b)
	if ca == "" || cb == "" {
		return false
	}
	if ca == cb {
		return true
	}
	sa := strings.TrimSpace(strings.TrimSuffix(ca, " enterprise"))
	sb := strings.TrimSpace(strings.TrimSuffix(cb, " enterprise"))
	return len(sa) >= 3 && sa == sb
}

func normalizePublisherToken(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, suffix := range []string{
		", inc.", " inc.", " inc", ", llc", " llc", " corp.", " corporation",
		" ltd.", " ltd", " gmbh", " s.r.o.", " co.",
	} {
		s = strings.TrimSuffix(s, suffix)
	}
	return strings.Join(strings.Fields(s), " ")
}

func publishersCompatible(a, b string) bool {
	na, nb := normalizePublisherToken(a), normalizePublisherToken(b)
	if na == "" || nb == "" {
		return true
	}
	return na == nb || strings.Contains(na, nb) || strings.Contains(nb, na)
}

func normalizePossibleGUID(raw string) string {
	s := CanonicalMSIProductCode(raw)
	if msiGUIDCheckRE.MatchString(s) {
		return s
	}
	return ""
}

func stableInventoryKey(prefix, id string) string {
	clean := strings.ToLower(strings.TrimSpace(id))
	if len(clean) <= 96 && clean != "" {
		return prefix + ":" + clean
	}
	sum := sha1.Sum([]byte(clean))
	return prefix + ":" + hex.EncodeToString(sum[:12])
}

func parseAnyScopeMSIURI(rawURI string) (productCode, leaf string, ok bool) {
	u := strings.TrimSpace(rawURI)
	if !strings.HasPrefix(u, "./") {
		u = "./" + u
	}
	switch {
	case strings.HasPrefix(strings.ToLower(u), "./vendor/msft/"):
		u = "./Device/" + u[2:]
	case strings.HasPrefix(strings.ToLower(u), "./user/vendor/msft/"):
		u = "./Device/" + u[7:]
	}
	return ParseMSIProductURI(u)
}

func parseWin32InventoryURI(rawURI string) (instanceID, leaf string, ok bool) {
	u := strings.TrimSpace(rawURI)
	lower := strings.ToLower(u)
	const marker = "/win32appinventory/win32installedprogram/"
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return "", "", false
	}
	rest := strings.Trim(u[idx+len(marker):], "/")
	if rest == "" {
		return "", "", false
	}
	lastSlash := strings.LastIndexByte(rest, '/')
	if lastSlash <= 0 || lastSlash >= len(rest)-1 {
		return "", "", false
	}
	inst := rest[:lastSlash]
	leaf = rest[lastSlash+1:]
	if strings.HasPrefix(strings.ToLower(inst), "installedprogram/") {
		inst = inst[len("installedprogram/"):]
	}
	if unesc, err := url.PathUnescape(inst); err == nil && unesc != "" {
		inst = unesc
	}
	return strings.TrimSpace(inst), strings.TrimSpace(leaf), inst != "" && leaf != ""
}

func isNodeFormatItem(it Item) bool {
	return it.Meta != nil && it.Meta.Format != nil &&
		strings.EqualFold(strings.TrimSpace(it.Meta.Format.Value), "node")
}

// updateSoftwareInventory extractsMSI and Win32 application inventory records
// from OMA-DM Results, persists them to device_software_inventory, and
// reconciles live installed versions on device_app_installs.
func updateSoftwareInventory(dbConn *sql.DB, deviceID string, results []Results) bool {
	msiByCode := make(map[string]*InventoryRecord)
	msiUninstalled := make(map[string]bool)
	win32ByInst := make(map[string]*InventoryRecord)
	var nodeOnlyMSICodes []string
	sawWin32Snapshot := false

	for _, r := range results {
		for _, it := range r.Items {
			if it.Source == nil {
				continue
			}
			loc := strings.TrimSpace(it.Source.LocURI)
			val := strings.TrimSpace(it.Data)
			if loc == "" {
				continue
			}
			if isNodeFormatItem(it) {
				if strings.HasSuffix(strings.ToLower(strings.TrimSuffix(loc, "/")), "/enterprisedesktopappmanagement/msi") && val != "" {
					for _, seg := range strings.FieldsFunc(val, func(c rune) bool { return c == '/' || c == '\n' || c == '\r' || c == '\t' || c == ' ' }) {
						if unesc, err := url.PathUnescape(seg); err == nil && unesc != "" {
							seg = unesc
						}
						if g := normalizePossibleGUID(seg); g != "" {
							nodeOnlyMSICodes = append(nodeOnlyMSICodes, g)
						}
					}
				}
				continue
			}

			if prodCode, leaf, ok := parseAnyScopeMSIURI(loc); ok && leaf != "" {
				rec := msiByCode[prodCode]
				if rec == nil {
					rec = &InventoryRecord{
						AppKey:      "msi:" + prodCode,
						Source:      "msi",
						ProductCode: prodCode,
					}
					msiByCode[prodCode] = rec
				}
				switch strings.ToLower(leaf) {
				case "name", "productname", "displayname":
					if val != "" {
						rec.Name = val
					}
				case "publisher", "manufacturer":
					if val != "" {
						rec.Publisher = val
					}
				case "version", "productversion":
					if val != "" {
						rec.Version = val
					}
				case "upgradecode":
					if g := normalizePossibleGUID(val); g != "" {
						rec.UpgradeCode = g
					}
				case "installdate":
					if val != "" {
						rec.InstallDate = val
					}
				case "installpath", "installlocation":
					if val != "" {
						rec.InstallLocation = val
					}
				case "status":
					if sc, err := strconv.Atoi(val); err == nil && sc == 0 {
						msiUninstalled[prodCode] = true
					}
				}
				continue
			}

			if instID, leaf, ok := parseWin32InventoryURI(loc); ok {
				sawWin32Snapshot = true
				rec := win32ByInst[instID]
				if rec == nil {
					rec = &InventoryRecord{
						AppKey: stableInventoryKey("win32", instID),
						Source: "win32",
					}
					win32ByInst[instID] = rec
				}
				switch strings.ToLower(leaf) {
				case "name", "displayname", "productname":
					if val != "" {
						rec.Name = val
					}
				case "publisher", "manufacturer":
					if val != "" {
						rec.Publisher = val
					}
				case "version", "productversion", "displayversion":
					if val != "" {
						rec.Version = val
					}
				case "source":
					if strings.Contains(strings.ToLower(val), "msi") {
						rec.Source = "msi"
					}
				case "msiproductcode":
					if g := normalizePossibleGUID(val); g != "" {
						rec.ProductCode = g
						rec.Source = "msi"
					}
				case "msiupgradecode", "upgradecode":
					if g := normalizePossibleGUID(val); g != "" {
						rec.UpgradeCode = g
					}
				case "regkey":
					if rec.ProductCode == "" {
						if g := normalizePossibleGUID(val); g != "" {
							rec.ProductCode = g
							rec.Source = "msi"
						}
					}
				case "installdate":
					if val != "" {
						rec.InstallDate = val
					}
				case "installlocation", "installpath":
					if val != "" {
						rec.InstallLocation = val
					}
				}
			}
		}
	}

	// Merge records: key MSI-backed apps by "msi:{ProductCode}" so duplicates across
	// Win32AppInventory and EnterpriseDesktopAppManagement collapse cleanly into one row.
	merged := make(map[string]*InventoryRecord)

	for _, wRec := range win32ByInst {
		if strings.TrimSpace(wRec.Name) == "" {
			continue
		}
		if wRec.ProductCode != "" {
			if msiUninstalled[wRec.ProductCode] {
				continue
			}
			wRec.AppKey = "msi:" + wRec.ProductCode
			wRec.Source = "msi"
		}
		existing := merged[wRec.AppKey]
		if existing == nil || CompareAppVersions(wRec.Version, existing.Version) > 0 {
			cp := *wRec
			merged[wRec.AppKey] = &cp
		}
	}

	for prodCode, mRec := range msiByCode {
		if msiUninstalled[prodCode] {
			delete(merged, "msi:"+prodCode)
			continue
		}
		// Only persist an MSI record if it includes Name or Version metadata (pure
		// Status-only poll responses should not create nameless inventory rows).
		if mRec.Name == "" && mRec.Version == "" {
			continue
		}
		key := "msi:" + prodCode
		if ex := merged[key]; ex != nil {
			if mRec.Name != "" {
				ex.Name = mRec.Name
			}
			if mRec.Publisher != "" {
				ex.Publisher = mRec.Publisher
			}
			if mRec.Version != "" {
				ex.Version = mRec.Version
			}
			if mRec.UpgradeCode != "" {
				ex.UpgradeCode = mRec.UpgradeCode
			}
			if mRec.InstallDate != "" {
				ex.InstallDate = mRec.InstallDate
			}
			if mRec.InstallLocation != "" {
				ex.InstallLocation = mRec.InstallLocation
			}
		} else {
			if mRec.Name == "" {
				// Enrich name/publisher/upgrade_code from catalog if this matches a known MSI
				_ = dbConn.QueryRow(dbpkg.Rebind(`
					SELECT name, publisher, upgrade_code FROM msi_apps WHERE product_code = ?
				`), prodCode).Scan(&mRec.Name, &mRec.Publisher, &mRec.UpgradeCode)
			}
			if mRec.Name != "" {
				cp := *mRec
				merged[key] = &cp
			}
		}
	}

	if len(merged) == 0 && len(msiUninstalled) == 0 {
		if len(nodeOnlyMSICodes) > 0 && len(msiByCode) == 0 {
			limit := len(nodeOnlyMSICodes)
			if limit > 40 {
				limit = 40
			}
			for _, g := range nodeOnlyMSICodes[:limit] {
				_, _ = EnqueueGet(dbConn, deviceID, EncodeMSIProductURI(g, "")+"?list=StructData")
			}
		}
		return false
	}

	now := time.Now().UTC()
	tx, err := dbConn.Begin()
	if err != nil {
		return false
	}
	defer tx.Rollback()

	if sawWin32Snapshot && len(merged) > 0 {
		// Prune stale win32:* entries no longer present in the full Win32AppInventory snapshot.
		_, _ = tx.Exec(dbpkg.Rebind(`
			DELETE FROM device_software_inventory
			WHERE device_id = ? AND app_key LIKE 'win32:%'
		`), deviceID)
	}
	for prodCode := range msiUninstalled {
		_, _ = tx.Exec(dbpkg.Rebind(`
			DELETE FROM device_software_inventory
			WHERE device_id = ? AND (app_key = ? OR product_code = ?)
		`), deviceID, "msi:"+prodCode, prodCode)
	}

	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		rec := merged[k]
		_, err := tx.Exec(dbpkg.Rebind(`
			INSERT INTO device_software_inventory (
				device_id, app_key, name, publisher, version, source,
				product_code, upgrade_code, install_date, install_location, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (device_id, app_key) DO UPDATE SET
				name             = EXCLUDED.name,
				publisher        = CASE WHEN EXCLUDED.publisher <> '' THEN EXCLUDED.publisher ELSE device_software_inventory.publisher END,
				version          = CASE WHEN EXCLUDED.version <> '' THEN EXCLUDED.version ELSE device_software_inventory.version END,
				source           = EXCLUDED.source,
				product_code     = CASE WHEN EXCLUDED.product_code <> '' THEN EXCLUDED.product_code ELSE device_software_inventory.product_code END,
				upgrade_code     = CASE WHEN EXCLUDED.upgrade_code <> '' THEN EXCLUDED.upgrade_code ELSE device_software_inventory.upgrade_code END,
				install_date     = CASE WHEN EXCLUDED.install_date <> '' THEN EXCLUDED.install_date ELSE device_software_inventory.install_date END,
				install_location = CASE WHEN EXCLUDED.install_location <> '' THEN EXCLUDED.install_location ELSE device_software_inventory.install_location END,
				updated_at       = EXCLUDED.updated_at
		`),
			deviceID, rec.AppKey, rec.Name, rec.Publisher, rec.Version, rec.Source,
			rec.ProductCode, rec.UpgradeCode, rec.InstallDate, rec.InstallLocation, now,
		)
		if err != nil {
			return false
		}
	}

	if err := tx.Commit(); err != nil {
		return false
	}

	ReconcileDeviceAppVersions(dbConn, deviceID)
	return true
}

// MatchCatalogAppToInventory finds the best live installed inventory entry on a
// device for a catalog MSI application — even if an auto-updater (like GoogleUpdate
// for Chrome) upgraded the binary in-place under a brand-new MSI ProductCode.
func MatchCatalogAppToInventory(appName, appPublisher, appProductCode, appUpgradeCode string, inv []InventoryRecord) *InventoryRecord {
	normProd := CanonicalMSIProductCode(appProductCode)
	normUpg := normalizePossibleGUID(appUpgradeCode)
	baseName := CanonicalAppBaseName(appName)

	// 1. Exact ProductCode match (prefer highest version if multiple)
	var best *InventoryRecord
	for i := range inv {
		if normProd != "" && strings.EqualFold(inv[i].ProductCode, normProd) {
			if best == nil || CompareAppVersions(inv[i].Version, best.Version) > 0 {
				best = &inv[i]
			}
		}
	}
	if best != nil && best.Version != "" {
		// Still check if a newer self-updated entry exists by UpgradeCode or exact canonical name!
		for i := range inv {
			cand := &inv[i]
			if cand.Version == "" {
				continue
			}
			sameFamily := (normUpg != "" && strings.EqualFold(cand.UpgradeCode, normUpg)) ||
				(len(baseName) >= 3 && appNamesCompatible(appName, cand.Name) && publishersCompatible(appPublisher, cand.Publisher))
			if sameFamily && CompareAppVersions(cand.Version, best.Version) > 0 {
				best = cand
			}
		}
		return best
	}

	// 2. UpgradeCode family match (catches MSI major upgrades with new ProductCode)
	if normUpg != "" {
		for i := range inv {
			if strings.EqualFold(inv[i].UpgradeCode, normUpg) {
				if best == nil || CompareAppVersions(inv[i].Version, best.Version) > 0 {
					best = &inv[i]
				}
			}
		}
		if best != nil {
			return best
		}
	}

	// 3. Canonical application base name + compatible publisher match
	//    (catches Chrome / Edge / 7-Zip self-updates reported via Win32AppInventory)
	if len(baseName) >= 3 {
		for i := range inv {
			if appNamesCompatible(appName, inv[i].Name) && publishersCompatible(appPublisher, inv[i].Publisher) {
				if best == nil || CompareAppVersions(inv[i].Version, best.Version) > 0 {
					best = &inv[i]
				}
			}
		}
	}

	return best
}

// ReconcileDeviceAppVersions matches device_software_inventory rows against the
// msi_apps catalog and updates installed_version / installed_product_code on
// device_app_installs (including auto-detecting pre-existing or auto-updated apps).
func ReconcileDeviceAppVersions(dbConn *sql.DB, deviceID string) {
	invRows, err := dbConn.Query(dbpkg.Rebind(`
		SELECT app_key, name, publisher, version, source, product_code, upgrade_code, install_date, install_location
		FROM device_software_inventory
		WHERE device_id = ?
	`), deviceID)
	if err != nil {
		return
	}
	var inv []InventoryRecord
	for invRows.Next() {
		var r InventoryRecord
		if invRows.Scan(&r.AppKey, &r.Name, &r.Publisher, &r.Version, &r.Source, &r.ProductCode, &r.UpgradeCode, &r.InstallDate, &r.InstallLocation) == nil {
			inv = append(inv, r)
		}
	}
	invRows.Close()
	if len(inv) == 0 {
		return
	}

	type catApp struct {
		id, name, publisher, version, productCode, upgradeCode string
	}
	appRows, err := dbConn.Query(`SELECT id, name, publisher, version, product_code, upgrade_code FROM msi_apps`)
	if err != nil {
		return
	}
	var apps []catApp
	for appRows.Next() {
		var a catApp
		if appRows.Scan(&a.id, &a.name, &a.publisher, &a.version, &a.productCode, &a.upgradeCode) == nil {
			apps = append(apps, a)
		}
	}
	appRows.Close()

	for _, a := range apps {
		match := MatchCatalogAppToInventory(a.name, a.publisher, a.productCode, a.upgradeCode, inv)
		if match == nil {
			continue
		}
		instProd := match.ProductCode
		if instProd == "" {
			instProd = a.productCode
		}
		atOrAboveCatalog := 0
		if match.Version != "" && (a.version == "" || CompareAppVersions(match.Version, a.version) >= 0) {
			atOrAboveCatalog = 1
		}
		_, _ = dbConn.Exec(dbpkg.Rebind(`
			UPDATE device_app_installs
			SET installed_version = CASE WHEN ? <> '' THEN ? ELSE installed_version END,
			    installed_product_code = CASE WHEN ? <> '' THEN ? ELSE installed_product_code END,
			    status_code = CASE
			        WHEN desired_action = 'install' AND status_code IS NULL AND ? = 1 THEN 70
			        ELSE status_code
			    END,
			    status_label = CASE
			        WHEN desired_action = 'install' AND status_code IS NULL AND ? = 1 THEN 'Installed'
			        ELSE status_label
			    END
			WHERE device_id = ? AND app_id = ?
		`), match.Version, match.Version, instProd, instProd, atOrAboveCatalog, atOrAboveCatalog, deviceID, a.id)
	}
}
