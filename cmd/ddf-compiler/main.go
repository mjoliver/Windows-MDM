package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/latchzmdm/latchz/internal/config"
	"github.com/latchzmdm/latchz/internal/db"
)

// CatalogEntry holds a parsed DDF policy ready for database insertion.
type CatalogEntry struct {
	OMAURI        string `json:"oma_uri"`
	DisplayName   string `json:"display_name"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	CSPName       string `json:"csp_name"`
	DataType      string `json:"data_type"`
	AllowedValues string `json:"allowed_values"` // JSON array string
	DefaultValue  string `json:"default_value"`
	MinOSVersion  string `json:"min_os_version"`
	AccessTypes   string `json:"access_types"` // JSON array string
	IsDeprecated  bool   `json:"is_deprecated"`
}

// ── XML Parsing Types ──────────────────────────────────────────────────────

type MgmtTree struct {
	XMLName xml.Name `xml:"MgmtTree"`
	Nodes   []Node   `xml:"Node"`
}

type Node struct {
	XMLName      xml.Name      `xml:"Node"`
	NodeName     string        `xml:"NodeName"`
	Path         string        `xml:"Path"` // Sometimes defined natively, often we construct it
	DFProperties *DFProperties `xml:"DFProperties"`
	Nodes        []Node        `xml:"Node"` // Recursive
}

type DFProperties struct {
	AccessType  *AccessType `xml:"AccessType"`
	Description string      `xml:"Description"`
	Format      *Format     `xml:"DFFormat"`
	Type        *TypeTag    `xml:"DFType"`
}

type AccessType struct {
	Add     *struct{} `xml:"Add"`
	Delete  *struct{} `xml:"Delete"`
	Exec    *struct{} `xml:"Exec"`
	Get     *struct{} `xml:"Get"`
	Replace *struct{} `xml:"Replace"`
}

type Format struct {
	B64  *struct{} `xml:"b64"`
	Bin  *struct{} `xml:"bin"`
	Bool *struct{} `xml:"bool"`
	Chr  *struct{} `xml:"chr"`
	Int  *struct{} `xml:"int"`
	Xml  *struct{} `xml:"xml"`
}

type TypeTag struct {
	MIME string `xml:"MIME"`
}

// Compiler holds the parsing state and dependencies for DDF compilation.
// It replaces the global allEntries/anomalies variables for better testability.
type Compiler struct {
	Entries   []CatalogEntry
	Anomalies []string
}

// NewCompiler creates a new Compiler instance with initialized slices.
func NewCompiler() *Compiler {
	return &Compiler{
		Entries:   make([]CatalogEntry, 0),
		Anomalies: make([]string, 0),
	}
}

func main() {
	configFile := flag.String("config", "latchz.yaml", "Path to the configuration YAML file (provides database.driver and database.dsn)")
	inDir := flag.String("in", "", "Directory containing Microsoft DDF XML files")
	outFile := flag.String("out", "", "Output JSON catalog file (optional; if omitted, only database is written)")
	reportFile := flag.String("report", "parser_anomalies_report.md", "Output anomalies report file")
	flag.Parse()

	if *inDir == "" {
		fmt.Println("Error: -in directory is required")
		os.Exit(1)
	}

	slog.Info("Starting DDF Compiler", "config", *configFile, "in", *inDir)

	// ── Load configuration (uses internal/config package) ──────────────
	cfg, err := config.Load(*configFile)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("Database config loaded", "driver", cfg.Database.Driver, "dsn", cfg.Database.DSN)

	// ── Open database (runs migrations automatically) ───────────────────
	database, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		slog.Error("Failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	// ── Create compiler with state ─────────────────────────────────────
	compiler := NewCompiler()

	// ── Parse all DDF XML files ─────────────────────────────────────────
	err = filepath.WalkDir(*inDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		compiler.processFile(path)
		return nil
	})

	if err != nil {
		slog.Error("WalkDir failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Parsing complete", "policies_extracted", len(compiler.Entries))

	// ── Insert entries into policy_catalog ──────────────────────────────
	inserted, updated, err := insertCatalogEntries(database, compiler.Entries)
	if err != nil {
		slog.Error("Failed to insert catalog entries", "error", err)
		os.Exit(1)
	}
	slog.Info("Database upsert complete", "inserted", inserted, "updated", updated)

	// ── Optionally write JSON catalog ───────────────────────────────────
	if *outFile != "" {
		outBytes, err := json.MarshalIndent(compiler.Entries, "", "  ")
		if err != nil {
			slog.Error("Failed to marshal catalog", "error", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outFile, outBytes, 0644); err != nil {
			slog.Error("Failed to write catalog.json", "error", err)
			os.Exit(1)
		}
		slog.Info("JSON catalog written", "file", *outFile)
	}

	// ── Write anomalies report if there are any ─────────────────────────
	if len(compiler.Anomalies) > 0 {
		var report strings.Builder
		report.WriteString(fmt.Sprintf("# DDF Parser Anomalies Report\nGenerated: %s\n\n", time.Now().Format(time.RFC3339)))
		report.WriteString("The following suspected policy nodes could not be fully parsed and were dropped from the catalog.\n\n")
		for _, a := range compiler.Anomalies {
			report.WriteString(a)
		}
		_ = os.WriteFile(*reportFile, []byte(report.String()), 0644)
		slog.Warn("Parser finished with anomalies", "policies_extracted", len(compiler.Entries), "anomalies", len(compiler.Anomalies), "report", *reportFile)
	} else {
		// Clean up old report if it existed
		_ = os.Remove(*reportFile)
		slog.Info("Parser finished flawlessly", "policies_extracted", len(compiler.Entries))
	}
}

// insertCatalogEntries upserts parsed entries into the policy_catalog table.
// Uses INSERT ... ON CONFLICT(oma_uri) DO UPDATE for postgres and
// INSERT OR IGNORE followed by UPDATE for sqlite.
func insertCatalogEntries(database *db.DB, entries []CatalogEntry) (inserted, updated int, err error) {
	now := time.Now().Format("2006-01-02 15:04:05")

	for _, e := range entries {
		// Determine the INSERT strategy based on database driver.
		// We use a generic approach: try INSERT, if unique conflict, UPDATE.
		// SQLite: INSERT OR IGNORE, then UPDATE where not matched.
		// Postgres: INSERT ... ON CONFLICT(oma_uri) DO UPDATE.

		switch db.DriverName {
		case "postgres":
			query := `INSERT INTO policy_catalog (
				oma_uri, display_name, description, category, csp_name,
				data_type, allowed_values, default_value, min_os_version,
				access_types, is_deprecated, source, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'ddf', $12)
			ON CONFLICT (oma_uri) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				description = EXCLUDED.description,
				category = EXCLUDED.category,
				csp_name = EXCLUDED.csp_name,
				data_type = EXCLUDED.data_type,
				allowed_values = EXCLUDED.allowed_values,
				default_value = EXCLUDED.default_value,
				min_os_version = EXCLUDED.min_os_version,
				access_types = EXCLUDED.access_types,
				is_deprecated = EXCLUDED.is_deprecated,
				updated_at = EXCLUDED.updated_at`

			_, err := database.Exec(
				query,
				e.OMAURI, e.DisplayName, e.Description, e.Category, e.CSPName,
				e.DataType, e.AllowedValues, e.DefaultValue, e.MinOSVersion,
				e.AccessTypes, e.IsDeprecated, now,
			)
			if err != nil {
				return inserted, updated, fmt.Errorf("upserting %s: %w", e.OMAURI, err)
			}
			inserted++

		default: // sqlite
			// Step 1: INSERT OR IGNORE
			insertQuery := `INSERT OR IGNORE INTO policy_catalog (
				oma_uri, display_name, description, category, csp_name,
				data_type, allowed_values, default_value, min_os_version,
				access_types, is_deprecated, source, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ddf', ?)`

			result, err := database.Exec(
				insertQuery,
				e.OMAURI, e.DisplayName, e.Description, e.Category, e.CSPName,
				e.DataType, e.AllowedValues, e.DefaultValue, e.MinOSVersion,
				e.AccessTypes, e.IsDeprecated, now,
			)
			if err != nil {
				return inserted, updated, fmt.Errorf("inserting %s: %w", e.OMAURI, err)
			}
			rows, _ := result.RowsAffected()
			if rows == 1 {
				inserted++
			} else {
				// Step 2: UPDATE existing row
				updateQuery := `UPDATE policy_catalog SET
					display_name = ?, description = ?, category = ?, csp_name = ?,
					data_type = ?, allowed_values = ?, default_value = ?,
					min_os_version = ?, access_types = ?, is_deprecated = ?,
					updated_at = ?
					WHERE oma_uri = ?`

				_, err := database.Exec(
					updateQuery,
					e.DisplayName, e.Description, e.Category, e.CSPName,
					e.DataType, e.AllowedValues, e.DefaultValue, e.MinOSVersion,
					e.AccessTypes, e.IsDeprecated, now, e.OMAURI,
				)
				if err != nil {
					return inserted, updated, fmt.Errorf("updating %s: %w", e.OMAURI, err)
				}
				updated++
			}
		}
	}

	return inserted, updated, nil
}

// processFile reads and parses a single DDF XML file, populating the compiler's
// Entries and Anomalies slices.
func (c *Compiler) processFile(path string) {
	slog.Info("Processing DDF", "file", path)
	b, err := os.ReadFile(path)
	if err != nil {
		slog.Error("Failed to read file", "file", path, "error", err)
		return
	}

	// Some DDFs have arbitrary namespace prefixes like <SyncML:MgmtTree>.
	// This makes standard decoding difficult.
	// For V1, we strip common prefixes if namespaces break the parser.
	s := string(b)
	s = strings.ReplaceAll(s, "<SyncML:", "<")
	s = strings.ReplaceAll(s, "</SyncML:", "</")

	var tree MgmtTree
	if err := xml.Unmarshal([]byte(s), &tree); err != nil {
		slog.Warn("Failed to unmarshal DDF (might require namespace mapping)", "file", path, "error", err)
		return
	}

	// Attempt to extract CSP name from the filename (e.g. BitLocker.xml -> BitLocker)
	baseName := filepath.Base(path)
	cspName := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	for _, n := range tree.Nodes {
		c.traverseNode(n, ".", cspName, path)
	}
}

// traverseNode recursively walks the XML node tree, populating Entries for leaf
// nodes and Anomalies for nodes that fail compilation.
func (c *Compiler) traverseNode(n Node, parentPath string, cspName string, sourceFile string) {
	// Construct the current absolute OMA-URI
	currentURI := parentPath
	if n.NodeName != "" {
		if strings.HasSuffix(parentPath, "/") {
			currentURI = parentPath + n.NodeName
		} else {
			currentURI = parentPath + "/" + n.NodeName
		}
	}

	// If there are subnodes, this is an interior component. Keep traversing.
	if len(n.Nodes) > 0 {
		for _, sub := range n.Nodes {
			c.traverseNode(sub, currentURI, cspName, sourceFile)
		}
		return
	}

	// Leaf Node! This is an actionable policy (or at least we assume it is).
	// Let's validate if we have DFProperties.
	if n.DFProperties == nil {
		// Lots of leaf elements are just layout padding or definitions. Safely ignore.
		return
	}

	entry, err := compileNode(n, currentURI, cspName)
	if err != nil {
		// Log the anomaly dynamically!
		anomaly := fmt.Sprintf("## Missing properties at `%s`\n**Source:** `%s`\n**Error:** %v\n\n```xml\n<!-- Leaf Node XML -->\n<NodeName>%s</NodeName>\n```\n\n---\n",
			currentURI, sourceFile, err, n.NodeName)
		c.Anomalies = append(c.Anomalies, anomaly)
		return
	}

	c.Entries = append(c.Entries, entry)
}

// compileNode converts a single XML Node into a CatalogEntry.
// Returns an error if the node is missing required properties.
func compileNode(n Node, uri string, cspName string) (CatalogEntry, error) {
	if n.NodeName == "" {
		return CatalogEntry{}, fmt.Errorf("node requires a NodeName")
	}

	// Bug fix: check DFProperties for nil before accessing it.
	// The test TestCompileNode/nil_DFProperties_returns_error caught this nil pointer dereference.
	if n.DFProperties == nil {
		return CatalogEntry{}, fmt.Errorf("node requires DFProperties")
	}

	entry := CatalogEntry{
		OMAURI:        uri,
		DisplayName:   n.NodeName, // Fallback to raw NodeName, often good enough.
		CSPName:       cspName,
		Category:      cspName, // Treat CSP as top-level category for V1
		AllowedValues: "[]",
		AccessTypes:   "[]",
	}

	props := n.DFProperties
	if props.Description != "" {
		entry.Description = strings.TrimSpace(props.Description)
	}

	// Parse Access Types
	var acc []string
	if props.AccessType != nil {
		if props.AccessType.Get != nil {
			acc = append(acc, "Get")
		}
		if props.AccessType.Replace != nil {
			acc = append(acc, "Replace")
		}
		if props.AccessType.Add != nil {
			acc = append(acc, "Add")
		}
		if props.AccessType.Delete != nil {
			acc = append(acc, "Delete")
		}
		if props.AccessType.Exec != nil {
			acc = append(acc, "Exec")
		}
	}
	if len(acc) > 0 {
		b, _ := json.Marshal(acc)
		entry.AccessTypes = string(b)
	} else {
		// Without Get/Replace, it's not a manageable policy.
		return CatalogEntry{}, fmt.Errorf("no AccessType tags found (Get/Replace missing)")
	}

	// Parse Format / DataType
	if props.Format != nil {
		if props.Format.Chr != nil {
			entry.DataType = "string"
		} else if props.Format.Int != nil {
			entry.DataType = "integer"
		} else if props.Format.Bool != nil {
			entry.DataType = "boolean"
		} else if props.Format.B64 != nil {
			entry.DataType = "base64"
		} else if props.Format.Xml != nil {
			entry.DataType = "xml"
		} else {
			entry.DataType = "string" // fallback
		}
	} else {
		return CatalogEntry{}, fmt.Errorf("no Format tag found to determine DataType")
	}

	return entry, nil
}