package main

import (
	"bytes"
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
)

// The structure of the output JSON matches the API/Database schema.
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
	Format      *Format     `xml:"Format"`
	Type        *TypeTag    `xml:"Type"`
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

// ── Application State ──────────────────────────────────────────────────────

var (
	allEntries []CatalogEntry
	anomalies  []string // Markdown blocks
)

func main() {
	inDir := flag.String("in", "", "Directory containing Microsoft DDF XML files")
	outFile := flag.String("out", "catalog.json", "Output JSON catalog file")
	reportFile := flag.String("report", "parser_anomalies_report.md", "Output anomalies report file")
	flag.Parse()

	if *inDir == "" {
		fmt.Println("Error: -in directory is required")
		os.Exit(1)
	}

	slog.Info("Starting DDF Compiler", "in", *inDir)

	err := filepath.WalkDir(*inDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		processFile(path)
		return nil
	})

	if err != nil {
		slog.Error("WalkDir failed", "error", err)
		os.Exit(1)
	}

	// Write catalog.json
	outBytes, err := json.MarshalIndent(allEntries, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal catalog", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outFile, outBytes, 0644); err != nil {
		slog.Error("Failed to write catalog.json", "error", err)
		os.Exit(1)
	}

	// Write anomalies report if there are any
	if len(anomalies) > 0 {
		var report bytes.Buffer
		report.WriteString(fmt.Sprintf("# DDF Parser Anomalies Report\nGenerated: %s\n\n", time.Now().Format(time.RFC3339)))
		report.WriteString("The following suspected policy nodes could not be fully parsed and were dropped from the catalog.\n\n")
		for _, a := range anomalies {
			report.WriteString(a)
		}
		_ = os.WriteFile(*reportFile, report.Bytes(), 0644)
		slog.Warn("Parser finished with anomalies", "policies_extracted", len(allEntries), "anomalies", len(anomalies), "report", *reportFile)
	} else {
		// Clean up old report if it existed
		_ = os.Remove(*reportFile)
		slog.Info("Parser finished flawlessly", "policies_extracted", len(allEntries))
	}
}

func processFile(path string) {
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
		traverseNode(n, ".", cspName, path)
	}
}

func traverseNode(n Node, parentPath string, cspName string, sourceFile string) {
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
			traverseNode(sub, currentURI, cspName, sourceFile)
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
		anomalies = append(anomalies, anomaly)
		return
	}

	allEntries = append(allEntries, entry)
}

func compileNode(n Node, uri string, cspName string) (CatalogEntry, error) {
	if n.NodeName == "" {
		return CatalogEntry{}, fmt.Errorf("node requires a NodeName")
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
