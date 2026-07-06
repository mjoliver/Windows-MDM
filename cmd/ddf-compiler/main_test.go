package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/latchzmdm/latchz/internal/db"
)

// ptrStruct is a helper to create *struct{} values for XML unmarshaling.
var ptrStruct = &struct{}{}

// ── TestNewCompiler ──────────────────────────────────────────────────────────

func TestNewCompiler(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"creates new compiler"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			if c == nil {
				t.Fatal("NewCompiler returned nil")
			}
			if c.Entries == nil {
				t.Error("Entries slice is nil")
			}
			if c.Anomalies == nil {
				t.Error("Anomalies slice is nil")
			}
			if len(c.Entries) != 0 {
				t.Errorf("Entries has len %d, want 0", len(c.Entries))
			}
			if len(c.Anomalies) != 0 {
				t.Errorf("Anomalies has len %d, want 0", len(c.Anomalies))
			}
		})
	}
}

// ── TestCompileNode ──────────────────────────────────────────────────────────

func TestCompileNode(t *testing.T) {
	tests := []struct {
		name      string
		node      Node
		uri       string
		cspName   string
		wantErr   bool
		wantEntry func() CatalogEntry
	}{
		{
			name: "full node with chr format and all access types",
			node: Node{
				NodeName: "MaxEncryption",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
						Delete:  ptrStruct,
						Add:     ptrStruct,
						Exec:    ptrStruct,
					},
					Description: "  Maximum encryption size  ",
					Format:      &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/BitLocker",
			cspName: "BitLocker",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker",
					DisplayName:   "MaxEncryption",
					Description:   "Maximum encryption size",
					CSPName:       "BitLocker",
					Category:      "BitLocker",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace","Add","Delete","Exec"]`,
				}
			},
		},
		{
			name: "node with int format",
			node: Node{
				NodeName: "MaxSecureDrives",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Format: &Format{Int: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/BitLocker",
			cspName: "BitLocker",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker",
					DisplayName:   "MaxSecureDrives",
					CSPName:       "BitLocker",
					Category:      "BitLocker",
					DataType:      "integer",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				}
			},
		},
		{
			name: "node with bool format",
			node: Node{
				NodeName: "EnableEncryption",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Format: &Format{Bool: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/DeviceLock",
			cspName: "DeviceLock",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/DeviceLock",
					DisplayName:   "EnableEncryption",
					CSPName:       "DeviceLock",
					Category:      "DeviceLock",
					DataType:      "boolean",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				}
			},
		},
		{
			name: "node with b64 format",
			node: Node{
				NodeName: "RootCertificate",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
						Add:     ptrStruct,
					},
					Format: &Format{B64: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Certificate",
			cspName: "Certificate",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/Certificate",
					DisplayName:   "RootCertificate",
					CSPName:       "Certificate",
					Category:      "Certificate",
					DataType:      "base64",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace","Add"]`,
				}
			},
		},
		{
			name: "node with xml format",
			node: Node{
				NodeName: "CustomPolicy",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Format: &Format{Xml: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Custom",
			cspName: "Custom",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/Custom",
					DisplayName:   "CustomPolicy",
					CSPName:       "Custom",
					Category:      "Custom",
					DataType:      "xml",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				}
			},
		},
		{
			name: "node with only Get access",
			node: Node{
				NodeName: "ReadOnlySetting",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get: ptrStruct,
					},
					Format: &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Settings",
			cspName: "Settings",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/Settings",
					DisplayName:   "ReadOnlySetting",
					CSPName:       "Settings",
					Category:      "Settings",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get"]`,
				}
			},
		},
		{
			name: "node with only Replace access",
			node: Node{
				NodeName: "WriteOnlySetting",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Replace: ptrStruct,
					},
					Format: &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Settings",
			cspName: "Settings",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/Settings",
					DisplayName:   "WriteOnlySetting",
					CSPName:       "Settings",
					Category:      "Settings",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Replace"]`,
				}
			},
		},
		{
			name: "empty nodename returns error",
			node: Node{
				NodeName: "",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get: ptrStruct,
					},
					Format: &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Empty",
			cspName: "Empty",
			wantErr: true,
		},
		{
			name: "no access type returns error",
			node: Node{
				NodeName: "NoAccess",
				DFProperties: &DFProperties{
					Format: &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/NoAccess",
			cspName: "NoAccess",
			wantErr: true,
		},
		{
			name: "no format returns error",
			node: Node{
				NodeName: "NoFormat",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get: ptrStruct,
					},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/NoFormat",
			cspName: "NoFormat",
			wantErr: true,
		},
		{
			name: "node with description trimming",
			node: Node{
				NodeName: "TrimmedDesc",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Description: "  This has leading and trailing spaces  ",
					Format:      &Format{Chr: ptrStruct},
				},
			},
			uri:     "./Vendor/MSFT/Policy/Config/Test",
			cspName: "Test",
			wantErr: false,
			wantEntry: func() CatalogEntry {
				return CatalogEntry{
					OMAURI:        "./Vendor/MSFT/Policy/Config/Test",
					DisplayName:   "TrimmedDesc",
					Description:   "This has leading and trailing spaces",
					CSPName:       "Test",
					Category:      "Test",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				}
			},
		},
		{
			name: "nil DFProperties returns error",
			node: Node{
				NodeName:     "NoDFProps",
				DFProperties: nil,
			},
			uri:     "./Vendor/MSFT/Policy/Config/NoDFProps",
			cspName: "NoDFProps",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := compileNode(tt.node, tt.uri, tt.cspName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("compileNode() expected error, got nil")
					return
				}
				return
			}
			if err != nil {
				t.Errorf("compileNode() unexpected error: %v", err)
				return
			}

			want := tt.wantEntry()
			if entry.OMAURI != want.OMAURI {
				t.Errorf("OMAURI = %q, want %q", entry.OMAURI, want.OMAURI)
			}
			if entry.DisplayName != want.DisplayName {
				t.Errorf("DisplayName = %q, want %q", entry.DisplayName, want.DisplayName)
			}
			if entry.Description != want.Description {
				t.Errorf("Description = %q, want %q", entry.Description, want.Description)
			}
			if entry.CSPName != want.CSPName {
				t.Errorf("CSPName = %q, want %q", entry.CSPName, want.CSPName)
			}
			if entry.Category != want.Category {
				t.Errorf("Category = %q, want %q", entry.Category, want.Category)
			}
			if entry.DataType != want.DataType {
				t.Errorf("DataType = %q, want %q", entry.DataType, want.DataType)
			}
			if entry.AllowedValues != want.AllowedValues {
				t.Errorf("AllowedValues = %q, want %q", entry.AllowedValues, want.AllowedValues)
			}
			if entry.AccessTypes != want.AccessTypes {
				t.Errorf("AccessTypes = %q, want %q", entry.AccessTypes, want.AccessTypes)
			}
		})
	}
}

// ── TestCompileNodeAccessTypeOrder ───────────────────────────────────────────
// Verifies access types are marshaled in a consistent order.

func TestCompileNodeAccessTypeOrder(t *testing.T) {
	node := Node{
		NodeName: "OrderTest",
		DFProperties: &DFProperties{
			AccessType: &AccessType{
				Get:     ptrStruct,
				Replace: ptrStruct,
				Add:     ptrStruct,
				Delete:  ptrStruct,
				Exec:    ptrStruct,
			},
			Format: &Format{Chr: ptrStruct},
		},
	}

	entry, err := compileNode(node, "./Vendor/MSFT/Policy/Config/Test", "Test")
	if err != nil {
		t.Fatalf("compileNode() unexpected error: %v", err)
	}

	var accessTypes []string
	if err := json.Unmarshal([]byte(entry.AccessTypes), &accessTypes); err != nil {
		t.Fatalf("failed to unmarshal AccessTypes: %v", err)
	}

	expectedOrder := []string{"Get", "Replace", "Add", "Delete", "Exec"}
	for i, want := range expectedOrder {
		if i >= len(accessTypes) {
			t.Fatalf("AccessTypes missing element at index %d, want %q", i, want)
		}
		if accessTypes[i] != want {
			t.Errorf("AccessTypes[%d] = %q, want %q", i, accessTypes[i], want)
		}
	}
}

// ── TestCompilerTraverseNode ─────────────────────────────────────────────────

func TestCompilerTraverseNode(t *testing.T) {
	tests := []struct {
		name          string
		node          Node
		parentPath    string
		cspName       string
		wantEntries   int
		wantAnomalies int
		wantURI       string
	}{
		{
			name: "leaf node with DFProperties adds entry",
			node: Node{
				NodeName: "MaxEncryption",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Format: &Format{Chr: ptrStruct},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   1,
			wantAnomalies: 0,
			// URI is built from parentPath + NodeName, cspName is NOT inserted into path
			wantURI: "./Vendor/MSFT/Policy/Config/MaxEncryption",
		},
		{
			name: "leaf node without DFProperties is skipped",
			node: Node{
				NodeName:     "EmptyLeaf",
				DFProperties: nil,
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   0,
			wantAnomalies: 0,
		},
		{
			name: "interior node with subnodes recurses",
			node: Node{
				NodeName: "Container",
				Nodes: []Node{
					{
						NodeName: "ChildPolicy",
						DFProperties: &DFProperties{
							AccessType: &AccessType{
								Get:     ptrStruct,
								Replace: ptrStruct,
							},
							Format: &Format{Chr: ptrStruct},
						},
					},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   1,
			wantAnomalies: 0,
			wantURI:       "./Vendor/MSFT/Policy/Config/Container/ChildPolicy",
		},
		{
			name: "multiple subnodes all traversed",
			node: Node{
				NodeName: "Container",
				Nodes: []Node{
					{
						NodeName: "Child1",
						DFProperties: &DFProperties{
							AccessType: &AccessType{Get: ptrStruct},
							Format:     &Format{Chr: ptrStruct},
						},
					},
					{
						NodeName: "Child2",
						DFProperties: &DFProperties{
							AccessType: &AccessType{Get: ptrStruct},
							Format:     &Format{Chr: ptrStruct},
						},
					},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   2,
			wantAnomalies: 0,
		},
		{
			name: "leaf node with missing properties generates anomaly",
			node: Node{
				NodeName:     "MissingProps",
				DFProperties: &DFProperties{}, // Empty DFProperties, no AccessType, no Format
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   0,
			wantAnomalies: 1,
		},
		{
			name: "parent path with trailing slash",
			node: Node{
				NodeName: "Policy",
				DFProperties: &DFProperties{
					AccessType: &AccessType{Get: ptrStruct},
					Format:     &Format{Chr: ptrStruct},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy/",
			cspName:       "Test",
			wantEntries:   1,
			wantAnomalies: 0,
			wantURI:       "./Vendor/MSFT/Policy/Policy",
		},
		{
			name: "parent path without trailing slash",
			node: Node{
				NodeName: "Policy",
				DFProperties: &DFProperties{
					AccessType: &AccessType{Get: ptrStruct},
					Format:     &Format{Chr: ptrStruct},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy",
			cspName:       "Test",
			wantEntries:   1,
			wantAnomalies: 0,
			wantURI:       "./Vendor/MSFT/Policy/Policy",
		},
		{
			name: "empty nodename leaf generates anomaly",
			node: Node{
				NodeName: "",
				DFProperties: &DFProperties{
					Format: &Format{Chr: ptrStruct},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy/Config",
			cspName:       "BitLocker",
			wantEntries:   0,
			wantAnomalies: 1,
		},
		{
			name: "deeply nested nodes",
			node: Node{
				NodeName: "Level1",
				Nodes: []Node{
					{
						NodeName: "Level2",
						Nodes: []Node{
							{
								NodeName: "Level3Policy",
								DFProperties: &DFProperties{
									AccessType: &AccessType{Get: ptrStruct, Replace: ptrStruct},
									Format:     &Format{Chr: ptrStruct},
								},
							},
						},
					},
				},
			},
			parentPath:    "./Vendor/MSFT/Policy",
			cspName:       "DeepCSP",
			wantEntries:   1,
			wantAnomalies: 0,
			wantURI:       "./Vendor/MSFT/Policy/Level1/Level2/Level3Policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			c.traverseNode(tt.node, tt.parentPath, tt.cspName, "test_source.xml")

			if len(c.Entries) != tt.wantEntries {
				t.Errorf("got %d entries, want %d", len(c.Entries), tt.wantEntries)
			}
			if len(c.Anomalies) != tt.wantAnomalies {
				t.Errorf("got %d anomalies, want %d", len(c.Anomalies), tt.wantAnomalies)
			}

			if tt.wantURI != "" && len(c.Entries) > 0 {
				if c.Entries[0].OMAURI != tt.wantURI {
					t.Errorf("OMAURI = %q, want %q", c.Entries[0].OMAURI, tt.wantURI)
				}
			}
		})
	}
}

// ── TestCompilerProcessFile ──────────────────────────────────────────────────

func TestCompilerProcessFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ddf-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name          string
		xmlContent    string
		filename      string
		wantEntries   int
		wantAnomalies int
	}{
		{
			name: "valid DDF XML with one policy",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>MaxEncryption</NodeName>
		<DFProperties>
			<AccessType>
				<Get/><Replace/>
			</AccessType>
			<DFFormat>
				<chr/>
			</DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "BitLocker.xml",
			wantEntries:   1,
			wantAnomalies: 0,
		},
		{
			name: "valid DDF XML with multiple policies",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>Policy1</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>Policy2</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><int/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "DeviceLock.xml",
			wantEntries:   2,
			wantAnomalies: 0,
		},
		{
			name: "DDF XML with nested nodes",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>Container</NodeName>
		<Node>
			<NodeName>InnerPolicy</NodeName>
			<DFProperties>
				<AccessType><Get/><Replace/></AccessType>
				<DFFormat><chr/></DFFormat>
			</DFProperties>
		</Node>
	</Node>
</MgmtTree>`,
			filename:      "Container.xml",
			wantEntries:   1,
			wantAnomalies: 0,
		},
		{
			name: "DDF XML with empty nodename generates anomaly",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName></NodeName>
		<DFProperties>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "EmptyNode.xml",
			wantEntries:   0,
			wantAnomalies: 1,
		},
		{
			name: "DDF XML with no access type generates anomaly",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>NoAccess</NodeName>
		<DFProperties>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "NoAccess.xml",
			wantEntries:   0,
			wantAnomalies: 1,
		},
		{
			name: "DDF XML with no format generates anomaly",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>NoFormat</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "NoFormat.xml",
			wantEntries:   0,
			wantAnomalies: 1,
		},
		{
			name: "DDF XML with leaf without DFProperties is skipped silently",
			xmlContent: `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>EmptyLeaf</NodeName>
	</Node>
	<Node>
		<NodeName>RealPolicy</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`,
			filename:      "Mixed.xml",
			wantEntries:   1,
			wantAnomalies: 0,
		},
		{
			name:        "non-existent file",
			xmlContent:  "",
			filename:    "nonexistent.xml",
			wantEntries: 0,
		},
		{
			name:        "invalid XML content",
			xmlContent:  `This is not XML at all! <broken>`,
			filename:    "invalid.xml",
			wantEntries: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()

			if tt.xmlContent != "" {
				fpath := filepath.Join(tmpDir, tt.filename)
				if err := os.WriteFile(fpath, []byte(tt.xmlContent), 0644); err != nil {
					t.Fatalf("failed to write test file: %v", err)
				}
				c.processFile(fpath)
			} else {
				c.processFile(filepath.Join(tmpDir, tt.filename))
			}

			if len(c.Entries) != tt.wantEntries {
				t.Errorf("got %d entries, want %d", len(c.Entries), tt.wantEntries)
			}
			if len(c.Anomalies) != tt.wantAnomalies {
				t.Errorf("got %d anomalies, want %d", len(c.Anomalies), tt.wantAnomalies)
			}

			// Verify CSP name extraction from filename
			if tt.wantEntries > 0 && len(c.Entries) > 0 {
				wantCSP := strings.TrimSuffix(tt.filename, filepath.Ext(tt.filename))
				if c.Entries[0].CSPName != wantCSP {
					t.Errorf("CSPName = %q, want %q", c.Entries[0].CSPName, wantCSP)
				}
			}
		})
	}
}

// ── helperForInsert ────────────────────────────────────────────────────────

// helperForInsert creates a fresh temp SQLite database with migrations applied,
// and returns the *db.DB along with a cleanup func that removes the temp
// directory. Each call creates an entirely new database so subtests get
// clean slate isolation.
func helperForInsert(t *testing.T) (database *db.DB, cleanup func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	database, err := db.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	// Capture tmpDir in the closure so we can remove it on cleanup.
	// t.TempDir() would auto-clean, but we explicitly remove it here to
	// ensure the directory is gone before the test process exits, avoiding
	// orphaned .db files on disk.
	return database, func() {
		database.Close()
		_ = os.RemoveAll(tmpDir)
	}
}

// ── TestInsertCatalogEntries ─────────────────────────────────────────────────

func TestInsertCatalogEntries(t *testing.T) {
	tests := []struct {
		name         string
		entries      []CatalogEntry
		wantInserted int
		wantUpdated  int
	}{
		{
			name: "single entry insert",
			entries: []CatalogEntry{
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
					DisplayName:   "Max Encryption",
					Description:   "Maximum encryption size",
					Category:      "BitLocker",
					CSPName:       "BitLocker",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
			},
			wantInserted: 1,
			wantUpdated:  0,
		},
		{
			name: "multiple entries insert",
			entries: []CatalogEntry{
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
					DisplayName:   "Max Encryption",
					Category:      "BitLocker",
					CSPName:       "BitLocker",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/DeviceLock/MinPasswordLength",
					DisplayName:   "Min Password Length",
					Category:      "DeviceLock",
					CSPName:       "DeviceLock",
					DataType:      "integer",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/WiFi/EnableWiFi",
					DisplayName:   "Enable WiFi",
					Category:      "WiFi",
					CSPName:       "WiFi",
					DataType:      "boolean",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
			},
			wantInserted: 3,
			wantUpdated:  0,
		},
		{
			name: "upsert existing entry",
			entries: []CatalogEntry{
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
					DisplayName:   "Max Encryption",
					Category:      "BitLocker",
					CSPName:       "BitLocker",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
					DisplayName:   "Max Encryption Updated",
					Category:      "BitLocker",
					CSPName:       "BitLocker",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
			},
			wantInserted: 1,
			wantUpdated:  1,
		},
		{
			name: "mixed insert and update",
			entries: []CatalogEntry{
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/A/PolicyA",
					DisplayName:   "Policy A",
					Category:      "A",
					CSPName:       "A",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/B/PolicyB",
					DisplayName:   "Policy B",
					Category:      "B",
					CSPName:       "B",
					DataType:      "integer",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/A/PolicyA",
					DisplayName:   "Policy A Updated",
					Category:      "A Updated",
					CSPName:       "A",
					DataType:      "string",
					AllowedValues: "[]",
					AccessTypes:   `["Get","Replace"]`,
				},
			},
			wantInserted: 2,
			wantUpdated:  1,
		},
		{
			name:         "empty entries",
			entries:      []CatalogEntry{},
			wantInserted: 0,
			wantUpdated:  0,
		},
		{
			name: "entry with all fields populated",
			entries: []CatalogEntry{
				{
					OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/FullPolicy",
					DisplayName:   "Full Policy",
					Description:   "A comprehensive test policy",
					Category:      "BitLocker",
					CSPName:       "BitLocker",
					DataType:      "string",
					AllowedValues: `["enabled","disabled"]`,
					DefaultValue:  "enabled",
					MinOSVersion:  "10.0.17763",
					AccessTypes:   `["Get","Replace","Exec"]`,
					IsDeprecated:  false,
				},
			},
			wantInserted: 1,
			wantUpdated:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each subtest gets a fresh database so one test case
			// doesn't unduly influence the next.
			database, cleanup := helperForInsert(t)
			defer cleanup()

			inserted, updated, err := insertCatalogEntries(database, tt.entries)
			if err != nil {
				t.Fatalf("insertCatalogEntries() error: %v", err)
			}

			if inserted != tt.wantInserted {
				t.Errorf("inserted = %d, want %d", inserted, tt.wantInserted)
			}
			if updated != tt.wantUpdated {
				t.Errorf("updated = %d, want %d", updated, tt.wantUpdated)
			}

			// Verify all entries are in the database
			var count int
			err = database.QueryRow("SELECT COUNT(*) FROM policy_catalog").Scan(&count)
			if err != nil {
				t.Fatalf("failed to query policy_catalog: %v", err)
			}
			uniqueURIs := make(map[string]bool)
			for _, e := range tt.entries {
				uniqueURIs[e.OMAURI] = true
			}
			wantTotal := len(uniqueURIs)
			if count != wantTotal {
				t.Errorf("total rows = %d, want %d", count, wantTotal)
			}
		})
	}
}

// ── TestInsertCatalogEntriesFieldVerification ────────────────────────────────

func TestInsertCatalogEntriesFieldVerification(t *testing.T) {
	database, cleanup := helperForInsert(t)
	defer cleanup()

	entry := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/VerifyFields",
		DisplayName:   "Verify Fields",
		Description:   "Test description for field verification",
		Category:      "BitLocker",
		CSPName:       "BitLocker",
		DataType:      "string",
		AllowedValues: `["value1","value2","value3"]`,
		DefaultValue:  "value1",
		MinOSVersion:  "10.0.17763",
		AccessTypes:   `["Get","Replace","Exec"]`,
		IsDeprecated:  true,
	}

	inserted, _, err := insertCatalogEntries(database, []CatalogEntry{entry})
	if err != nil {
		t.Fatalf("insertCatalogEntries() error: %v", err)
	}
	if inserted != 1 {
		t.Errorf("inserted = %d, want 1", inserted)
	}

	var storedOMAURI, storedDisplayName, storedDescription, storedCategory, storedCSPName string
	var storedDataType, storedAllowedValues, storedDefaultValue, storedMinOSVersion string
	var storedAccessTypes string
	var storedIsDeprecated int

	err = database.QueryRow(`SELECT 
		oma_uri, display_name, description, category, csp_name,
		data_type, allowed_values, default_value, min_os_version,
		access_types, is_deprecated
		FROM policy_catalog WHERE oma_uri = ?`, entry.OMAURI).Scan(
		&storedOMAURI, &storedDisplayName, &storedDescription, &storedCategory,
		&storedCSPName, &storedDataType, &storedAllowedValues, &storedDefaultValue,
		&storedMinOSVersion, &storedAccessTypes, &storedIsDeprecated,
	)
	if err != nil {
		t.Fatalf("failed to query stored entry: %v", err)
	}

	if storedOMAURI != entry.OMAURI {
		t.Errorf("oma_uri = %q, want %q", storedOMAURI, entry.OMAURI)
	}
	if storedDisplayName != entry.DisplayName {
		t.Errorf("display_name = %q, want %q", storedDisplayName, entry.DisplayName)
	}
	if storedDescription != entry.Description {
		t.Errorf("description = %q, want %q", storedDescription, entry.Description)
	}
	if storedCategory != entry.Category {
		t.Errorf("category = %q, want %q", storedCategory, entry.Category)
	}
	if storedCSPName != entry.CSPName {
		t.Errorf("csp_name = %q, want %q", storedCSPName, entry.CSPName)
	}
	if storedDataType != entry.DataType {
		t.Errorf("data_type = %q, want %q", storedDataType, entry.DataType)
	}
	if storedAllowedValues != entry.AllowedValues {
		t.Errorf("allowed_values = %q, want %q", storedAllowedValues, entry.AllowedValues)
	}
	if storedDefaultValue != entry.DefaultValue {
		t.Errorf("default_value = %q, want %q", storedDefaultValue, entry.DefaultValue)
	}
	if storedMinOSVersion != entry.MinOSVersion {
		t.Errorf("min_os_version = %q, want %q", storedMinOSVersion, entry.MinOSVersion)
	}
	if storedAccessTypes != entry.AccessTypes {
		t.Errorf("access_types = %q, want %q", storedAccessTypes, entry.AccessTypes)
	}
	if storedIsDeprecated != 1 {
		t.Errorf("is_deprecated = %d, want 1", storedIsDeprecated)
	}
}

// ── TestInsertCatalogEntriesErrorHandling ─────────────────────────────────────

func TestInsertCatalogEntriesErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Open with a fresh database that has no migrations applied.
	// We'll create the table manually without the unique constraint to test
	// the sqlite INSERT OR IGNORE path works correctly.
	sqlDB, err := db.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	defer sqlDB.Close()

	// Drop any existing table and create a version without the unique constraint
	// to verify the sqlite fallback path handles inserts gracefully.
	_, err = sqlDB.Exec(`DROP TABLE IF EXISTS policy_catalog; CREATE TABLE policy_catalog (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		oma_uri TEXT NOT NULL,
		display_name TEXT,
		description TEXT,
		category TEXT,
		csp_name TEXT,
		data_type TEXT,
		allowed_values TEXT,
		default_value TEXT,
		min_os_version TEXT,
		access_types TEXT,
		is_deprecated INTEGER DEFAULT 0,
		source TEXT DEFAULT 'ddf',
		updated_at TEXT
	)`)
	if err != nil {
		t.Fatalf("failed to set up test table: %v", err)
	}

	entry := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/Test",
		DisplayName:   "Test",
		Category:      "Test",
		CSPName:       "Test",
		DataType:      "string",
		AllowedValues: "[]",
		AccessTypes:   `["Get","Replace"]`,
	}
	_, _, err = insertCatalogEntries(sqlDB, []CatalogEntry{entry})
	if err != nil {
		t.Errorf("insertCatalogEntries() error (expected to succeed without unique constraint): %v", err)
	}
}

// ── TestCatalogEntryJSONMarshaling ───────────────────────────────────────────

func TestCatalogEntryJSONMarshaling(t *testing.T) {
	entry := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
		DisplayName:   "Max Encryption",
		Description:   "Maximum encryption size",
		Category:      "BitLocker",
		CSPName:       "BitLocker",
		DataType:      "string",
		AllowedValues: `["enabled","disabled"]`,
		DefaultValue:  "enabled",
		MinOSVersion:  "10.0.17763",
		AccessTypes:   `["Get","Replace","Exec"]`,
		IsDeprecated:  false,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded CatalogEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.OMAURI != entry.OMAURI {
		t.Errorf("OMAURI = %q, want %q", decoded.OMAURI, entry.OMAURI)
	}
	if decoded.DisplayName != entry.DisplayName {
		t.Errorf("DisplayName = %q, want %q", decoded.DisplayName, entry.DisplayName)
	}
	if decoded.Description != entry.Description {
		t.Errorf("Description = %q, want %q", decoded.Description, entry.Description)
	}
	if decoded.DataType != entry.DataType {
		t.Errorf("DataType = %q, want %q", decoded.DataType, entry.DataType)
	}
	if decoded.AllowedValues != entry.AllowedValues {
		t.Errorf("AllowedValues = %q, want %q", decoded.AllowedValues, entry.AllowedValues)
	}
	if decoded.AccessTypes != entry.AccessTypes {
		t.Errorf("AccessTypes = %q, want %q", decoded.AccessTypes, entry.AccessTypes)
	}
	if decoded.IsDeprecated != entry.IsDeprecated {
		t.Errorf("IsDeprecated = %v, want %v", decoded.IsDeprecated, entry.IsDeprecated)
	}
}

// ── TestCatalogEntryJSONEmptyFields ──────────────────────────────────────────

func TestCatalogEntryJSONEmptyFields(t *testing.T) {
	entry := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/Test/Empty",
		DisplayName:   "Empty Fields",
		CSPName:       "Test",
		Category:      "Test",
		DataType:      "string",
		AllowedValues: "[]",
		AccessTypes:   `["Get","Replace"]`,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded CatalogEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.OMAURI != entry.OMAURI {
		t.Errorf("OMAURI = %q, want %q", decoded.OMAURI, entry.OMAURI)
	}
	if decoded.Description != "" {
		t.Errorf("Description should be empty, got %q", decoded.Description)
	}
	if decoded.DefaultValue != "" {
		t.Errorf("DefaultValue should be empty, got %q", decoded.DefaultValue)
	}
	if decoded.MinOSVersion != "" {
		t.Errorf("MinOSVersion should be empty, got %q", decoded.MinOSVersion)
	}
}

// ── TestCompileNodeWithDifferentFormats ──────────────────────────────────────

func TestCompileNodeWithDifferentFormats(t *testing.T) {
	tests := []struct {
		name     string
		format   *Format
		wantType string
	}{
		{"chr format", &Format{Chr: ptrStruct}, "string"},
		{"int format", &Format{Int: ptrStruct}, "integer"},
		{"bool format", &Format{Bool: ptrStruct}, "boolean"},
		{"b64 format", &Format{B64: ptrStruct}, "base64"},
		{"xml format", &Format{Xml: ptrStruct}, "xml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := Node{
				NodeName: "FormatTest",
				DFProperties: &DFProperties{
					AccessType: &AccessType{
						Get:     ptrStruct,
						Replace: ptrStruct,
					},
					Format: tt.format,
				},
			}

			entry, err := compileNode(node, "./Vendor/MSFT/Policy/Config/Test", "Test")
			if err != nil {
				t.Fatalf("compileNode() error: %v", err)
			}
			if entry.DataType != tt.wantType {
				t.Errorf("DataType = %q, want %q", entry.DataType, tt.wantType)
			}
		})
	}
}

// ── TestCompileNodeAccessTypeCombos ──────────────────────────────────────────

func TestCompileNodeAccessTypeCombos(t *testing.T) {
	tests := []struct {
		name       string
		accessType *AccessType
		wantTypes  []string
	}{
		{"Get only", &AccessType{Get: ptrStruct}, []string{"Get"}},
		{"Replace only", &AccessType{Replace: ptrStruct}, []string{"Replace"}},
		{"Get + Replace", &AccessType{Get: ptrStruct, Replace: ptrStruct}, []string{"Get", "Replace"}},
		{"Get + Add", &AccessType{Get: ptrStruct, Add: ptrStruct}, []string{"Get", "Add"}},
		{"Get + Delete", &AccessType{Get: ptrStruct, Delete: ptrStruct}, []string{"Get", "Delete"}},
		{"Get + Exec", &AccessType{Get: ptrStruct, Exec: ptrStruct}, []string{"Get", "Exec"}},
		{"All access types", &AccessType{Get: ptrStruct, Replace: ptrStruct, Add: ptrStruct, Delete: ptrStruct, Exec: ptrStruct}, []string{"Get", "Replace", "Add", "Delete", "Exec"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := Node{
				NodeName: "AccessTest",
				DFProperties: &DFProperties{
					AccessType: tt.accessType,
					Format:     &Format{Chr: ptrStruct},
				},
			}

			entry, err := compileNode(node, "./Vendor/MSFT/Policy/Config/Test", "Test")
			if err != nil {
				t.Fatalf("compileNode() error: %v", err)
			}

			var accessTypes []string
			if err := json.Unmarshal([]byte(entry.AccessTypes), &accessTypes); err != nil {
				t.Fatalf("failed to unmarshal AccessTypes: %v", err)
			}

			if len(accessTypes) != len(tt.wantTypes) {
				t.Errorf("got %d access types, want %d", len(accessTypes), len(tt.wantTypes))
			}

			for i, want := range tt.wantTypes {
				if i >= len(accessTypes) {
					t.Errorf("accessTypes[%d] = <missing>, want %q (got: %v)", i, want, accessTypes)
					continue
				}
				if accessTypes[i] != want {
					t.Errorf("accessTypes[%d] = %q, want %q", i, accessTypes[i], want)
				}
			}
		})
	}
}

// ── TestCompilerTraverseNodePathConstruction ──────────────────────────────────

func TestCompilerTraverseNodePathConstruction(t *testing.T) {
	tests := []struct {
		name       string
		parentPath string
		nodeName   string
		wantURI    string
	}{
		{"root path with nodename", ".", "Policy", "./Vendor/MSFT/Policy/Config/Policy"},
		{"path with trailing slash", "./Vendor/MSFT/", "Policy", "./Vendor/MSFT/Policy"},
		{"path without trailing slash", "./Vendor/MSFT", "Policy", "./Vendor/MSFT/Policy"},
		{"deep nested path", "./Vendor/MSFT/Policy/Config", "BitLocker", "./Vendor/MSFT/Policy/Config/BitLocker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCompiler()
			node := Node{
				NodeName: tt.nodeName,
				DFProperties: &DFProperties{
					AccessType: &AccessType{Get: ptrStruct},
					Format:     &Format{Chr: ptrStruct},
				},
			}
			c.traverseNode(node, tt.parentPath, "Test", "test.xml")

			if len(c.Entries) != 1 {
				t.Fatalf("got %d entries, want 1", len(c.Entries))
			}
			expectedURI := tt.parentPath
			if tt.nodeName != "" {
				if strings.HasSuffix(tt.parentPath, "/") {
					expectedURI = tt.parentPath + tt.nodeName
				} else {
					expectedURI = tt.parentPath + "/" + tt.nodeName
				}
			}
			if c.Entries[0].OMAURI != expectedURI {
				t.Errorf("OMAURI = %q, want %q", c.Entries[0].OMAURI, expectedURI)
			}
		})
	}
}

// ── TestProcessFileMultiplePolicies ──────────────────────────────────────────

func TestProcessFileMultiplePolicies(t *testing.T) {
	tmpDir := t.TempDir()
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>Policy1</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>Policy2</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><int/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>Policy3</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><bool/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`

	fpath := filepath.Join(tmpDir, "MultiPolicy.xml")
	if err := os.WriteFile(fpath, []byte(xmlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c := NewCompiler()
	c.processFile(fpath)

	if len(c.Entries) != 3 {
		t.Errorf("got %d entries, want 3", len(c.Entries))
	}
	if len(c.Anomalies) != 0 {
		t.Errorf("got %d anomalies, want 0", len(c.Anomalies))
	}

	for _, entry := range c.Entries {
		if entry.CSPName != "MultiPolicy" {
			t.Errorf("CSPName = %q, want %q", entry.CSPName, "MultiPolicy")
		}
	}

	typeMap := map[string]string{
		"Policy1": "string",
		"Policy2": "integer",
		"Policy3": "boolean",
	}
	for _, entry := range c.Entries {
		expectedType, ok := typeMap[entry.DisplayName]
		if !ok {
			t.Errorf("unexpected entry DisplayName: %q", entry.DisplayName)
			continue
		}
		if entry.DataType != expectedType {
			t.Errorf("DisplayName %q DataType = %q, want %q", entry.DisplayName, entry.DataType, expectedType)
		}
	}
}

// ── TestProcessFileMixedValidAndInvalid ──────────────────────────────────────

func TestProcessFileMixedValidAndInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>ValidPolicy</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>NoAccess</NodeName>
		<DFProperties>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>ValidPolicy2</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><int/></DFFormat>
		</DFProperties>
	</Node>
	<Node>
		<NodeName>NoFormat</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
		</DFProperties>
	</Node>
</MgmtTree>`

	fpath := filepath.Join(tmpDir, "Mixed.xml")
	if err := os.WriteFile(fpath, []byte(xmlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c := NewCompiler()
	c.processFile(fpath)

	if len(c.Entries) != 2 {
		t.Errorf("got %d entries, want 2", len(c.Entries))
	}
	if len(c.Anomalies) != 2 {
		t.Errorf("got %d anomalies, want 2", len(c.Anomalies))
	}

	for _, entry := range c.Entries {
		if entry.DisplayName != "ValidPolicy" && entry.DisplayName != "ValidPolicy2" {
			t.Errorf("unexpected valid entry DisplayName: %q", entry.DisplayName)
		}
	}

	anomalyMap := map[string]bool{}
	for _, a := range c.Anomalies {
		if strings.Contains(a, "NoAccess") {
			anomalyMap["NoAccess"] = true
		}
		if strings.Contains(a, "NoFormat") {
			anomalyMap["NoFormat"] = true
		}
	}
	if !anomalyMap["NoAccess"] {
		t.Error("expected anomaly for NoAccess")
	}
	if !anomalyMap["NoFormat"] {
		t.Error("expected anomaly for NoFormat")
	}
}

// ── TestProcessFileWithDescription ───────────────────────────────────────────

func TestProcessFileWithDescription(t *testing.T) {
	tmpDir := t.TempDir()
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>DescribedPolicy</NodeName>
		<DFProperties>
			<AccessType><Get/><Replace/></AccessType>
			<DFFormat><chr/></DFFormat>
			<Description>This is a described policy</Description>
		</DFProperties>
	</Node>
</MgmtTree>`

	fpath := filepath.Join(tmpDir, "Described.xml")
	if err := os.WriteFile(fpath, []byte(xmlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c := NewCompiler()
	c.processFile(fpath)

	if len(c.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(c.Entries))
	}

	if c.Entries[0].Description != "This is a described policy" {
		t.Errorf("Description = %q, want %q", c.Entries[0].Description, "This is a described policy")
	}
}

// ── TestInsertCatalogEntriesWithUpdate ───────────────────────────────────────

func TestInsertCatalogEntriesWithUpdate(t *testing.T) {
	database, cleanup := helperForInsert(t)
	defer cleanup()

	entry1 := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/UpdateTest",
		DisplayName:   "Original Name",
		Category:      "BitLocker",
		CSPName:       "BitLocker",
		DataType:      "string",
		AllowedValues: `["a","b"]`,
		AccessTypes:   `["Get","Replace"]`,
	}

	inserted, updated, err := insertCatalogEntries(database, []CatalogEntry{entry1})
	if err != nil {
		t.Fatalf("first insert error: %v", err)
	}
	if inserted != 1 || updated != 0 {
		t.Errorf("first insert: inserted = %d, updated = %d, want 1, 0", inserted, updated)
	}

	entry2 := CatalogEntry{
		OMAURI:        "./Vendor/MSFT/Policy/Config/BitLocker/UpdateTest",
		DisplayName:   "Updated Name",
		Category:      "BitLocker Updated",
		CSPName:       "BitLocker",
		DataType:      "integer",
		AllowedValues: `["x","y","z"]`,
		AccessTypes:   `["Get","Replace","Exec"]`,
	}

	inserted, updated, err = insertCatalogEntries(database, []CatalogEntry{entry2})
	if err != nil {
		t.Fatalf("second insert error: %v", err)
	}
	if inserted != 0 || updated != 1 {
		t.Errorf("second insert: inserted = %d, updated = %d, want 0, 1", inserted, updated)
	}

	var displayName, category, dataType, allowedValues, accessTypes string
	err = database.QueryRow(`SELECT display_name, category, data_type, allowed_values, access_types 
		FROM policy_catalog WHERE oma_uri = ?`, entry1.OMAURI).Scan(
		&displayName, &category, &dataType, &allowedValues, &accessTypes)
	if err != nil {
		t.Fatalf("query error: %v", err)
	}

	if displayName != "Updated Name" {
		t.Errorf("display_name = %q, want %q", displayName, "Updated Name")
	}
	if category != "BitLocker Updated" {
		t.Errorf("category = %q, want %q", category, "BitLocker Updated")
	}
	if dataType != "integer" {
		t.Errorf("data_type = %q, want %q", dataType, "integer")
	}
	if allowedValues != `["x","y","z"]` {
		t.Errorf("allowed_values = %q, want %q", allowedValues, `["x","y","z"]`)
	}
	if accessTypes != `["Get","Replace","Exec"]` {
		t.Errorf("access_types = %q, want %q", accessTypes, `["Get","Replace","Exec"]`)
	}
}

// ── TestCompilerTraverseNodeDeepNesting ──────────────────────────────────────

func TestCompilerTraverseNodeDeepNesting(t *testing.T) {
	c := NewCompiler()

	root := Node{
		NodeName: "Level1",
		Nodes: []Node{
			{
				NodeName: "Level2",
				Nodes: []Node{
					{
						NodeName: "Level3",
						Nodes: []Node{
							{
								NodeName: "Level4",
								Nodes: []Node{
									{
										NodeName: "LeafPolicy",
										DFProperties: &DFProperties{
											AccessType: &AccessType{Get: ptrStruct, Replace: ptrStruct},
											Format:     &Format{Chr: ptrStruct},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	c.traverseNode(root, "./Vendor/MSFT/Policy", "DeepCSP", "deep.xml")

	if len(c.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(c.Entries))
	}

	expectedURI := "./Vendor/MSFT/Policy/Level1/Level2/Level3/Level4/LeafPolicy"
	if c.Entries[0].OMAURI != expectedURI {
		t.Errorf("OMAURI = %q, want %q", c.Entries[0].OMAURI, expectedURI)
	}
}

// ── TestInsertCatalogEntriesMultipleUpserts ──────────────────────────────────

func TestInsertCatalogEntriesMultipleUpserts(t *testing.T) {
	database, cleanup := helperForInsert(t)
	defer cleanup()

	entries := []CatalogEntry{
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/A/PolicyA",
			DisplayName:   "Policy A",
			Category:      "A",
			CSPName:       "A",
			DataType:      "string",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/B/PolicyB",
			DisplayName:   "Policy B",
			Category:      "B",
			CSPName:       "B",
			DataType:      "integer",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/C/PolicyC",
			DisplayName:   "Policy C",
			Category:      "C",
			CSPName:       "C",
			DataType:      "boolean",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
	}

	inserted, updated, err := insertCatalogEntries(database, entries)
	if err != nil {
		t.Fatalf("first batch insert error: %v", err)
	}
	if inserted != 3 || updated != 0 {
		t.Errorf("first batch: inserted = %d, updated = %d, want 3, 0", inserted, updated)
	}

	updatedEntries := []CatalogEntry{
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/A/PolicyA",
			DisplayName:   "Policy A Updated",
			Category:      "A",
			CSPName:       "A",
			DataType:      "string",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/B/PolicyB",
			DisplayName:   "Policy B Updated",
			Category:      "B",
			CSPName:       "B",
			DataType:      "integer",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
		{
			OMAURI:        "./Vendor/MSFT/Policy/Config/C/PolicyC",
			DisplayName:   "Policy C Updated",
			Category:      "C",
			CSPName:       "C",
			DataType:      "boolean",
			AllowedValues: "[]",
			AccessTypes:   `["Get","Replace"]`,
		},
	}

	inserted, updated, err = insertCatalogEntries(database, updatedEntries)
	if err != nil {
		t.Fatalf("second batch insert error: %v", err)
	}
	if inserted != 0 || updated != 3 {
		t.Errorf("second batch: inserted = %d, updated = %d, want 0, 3", inserted, updated)
	}

	var count int
	err = database.QueryRow("SELECT COUNT(*) FROM policy_catalog WHERE display_name LIKE '%Updated%'").Scan(&count)
	if err != nil {
		t.Fatalf("query error: %v", err)
	}
	if count != 3 {
		t.Errorf("updated count = %d, want 3", count)
	}
}

// ── TestProcessFileWithAllAccessTypes ────────────────────────────────────────

func TestProcessFileWithAllAccessTypes(t *testing.T) {
	tmpDir := t.TempDir()
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
	<Node>
		<NodeName>FullAccess</NodeName>
		<DFProperties>
			<AccessType>
				<Get/><Replace/><Add/><Delete/><Exec/>
			</AccessType>
			<DFFormat><chr/></DFFormat>
		</DFProperties>
	</Node>
</MgmtTree>`

	fpath := filepath.Join(tmpDir, "FullAccess.xml")
	if err := os.WriteFile(fpath, []byte(xmlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c := NewCompiler()
	c.processFile(fpath)

	if len(c.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(c.Entries))
	}

	var accessTypes []string
	if err := json.Unmarshal([]byte(c.Entries[0].AccessTypes), &accessTypes); err != nil {
		t.Fatalf("failed to unmarshal AccessTypes: %v", err)
	}

	expectedTypes := []string{"Get", "Replace", "Add", "Delete", "Exec"}
	if len(accessTypes) != len(expectedTypes) {
		t.Errorf("got %d access types, want %d", len(accessTypes), len(expectedTypes))
	}

	for i, want := range expectedTypes {
		if i >= len(accessTypes) {
			t.Errorf("accessTypes[%d] = <missing>, want %q", i, want)
			continue
		}
		if accessTypes[i] != want {
			t.Errorf("accessTypes[%d] = %q, want %q", i, accessTypes[i], want)
		}
	}
}
