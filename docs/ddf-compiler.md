# DDF Compiler — Policy Catalog Ingestion Guide

The DDF (Device Description Framework) Compiler is a standalone CLI tool that parses Microsoft's DDF XML schemas and populates Latchz's **Policy Catalog** — the searchable database of available device configuration policies shown in the dashboard.

## Why You Need It

When a device is enrolled in Latchz, administrators create **configuration profiles** that assign specific policies (e.g., "require a password", "enable BitLocker"). The Policy Catalog defines **which policies are available** and their metadata (data type, access type, allowed values).

Without ingesting DDF files, the catalog is empty and the profile editor has no policies to assign.

## How It Works

```
Microsoft DDF XML files
        │
        ▼
  DDF Compiler (cmd/ddf-compiler)
        │
        ├── Parses XML tree structure
        ├── ExtractsOMA-URI, display name, description, data type
        ├── Determines access types (Get, Replace, Add, Delete, Exec)
        └── Generates anomaly report for unparseable nodes
        │
        ▼
  policy_catalog table (SQLite / PostgreSQL)
        │
        ▼
  Dashboard Policy Catalog UI
```

## Installation

Build the compiler from source:

```bash
go build -o ddf-compiler ./cmd/ddf-compiler
```

This produces a single statically-linked binary with no runtime dependencies.

## Usage

```bash
./ddf-compiler -config <config> -in <directory> [options]
```

### Command-Line Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-config` | No | `latchz.yaml` | Path to Latchz configuration YAML (provides `database.driver` and `database.dsn`) |
| `-in` | **Yes** | — | Directory containing Microsoft DDF XML files |
| `-out` | No | (none) | Optional: write parsed entries to a JSON catalog file |
| `-report` | No | `parser_anomalies_report.md` | Path to write the anomalies report (set to `/dev/null` or `""` to suppress) |

### Examples

**Basic usage** (read database config from `latchz.yaml`, parse `./ddf` directory):

```bash
./ddf-compiler -in ./ddf
```

**With output catalog and custom report path:**

```bash
./ddf-compiler \
  -config /etc/latchz/latchz.yaml \
  -in ./ddf \
  -out catalog.json \
  -report anomalies.md
```

**Using environment variable overrides for database:**

```bash
LATCHZ_DATABASE_DRIVER=postgres \
LATCHZ_DATABASE_DSN="postgres://latchz:pass@localhost/latchz" \
./ddf-compiler -in ./ddf
```

## Getting Microsoft DDF Files

Microsoft publishes DDF XML files for all Windows CSPs (Configuration Service Providers). These files define the complete set of available policies per CSP.

### Where to Find Them

1. **Microsoft Intune Content Tools** — The [Microsoft Intune Windows 10 SDK](https://developer.microsoft.com/en-us/windows/iot/sdks) includes DDF reference files.

2. **Microsoft Documentation** — Each CSP page on [Microsoft Learn](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider) references the DDF schema. The DDF XML files are sometimes bundled with the [MDT (Microsoft Deployment Toolkit)](https://learn.microsoft.com/en-us/windows/deployment/mt/) or the [Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install).

3. **Windows SDK** — If you have the Windows 10/11 SDK installed, DDF files are typically at:
   ```
   C:\Program Files (x86)\Windows Kits\10\PolicyConfig\
   ```

4. **Community collections** — Various community-maintained collections of DDF files exist on GitHub. Search for "windows DDF files" or "Microsoft DDF CSP".

### Organizing DDF Files

Place all DDF XML files in a single directory (or subdirectories). The compiler recursively walks the input directory:

```
ddf/
├── BitLocker.xml
├── DeviceLock.xml
├── WiFi.xml
├── Certificate.xml
└── EnterpriseCertEnroll.xml
```

> **Note:** The compiler processes all `.xml` files in the input directory and its subdirectories. Non-DDF XML files will be silently skipped if they don't contain valid DDF structure.

## What the Compiler Extracts

For each leaf node in the DDF XML tree, the compiler extracts:

| Field | Source | Description |
|-------|--------|-------------|
| `oma_uri` | XML node path | The OMA-URI used to target the policy (e.g., `./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption`) |
| `display_name` | XML `NodeName` | Human-readable policy name |
| `description` | XML `DFProperties/Description` | Policy description (trimmed of whitespace) |
| `category` | Filename | CSP name derived from the XML filename (e.g., `BitLocker.xml` → `BitLocker`) |
| `csp_name` | Filename | Same as category; identifies the Configuration Service Provider |
| `data_type` | XML `DFProperties/DFFormat` | One of: `string`, `integer`, `boolean`, `base64`, `xml` |
| `allowed_values` | — | JSON array string (reserved for future use; currently always `"[]"`) |
| `default_value` | — | Default value (not extracted from DDF; currently empty) |
| `min_os_version` | — | Minimum Windows version (not extracted from DDF; currently empty) |
| `access_types` | XML `DFProperties/AccessType` | JSON array of supported operations: `Get`, `Replace`, `Add`, `Delete`, `Exec` |
| `is_deprecated` | — | Whether the policy is deprecated (not extracted from DDF; currently `false`) |
| `source` | Hardcoded | Always `"ddf"` |

### Supported XML Structure

The compiler expects DDF files with this structure:

```xml
<MgmtTree>
  <Node>
    <NodeName>MaxEncryption</NodeName>
    <DFProperties>
      <AccessType>
        <Get/>
        <Replace/>
      </AccessType>
      <DFFormat>
        <chr/>
      </DFFormat>
      <Description>Maximum encryption level</Description>
    </DFProperties>
  </Node>
</MgmtTree>
```

**Supported `<DFFormat>` types:**

| XML Tag | Extracted `data_type` |
|---------|----------------------|
| `<chr/>` | `string` |
| `<int/>` | `integer` |
| `<bool/>` | `boolean` |
| `<b64/>` | `base64` |
| `<xml/>` | `xml` |

**Supported `<AccessType>` tags:**

| Tag | Extracted operation |
|-----|---------------------|
| `<Get/>` | `Get` |
| `<Replace/>` | `Replace` |
| `<Add/>` | `Add` |
| `<Delete/>` | `Delete` |
| `<Exec/>` | `Exec` |

A policy node **must** have at least one of `<Get/>` or `<Replace/>` in `<AccessType>` and exactly one `<DFFormat>` tag. Nodes missing these are recorded as anomalies.

### Namespace Handling

Some DDF files use namespace prefixes like `<SyncML:MgmtTree>` or `<SyncML:Node>`. The compiler strips these prefixes automatically before parsing:

```
<SyncML:MgmtTree>  →  <MgmtTree>
<SyncML:Node>      →  <Node>
```

If a file still fails to parse after namespace stripping, it will be logged as an anomaly.

## Database Behavior

### Upsert Logic

The compiler uses **upsert** semantics — if a policy with the same `oma_uri` already exists in the catalog, it is **updated** rather than duplicated.

**PostgreSQL:**
```sql
INSERT INTO policy_catalog (...) VALUES (...)
ON CONFLICT (oma_uri) DO UPDATE SET ...
```

**SQLite:**
```sql
-- Step 1: Try INSERT OR IGNORE
INSERT OR IGNORE INTO policy_catalog (...) VALUES (...);
-- Step 2: If 0 rows affected, UPDATE instead
UPDATE policy_catalog SET ... WHERE oma_uri = ?;
```

### Migration Requirement

The `policy_catalog` table is created by migration `0001_initial_schema.up.sql`. Ensure your database has been migrated before running the compiler:

```bash
# The compiler runs migrations automatically via db.Open(), but you can
# also run them manually:
go run github.com/golang-migrate/migrate/v4/cmd/migrate -path internal/db/migrations/sqlite -database sqlite:///latchz.db up
```

## Output

### Database Insertion

After parsing, all entries are inserted into the `policy_catalog` table. You can verify the results:

```sql
SELECT COUNT(*) FROM policy_catalog;
-- Example output: 1247

SELECT category, COUNT(*) FROM policy_catalog GROUP BY category ORDER BY COUNT(*) DESC;
-- Example output:
-- BitLocker         | 45
-- DeviceLock        | 38
-- WiFi              | 29
```

### JSON Catalog (Optional)

When `-out catalog.json` is specified, the parsed entries are written as a JSON array:

```json
[
  {
    "oma_uri": "./Vendor/MSFT/Policy/Config/BitLocker/MaxEncryption",
    "display_name": "MaxEncryption",
    "description": "Maximum encryption level",
    "category": "BitLocker",
    "csp_name": "BitLocker",
    "data_type": "string",
    "allowed_values": "[]",
    "default_value": "",
    "min_os_version": "",
    "access_types": "[\"Get\",\"Replace\"]",
    "is_deprecated": false
  }
]
```

This is useful for:
- Previewing what will be inserted before writing to the database
- Sharing policy catalogs between team members
- Version-controlling your policy catalog

### Anomaly Report

Nodes that fail to compile are logged to a Markdown report file. This helps identify DDF files that need manual attention or custom parsing rules.

**Example anomaly entry:**

```markdown
## Missing properties at `./Vendor/MSFT/Policy/Config/BitLocker/SomePolicy`
**Source:** `BitLocker.xml`
**Error:** no AccessType tags found (Get/Replace missing)

```xml
<!-- Leaf Node XML -->
<NodeName>SomePolicy</NodeName>
```
```

Common anomaly causes:

| Cause | Fix |
|-------|-----|
| Missing `<AccessType>` tag | Node is layout padding, not a policy |
| Missing `<DFFormat>` tag | Node has no data type, skip |
| Empty `<NodeName>` | Layout element, skip |
| Missing `<DFProperties>` | Container node, skip |
| Unparseable XML namespace | File needs namespace mapping |

> **Tip:** A non-zero anomaly count is normal. Many DDF nodes are structural containers (folders) rather than actual policies. The compiler silently skips valid container nodes; only leaf nodes with missing properties generate anomalies.

## Troubleshooting

### "Failed to open database"

Ensure the database driver and connection string are correctly configured in the config file:

```yaml
database:
  driver: sqlite        # or "postgres"
  dsn: /path/to/latchz.db
```

For PostgreSQL:

```yaml
database:
  driver: postgres
  dsn: "postgres://user:pass@host:5432/latchz?sslmode=require"
```

### "Parser finished with anomalies: N"

This is informational, not an error. The compiler still inserts all successfully parsed entries. Check the anomaly report to see which nodes were dropped:

```bash
cat parser_anomalies_report.md
```

If you see many anomalies for a specific CSP, the DDF file may use a non-standard structure that the compiler doesn't yet handle. Consider filing an issue with a sample file.

### "Failed to unmarshal DDF (might require namespace mapping)"

This DDF file uses custom XML namespaces that `xml.Unmarshal` can't resolve. The compiler strips common `SyncML:` prefixes automatically. If a file still fails, it may need custom namespace handling. You can manually edit the DDF file to remove namespace prefixes, or file an issue with a sample.

### "No AccessType tags found" / "No Format tag found"

These are expected for container/layout nodes in the DDF tree. The compiler correctly skips them. If actual policy nodes produce these errors, verify that the DDF file follows the standard Microsoft DDF structure.

### "INSERT ... ON CONFLICT" errors (PostgreSQL)

Ensure your PostgreSQL database has been migrated to the latest schema:

```bash
# The compiler auto-runs migrations via db.Open(), but you can verify:
psql -d latchz -c "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"
```

The latest migration version is `0003` (consumed_tokens table).

### "table policy_catalog doesn't exist" (SQLite)

Same as above — run migrations first. The `db.Open()` function auto-runs migrations, but if the database file is new or corrupted, recreate it:

```bash
rm latchz.db
./ddf-compiler -in ./ddf
```

## Updating the Catalog

Since the compiler uses upsert semantics, you can re-run it whenever Microsoft releases updated DDF files:

```bash
# Download updated DDF files
wget -r -A "*.xml" -nH -nd -P ./ddf \
  "https://example.com/updated-ddf-files/"

# Re-run — existing entries are updated, new entries are inserted
./ddf-compiler -in ./ddf
```

The `updated_at` timestamp in the database is refreshed on each upsert.

## Architecture

The compiler is implemented as a `Compiler` struct with clean separation between parsing and database operations:

```
main()
  ├── Load config (config.Load)
  ├── Open database (db.Open — auto-migrates)
  ├── Create Compiler
  ├── WalkDir → processFile()
  │     └── traverseNode() (recursive XML walk)
  │           └── compileNode() (single node → CatalogEntry)
  ├── insertCatalogEntries() (database upsert)
  ├── Write JSON catalog (optional)
  └── Write anomaly report (if anomalies > 0)
```

Key types:

| Type | Purpose |
|------|---------|
| `Compiler` | Parsing state — holds `Entries` and `Anomalies` |
| `CatalogEntry` | Parsed policy ready for database insertion |
| `MgmtTree` | Root XML element |
| `Node` | XML tree node (recursive, with `Nodes []Node`) |
| `DFProperties` | Policy metadata (access type, format, description) |