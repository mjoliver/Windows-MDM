# Latchz MDM

> ⚠️ **DISCLAIMER: PROOF OF CONCEPT & WORK IN PROGRESS**
>
> This repository is a **Proof of Concept (POC)** and is currently **incomplete**. It is not yet ready for production use. Features may be missing, security audits have not been performed, and breaking changes will occur without notice. Use at your own risk.

Latchz is an open-source, single-binary Windows MDM (Mobile Device Management) server. It enables zero-touch enrollment and continuous configuration management of Windows 10/11 devices via Microsoft's native WSTEP and SyncML/OMA-DM protocols — no custom agent required.

## Features

- **WSTEP Zero-Touch Enrollment** — Windows devices auto-discover the server via `enterpriseenrollment.<domain>` and complete enrollment through Microsoft's standard flow, with no manual setup.
- **SyncML/OMA-DM Policy Management** — Push, retrieve, and reconcile device configuration policies using the OMA-DM protocol over HTTPS.
- **Win32 MSI & WinGet Application Deployment** — Drag-and-drop local `.msi` uploads, 1-click imports & seed refreshes from Microsoft's `winget-pkgs` catalog (native MSI/WiX manifests), or remote HTTPS URLs with pure-Go CFB metadata/SHA-256 inspection, `HTTP 206` Delivery Optimization streaming, and silent `EnterpriseDesktopAppManagement` CSP installs/uninstalls.
- **Agentless Software Inventory & Live Version Tracking** — Automatic `Win32AppInventory` + `EnterpriseDesktopAppManagement` `StructData` discovery of all installed Win32 and MSI programs on each endpoint, reconciling self-updating apps (such as Chrome `GoogleUpdate.exe` replacing `ProductCode` GUIDs) to display live per-device versions alongside catalog seeds.
- **BitLocker CSP & Recovery Key Escrow Vault** — Zero-touch `BitLocker` CSP enforcement (XTS-AES 256-bit ciphers, silent standard-user encryption) paired with an Argon2id + AES-256-GCM device-bound 48-digit recovery password vault, mTLS device escrow, and audited reveals.
- **Windows Update Rings** — Granular `Policy/Config/Update` & `Update` CSP deployment rings controlling quality/feature update deferrals, active hours, installation deadlines, grace periods, and 35-day emergency pause/resume.
- **Agentless Cloud LAPS (Ephemeral Local Admin)** — 100% agentless local administrator lifecycle management using native Windows `Accounts` + `LocalUsersAndGroups` CSPs (`S-1-5-32-544`), zero-plaintext AES-256-GCM credential vaulting, scheduled & post-reveal auto-rotation, and audited reveals.
- **Defender Antivirus & Firewall CSP Baselines** — Fleet-wide `Policy/Config/Defender` + `Firewall` (`MdmStore`) security baselines, transactional SyncML `<Atomic>` custom inbound/outbound firewall rules (`FirewallRules/{RuleKey}`), and remote Quick/Full Defender scans & signature updates (`Defender/Scan`, `Defender/UpdateSignature`).
- **Enterprise Wi-Fi, VPNv2 & Root/Intermediate CA Provisioning** — Zero-touch X.509 Root & Intermediate CA certificate trust (`RootCATrustedCertificates` CSP), WPA2/WPA3 Wi-Fi `WLANProfile` deployment with AES-256-GCM vault-encrypted passphrases (`WiFi` CSP), and transactional `<Atomic>` IKEv2 / Always-On VPN tunnels (`VPNv2` CSP).
- **Device Lockdown, USB Storage & Kiosk Controls** — Removable USB storage allow / read-only / block-all controls (`Policy/Config/Storage`), password/PIN complexity & screen inactivity timeouts (`Policy/Config/DeviceLock`), camera/Bluetooth hardware toggles, and single-app kiosk mode (`AssignedAccess` CSP).
- **Hardware & Security Posture Telemetry** — Continuous inventory of RAM, disk, BIOS, Secure Boot, BitLocker, Windows Defender AV/tamper protection, and Firewall state.
- **Instant Device Wake-Up (WNS)** — Optional Windows Push Notification Services (`wns/raw`) integration alongside automatic `DMClient` background polling.
- **Built-in PKI** — Self-hosted RSA 4096-bit Certificate Authority with encrypted key-at-rest (argon2id-derived master secret) for device certificate issuance via XCEP.
- **Policy Catalog via DDF Compiler** — Import Microsoft's Device Description Framework (DDF) XML schemas to populate a searchable catalog of available device policies.
- **OIDC + Builtin Authentication** — Support for Google Workspace, Entra ID, Okta, and other OIDC providers, plus local builtin username/password accounts.
- **Role-Based Access Control** — Granular permissions with `super_admin`, `admin`, and `user` roles.
- **React Dashboard** — Modern, glassmorphism-styled management UI embedded directly into the Go binary (zero external runtime dependencies).
- **Auto-TLS** — Native Let's Encrypt integration with automatic certificate renewal. Port 80 required for ACME HTTP-01 challenge.
- **Rate Limiting** — Configurable request rate limiting to protect endpoints.
- **SQLite + PostgreSQL** — SQLite for local development; PostgreSQL for production deployments.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Latchz Single Binary                     │
├─────────────────────────────────────────────────────────────┤
│  Go Backend (go-chi/chi v5)                                 │
│  ├── Primary TLS (:443, NoClientCert — WinHTTP safe)        │
│  │   ├── MDM Discovery (/EnterpriseEnrollment/*,            │
│  │   │                  /EnrollmentServer/*)                │
│  │   ├── XCEP Certificate Policy (/xcep, /pki/ca.pem)       │
│  │   ├── WSTEP Device Provisioning (/wstep)                 │
│  │   ├── Auth & Enrollment Broker (/auth/*)                 │
│  │   ├── Admin REST API (/api/*)                            │
│  │   ├── Embedded React SPA (/*)                            │
│  │   └── Emergency Access (/emergency)                      │
│  └── mTLS Endpoint (:8443 or SNI server.mdm_domain)         │
│      ├── OMA-DM / SyncML Handler (/omadm)                   │
│      └── WSTEP Certificate Renewal (/wstep ROBO)            │
│                                                             │
│  Auth Layer                                                 │
│  ├── OIDC (go-jose/jose4 + coreos/go-oidc)                  │
│  ├── Builtin (local username/password + AuthHost WAB flow)  │
│  ├── JWT Session + Single-Use Enrollment Tokens             │
│  └── RBAC Middleware                                        │
│                                                             │
│  PKI Subsystem                                              │
│  ├── RSA 4096-bit CA (self-signed)                          │
│  ├── Device cert signing (CN=<device_id>, client auth EKU)  │
│  └── Encrypted key-at-rest (argon2id)                       │
│                                                             │
│  Policy Engine                                              │
│  ├── DDF XML Parser (cmd/ddf-compiler)                      │
│  ├── Policy Catalog (SQLite / PostgreSQL)                   │
│  └── SyncML Replace / Get / Delete / Exec Reconciliation    │
│                                                             │
│  Database Layer                                             │
│  ├── golang-migrate (versioned migrations)                  │
│  ├── SQLite (development / single-node)                     │
│  └── PostgreSQL / libpq (production)                        │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

To run Latchz, you need:

1. **Go 1.26.2+** (to build from source)
2. **Node.js 20+** (to build the frontend, optional if using prebuilt binary)
3. A **domain name** (`mdm.example.com`) with DNS management access
4. An **Identity Provider (IdP)** via OIDC (e.g., Google Workspace, Entra ID) — or use builtin auth for testing/self-hosted setups
5. **Port 443** exposed for enrollment & dashboard, plus **port 8443** (or a separate `server.mdm_domain` hostname on 443) for mTLS OMA-DM device check-ins (and **port 80** if using Auto-TLS / Let's Encrypt)

## Quick Start

### 1. Build

```bash
make all
```

This builds the React dashboard and compiles the Go binary. The binary will be at `./latchz`.

### 2. Configure

Copy the example config and edit it to suit your environment:

```bash
cp latchz.example.yaml latchz.yaml
```

Key settings to update:
- `server.domain` — Your server's fully qualified domain name (FQDN)
- `server.enrollment_domain` — The email domain your users enroll with (e.g., `example.com`)
- `server.master_secret` — High-entropy random string (≥16 chars) that encrypts the CA key at rest
- `auth.oidc.*` — Your OIDC provider credentials (or set `auth.provider: builtin` for local auth)

### 3. Run

```bash
./latchz serve
```

Navigate to `https://<your-domain>` to access the admin dashboard.

> **Development mode:** For local testing with self-signed TLS and SQLite, the default `latchz.yaml` configuration is sufficient. Run `./latchz serve` and navigate to `https://localhost:8443` (accept the self-signed certificate warning).

## Configuration Reference

All configuration values can be set in `latchz.yaml` or overridden via environment variables using the `LATCHZ_` prefix (dots become underscores).

| Config Key | Env Var | Default | Description |
|---|---|---|---|
| `server.domain` | `LATCHZ_SERVER_DOMAIN` | — | Public FQDN of the MDM server |
| `server.listen` | `LATCHZ_SERVER_LISTEN` | `:443` / `:8443` | Primary HTTPS address (`NoClientCert` for Windows `WinHTTP` enrollment & UI) |
| `server.mtls_listen` | `LATCHZ_SERVER_MTLS_LISTEN` | `""` (`:8443` recommended) | Dedicated mTLS listener (`VerifyClientCertIfGiven`) for `/omadm` device check-ins |
| `server.mdm_domain` | `LATCHZ_SERVER_MDM_DOMAIN` | `""` | Optional SNI hostname for mTLS on `:443` instead of a second port (e.g., `mdm-mtls.example.com`) |
| `server.enrollment_domain` | `LATCHZ_SERVER_ENROLLMENT_DOMAIN` | (same as domain) | Email domain for user enrollment |
| `server.master_secret` | `LATCHZ_SERVER_MASTER_SECRET` | — | Encrypts the CA private key at rest |
| `server.emergency_token` | `LATCHZ_SERVER_EMERGENCY_TOKEN` | — | Emergency access token for dashboard lockout recovery |
| `tls.mode` | `LATCHZ_TLS_MODE` | `auto` | `auto` (Let's Encrypt), `manual`, `self-signed`, `none` |
| `tls.cache_dir` | `LATCHZ_TLS_CACHE_DIR` | `/var/lib/latchz/certs` | Let's Encrypt cert cache location |
| `database.driver` | `LATCHZ_DATABASE_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `database.dsn` | `LATCHZ_DATABASE_DSN` | `latchz.db` | Database connection string / file path |
| `auth.provider` | `LATCHZ_AUTH_PROVIDER` | `oidc` | `oidc` or `builtin` |
| `auth.jwt_secret` | `LATCHZ_AUTH_JWT_SECRET` | — | Signs dashboard session + enrollment JWTs |
| `auth.bootstrap_admin` | `LATCHZ_AUTH_BOOTSTRAP_ADMIN` | — | Email auto-granted super_admin on first login |
| `auth.oidc.issuer` | `LATCHZ_AUTH_OIDC_ISSUER` | — | OIDC discovery URL |
| `auth.oidc.client_id` | `LATCHZ_AUTH_OIDC_CLIENT_ID` | — | OIDC client ID |
| `auth.oidc.client_secret` | `LATCHZ_AUTH_OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `auth.oidc.allowed_domains` | `LATCHZ_AUTH_OIDC_ALLOWED_DOMAINS` | — | Email domains restricted for login |
| `mdm.poll_interval_minutes` | `LATCHZ_MDM_POLL_INTERVAL_MINUTES` | `15` | Background OMA-DM check-in interval in minutes (`0` disables) |
| `mdm.poll_on_login` | `LATCHZ_MDM_POLL_ON_LOGIN` | `true` | Trigger an OMA-DM check-in whenever a user logs into Windows |
| `mdm.packages_dir` | `LATCHZ_MDM_PACKAGES_DIR` | `./packages` | Local storage directory for drag-and-drop uploaded `.msi` packages |
| `mdm.wns.package_family_name` | `LATCHZ_MDM_WNS_PACKAGE_FAMILY_NAME` | `""` | Optional Microsoft Partner Center WNS Package Family Name (`DMClient` Push PFN) |
| `mdm.wns.package_sid` | `LATCHZ_MDM_WNS_PACKAGE_SID` | `""` | Optional WNS OAuth2 `client_id` (`ms-app://s-1-15-2-...`) |
| `mdm.wns.client_secret` | `LATCHZ_MDM_WNS_CLIENT_SECRET` | `""` | Optional WNS OAuth2 `client_secret` for instant `wns/raw` wake-ups |

> **Why separate `listen` and `mtls_listen` / `mdm_domain`?** Windows `DeviceEnroller.exe` uses `WinHTTP`, which aborts unauthenticated Discovery/XCEP/WSTEP requests with `0x80072f0c` (`ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED`) if the server sends a TLS `CertificateRequest` handshake message before the device has enrolled. Latchz keeps `server.listen` (`:443`) free of client-cert prompts and provisions devices to check in via `server.mtls_listen` (e.g., `:8443`) or `server.mdm_domain`.

See `latchz.example.yaml` for the complete reference with comments.

## Deployment

### Development (SQLite + Self-Signed TLS)

```yaml
server:
  domain: enterpriseenrollment.lab.local
  listen: ":443"
  mtls_listen: ":8443"
  enrollment_domain: lab.local

tls:
  mode: self-signed

database:
  driver: sqlite
  dsn: latchz.db

auth:
  provider: builtin
```

### Production (PostgreSQL + Auto-TLS)

```yaml
server:
  domain: mdm.example.com
  listen: ":443"
  mtls_listen: ":8443"
  enrollment_domain: example.com
  master_secret: "your-high-entropy-random-string"

tls:
  mode: auto
  cache_dir: /var/lib/latchz/certs

database:
  driver: postgres
  dsn: "postgres://latchz:password@localhost:5432/latchz?sslmode=require"

auth:
  provider: oidc
  jwt_secret: "your-high-entropy-32-byte-secret"
  oidc:
    issuer: https://accounts.google.com
    client_id: "your-client-id.apps.googleusercontent.com"
    client_secret: "your-client-secret"
    allowed_domains:
      - example.com
```

### Docker

A multi-stage Dockerfile is provided for containerized deployments:

```bash
# Build the Docker image
docker build -t latchz:latest .

# Run with config mounted as a volume
docker run -d \
  --name latchz \
  -p 443:443 \
  -p 8443:8443 \
  -v $(pwd)/latchz.yaml:/app/latchz.yaml:ro \
  -v latchz-data:/var/lib/latchz \
  latchz:latest
```

See [docs/self-hosting.md](docs/self-hosting.md) for a complete Google Cloud Run deployment walkthrough.

### DDF Policy Catalog

To show available configurations in the dashboard's **Policy Catalog**, you need to ingest Microsoft's Device Description Framework (DDF) XML files into the database. Latchz ships with a dedicated CLI tool for this:

```bash
# Build the DDF compiler
go build -o ddf-compiler ./cmd/ddf-compiler

# Download Microsoft DDF XML files (see docs/ddf-compiler.md)
mkdir -p ddf
# ... place DDF XML files in ddf/ ...

# Run the compiler
./ddf-compiler -config latchz.yaml -in ./ddf -out catalog.json -report anomalies.md
```

This parses all `.xml` files in the input directory, extracts policy definitions, and upserts them into the `policy_catalog` table. See [docs/ddf-compiler.md](docs/ddf-compiler.md) for a complete guide.

### DNS Configuration

For Windows devices to automatically discover your MDM server using just an email address (`user@example.com`), create the following DNS record at your domain (`example.com`):

```
Type:     CNAME
Name:     enterpriseenrollment
Value:    mdm.example.com
```

Windows also looks for `enterpriseregistration` — you may want to add that as well:

```
Type:     CNAME
Name:     enterpriseregistration
Value:    mdm.example.com
```

After the DNS records propagate, a Windows 10/11 device joined to `example.com` will auto-discover the Latchz server when the user enters their email in **Settings → Accounts → Access work or school → Connect**.

## Admin Dashboard

The embedded React dashboard provides the following pages:

| Page | Description |
|------|-------------|
| **Overview** | System health, device counts, compliance summary |
| **Devices** | List of all enrolled devices with status |
| **Device Detail** | Per-device hardware & security posture, full Win32/MSI software inventory, BitLocker vault, Cloud LAPS admin credentials, Update Ring status, WNS wake-up, remote actions |
| **Groups** | Device groups for bulk policy, app, BitLocker, Update Ring, and LAPS assignment |
| **Compliance** | Fleet security posture, BitLocker CSP policy configuration, and Cloud LAPS policy settings |
| **Applications** | Win32 `.msi` catalog (drag-and-drop local hosting, 1-click WinGet MSI import & seed update check, HTTPS URLs), live endpoint version reconciliation & group/device deployment |
| **Update Rings** | Windows Update for Business rings (deferrals, active hours, deadlines, 35-day pause/resume) |
| **Profiles** | Configuration profiles (policies) created for devices |
| **Profile Detail** | Profile settings, catalog browsing, device targeting |
| **Users & Roles** | RBAC user management (`super_admin`, `admin`, `user`) |
| **Audit Log** | Searchable administrative & enrollment security audit trail |
| **Login** | OIDC or builtin authentication |

### Emergency Access

If you're locked out of the dashboard, hit:

```
https://<domain>/emergency?token=<server.emergency_token>
```

Rotate the `server.emergency_token` immediately after use.

### Admin CLI

Promote users to admin roles from the command line:

```bash
# Promote a user to admin
./latchz admin -email user@example.com

# Promote to super_admin with a builtin password
./latchz admin -email user@example.com -role super_admin -password "secure-password"
```

## Development

### Backend Development

```bash
# Run the Go server (auto-reload not built-in; use air or similar)
make dev
# or
go run ./cmd/latchz serve
```

### Frontend Development (with Hot Module Replacement)

```bash
# Start the Go API server (separate terminal)
make dev

# Start the Vite dev server
cd web
npm install
npm run dev
```

Then open the URL Vite provides (`http://localhost:5173`). API requests are proxied to the Go backend automatically.

### Testing

```bash
# Run all Go tests
make test

# Run with race detector
make test-race

# Run with coverage report
make cover
```

### Static Checks

```bash
# Go vet
make vet

# Go fmt check (fails if any file needs formatting)
make fmt-check
```

### Building

```bash
make all          # Build web + Go binary
make web          # Build React dashboard only
make go           # Build Go binary only
make clean        # Remove build artifacts
```

## Project Structure

```
.
├── cmd/
│   ├── latchz/              # Main server binary (serve, admin, version commands)
│   └── ddf-compiler/        # DDF XML parser → policy catalog compiler
├── docs/
│   ├── architecture.md      # System architecture, protocol flows, and state machines
│   ├── ddf-compiler.md      # Microsoft DDF policy catalog ingestion guide
│   ├── reverse-proxy.md     # Nginx / Caddy / Traefik reverse-proxy & mTLS setup
│   └── self-hosting.md      # Google Cloud Run & self-hosting walkthrough
├── internal/
│   ├── api/                 # REST API handlers (apps, winget, bitlocker, laps, updates, catalog, compliance, devices, groups, profiles, posture, users, audit)
│   ├── auth/                # OIDC + builtin auth, JWT token management
│   ├── config/              # YAML config loading with Viper
│   ├── db/                  # Database layer + versioned migrations (SQLite + PostgreSQL)
│   ├── devauth/             # Device authentication verification
│   ├── enrollment/          # WSTEP enrollment + XCEP certificate issuance + auto-discovery
│   ├── mdm/                 # OMA-DM/SyncML protocol handler + BitLocker, Update, Accounts/LAPS & MSI commands
│   ├── msi/                 # Pure-Go MS-CFB (.msi) binary inspector & SSRF-hardened client
│   ├── pki/                 # RSA 4096-bit CA + certificate issuance
│   ├── policy/              # ADMX policy resolution + BitLocker & Update Ring reconciliation
│   ├── server/              # HTTP server, middleware, TLS, embedded web assets
│   ├── vault/               # Argon2id + AES-256-GCM device-bound secret vault (BitLocker & Cloud LAPS)
│   ├── winget/              # Agentless Microsoft winget-pkgs YAML manifest resolver & MSI catalog search
│   └── wns/                 # Windows Push Notification Services (WNS) OAuth2 + wns/raw wake-up client
├── web/                     # React + TypeScript frontend (Vite)
│   ├── src/
│   │   ├── components/      # Shared UI components (Badge, Layout)
│   │   ├── pages/           # Dashboard pages
│   │   └── api.ts           # API client
│   └── package.json
├── Dockerfile               # Multi-stage Docker build
├── Makefile                 # Build targets (web, go, test, dev)
├── latchz.example.yaml      # Full configuration reference
└── build.ps1 / deploy.ps1   # PowerShell build/deploy scripts
```

## License

This project is open source.