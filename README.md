# Latchz MDM

> ⚠️ **DISCLAIMER: PROOF OF CONCEPT & WORK IN PROGRESS**
>
> This repository is a **Proof of Concept (POC)** and is currently **incomplete**. It is not yet ready for production use. Features may be missing, security audits have not been performed, and breaking changes will occur without notice. Use at your own risk.

Latchz is an open-source, single-binary Windows MDM (Mobile Device Management) server. It enables zero-touch enrollment and continuous configuration management of Windows 10/11 devices via Microsoft's native WSTEP and SyncML/OMA-DM protocols — no custom agent required.

## Features

- **WSTEP Zero-Touch Enrollment** — Windows devices auto-discover the server via `enterpriseenrollment.<domain>` and complete enrollment through Microsoft's standard flow, with no manual setup.
- **SyncML/OMA-DM Policy Management** — Push, retrieve, and reconcile device configuration policies using the OMA-DM protocol over HTTPS.
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
┌─────────────────────────────────────────────────────┐
│                   Latchz Single Binary               │
├─────────────────────────────────────────────────────┤
│  Go Backend (go-chi/chi v5)                         │
│  ├── WSTEP Enrollment Handler (/wstep)              │
│  ├── OMA-DM / SyncML Handler (/mdm)                 │
│  ├── XCEP Certificate Enrollment (/msce)            │
│  ├── REST API (/api/v1/*)                           │
│  ├── Auth Dashboard (/auth/*)                       │
│  ├── Embedded React SPA (/*)                        │
│  └── Emergency Access (/emergency)                  │
│                                                     │
│  Auth Layer                                         │
│  ├── OIDC (go-jose/jose4 + coreos/go-oidc)          │
│  ├── Builtin (local username/password)              │
│  ├── JWT Session + Enrollment Tokens                │
│  └── RBAC Middleware                                │
│                                                     │
│  PKI Subsystem                                      │
│  ├── RSA 4096-bit CA (self-signed)                  │
│  ├── Device cert signing (XCEP)                     │
│  └── Encrypted key-at-rest (argon2id)               │
│                                                     │
│  Policy Engine                                      │
│  ├── DDF XML Parser (cmd/ddf-compiler)              │
│  ├── Policy Catalog (SQLite / PostgreSQL)           │
│  └── ADMX Policy Resolution                         │
│                                                     │
│  Database Layer                                     │
│  ├── golang-migrate (versioned migrations)          │
│  ├── SQLite (development)                           │
│  └── PostgreSQL / libpq (production)                │
└─────────────────────────────────────────────────────┘
```

## Requirements

To run Latchz, you need:

1. **Go 1.26.2+** (to build from source)
2. **Node.js 20+** (to build the frontend, optional if using prebuilt binary)
3. A **domain name** (`mdm.example.com`) with DNS management access
4. An **Identity Provider (IdP)** via OIDC (e.g., Google Workspace, Entra ID) — or use builtin auth for testing
5. **Port 443** exposed (and **port 80** if using Auto-TLS / Let's Encrypt)

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
| `server.listen` | `LATCHZ_SERVER_LISTEN` | `:443` / `:8443` | Network address to bind |
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

See `latchz.example.yaml` for the complete reference with comments.

## Deployment

### Development (SQLite + Self-Signed TLS)

```yaml
server:
  domain: localhost
  listen: ":8443"
  enrollment_domain: localhost

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
| **Device Detail** | Per-device info, policy assignments, compliance history |
| **Groups** | Device groups for bulk policy assignment |
| **Compliance** | Device compliance status and violations |
| **Profiles** | Configuration profiles (policies) created for devices |
| **Profile Detail** | Profile settings, catalog browsing, device targeting |
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
│   └── self-hosting.md      # Google Cloud Run deployment guide
├── internal/
│   ├── api/                 # REST API handlers (catalog, compliance, devices, groups, profiles)
│   ├── auth/                # OIDC + builtin auth, JWT token management
│   ├── config/              # YAML config loading with Viper
│   ├── db/                  # Database layer + versioned migrations (SQLite + PostgreSQL)
│   ├── devauth/             # Device authentication verification
│   ├── enrollment/          # WSTEP enrollment + XCEP certificate issuance + auto-discovery
│   ├── mdm/                 # OMA-DM/SyncML protocol handler + device commands
│   ├── pki/                 # RSA 4096-bit CA + certificate issuance
│   ├── policy/              # ADMX policy resolution + DDF catalog integration
│   └── server/              # HTTP server, middleware, TLS, embedded web assets
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