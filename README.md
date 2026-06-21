# Latchz MDM

> ⚠️ **DISCLAIMER: PROOF OF CONCEPT & WORK IN PROGRESS**
> 
> This repository is a **Proof of Concept (POC)** and is currently **incomplete**. It is not yet ready for production use. Features may be missing, security audits have not been performed, and breaking changes will occur without notice. Use at your own risk.

Latchz is an open-source, single-binary Windows MDM (Mobile Device Management) server. It enables zero-touch enrollment and continuous configuration management of Windows 10/11 devices via the native OMA-DM protocol.

## Features

- **Native Windows Protocol Support**: Full MS-MDE2 enrollment and OMA-DM/SyncML policy management. No custom agent required.
- **Embedded React Dashboard**: Modern, glassmorphism-styled UI compiled and embedded directly into the Go binary.
- **Auto-TLS**: Native Let's Encrypt integration for painless production deployments.
- **Zero-touch Deployments**: Uses Microsoft's standard automatic enrollment flow (e.g. `enterpriseenrollment.yourdomain.com`).
- **Flexible Database**: Supports SQLite for testing and PostgreSQL for production.
- **Single Binary**: No complex dependencies outside of your chosen database.

## Requirements

To run Latchz in production, you need:
1. A server with port 443 (and 80 if using Auto-TLS) exposed.
2. A domain name (`mdm.example.com`).
3. An Identity Provider (IdP) via OIDC (e.g., Google Workspace, Entra ID) to authenticate to the dashboard.
4. Microsoft DDF (Device Description Framework) schemas imported into the database to populate the policy catalog.

## Quick Start (Development)

Build the dashboard and the server:
```bash
make all
```

Create a local config file `latchz.yaml` (see `latchz.example.yaml` for reference). For local development, `self-signed` TLS and `sqlite` are sufficient.

Run the server:
```bash
./latchz serve
```
Navigate to `https://localhost:8443` (ignoring the self-signed warning) to view the dashboard.

## Deployment (Production)

### Configuration

Copy `latchz.example.yaml` to `/etc/latchz/latchz.yaml` (or pass it via env vars using the `LATCHZ_` prefix). Configure the following:
- `server.domain`: The exact Fully Qualified Domain Name (FQDN) that handles your requests.
- `server.listen`: Typically `":443"`.
- `tls.mode`: `auto` (to use Let's Encrypt). Ensure port 80 is also open.
- `database`: Highly recommended to use `postgres`.

### The DDF Ingestion Pipeline
To show available configurations in the dashboard's "Policy Catalog", you need to ingest the Microsoft DDF files. 
*(Note: A python ingestion script is typically used here to parse the `docs.microsoft.com` CSP definitions into the `policy_catalog` table. Ensure `data_type`, `allowed_values`, and `oma_uri` references are mapped properly).*

### DNS Records

For Windows devices to automatically discover your server using just an email address (`user@example.com`), create the following CNAME record:

```
Type: CNAME
Name: enterpriseenrollment.example.com
Target: mdm.example.com
```

### Running

```bash
./latchz serve
```

## Developing the Dashboard

If you want to edit the React frontend with Hot Module Replacement (HMR):
1. Start the Go API server: `make dev` (keeps it running on `:8443`).
2. Run the Vite development server:
   ```bash
   cd web
   npm run dev
   ```
3. Open the URL Vite provides (`http://localhost:5173`). API requests will be transparently proxied to the Go backend.
