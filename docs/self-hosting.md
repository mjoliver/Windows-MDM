# Latchz MDM — Self-Hosting Guide

This guide walks through deploying Latchz MDM on **Google Cloud Run** (free tier) using **Google Workspace** for authentication and **Cloudflare** for DNS.

---

## Prerequisites

- **Domain**: `mjo.gg` (managed via Cloudflare)
- **Google Workspace** account (for OIDC login)
- **Google Cloud** account (free tier is sufficient)
- **Cloudflare** account (for DNS management)

---

## Architecture Overview

```
Windows Device
     │
     ▼ HTTPS (port 443)
enterpriseenrollment.mjo.gg  ──► Cloudflare (DNS proxy)
                                       │
                                       ▼
                              Google Cloud Run
                              (latchz binary + SQLite)
                                       │
                              Google OAuth 2.0 (OIDC)
                              (login restricted to mjo.gg)
```

> **Note**: Cloud Run handles TLS automatically. No manual cert management needed.

---

## Step 1 — Google Cloud Setup

### 1.1 Create a Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project: **latchz-mdm** (or any name)
3. Note your **Project ID**

### 1.2 Enable Required APIs

In the Cloud Console, enable:
- **Cloud Run API**
- **Artifact Registry API** (for container images)

```bash
gcloud services enable run.googleapis.com artifactregistry.googleapis.com
```

---

## Step 2 — Google OAuth 2.0 Credentials

### 2.1 Configure Consent Screen

1. Go to **APIs & Services → OAuth consent screen**
2. Select **Internal** (restricts to your Google Workspace org — `mjo.gg` only)
3. Fill in:
   - App name: `Latchz MDM`
   - User support email: your Google Workspace email
   - Authorized domain: `mjo.gg`
4. Add scopes: `email`, `profile`, `openid`
5. Save

### 2.2 Create OAuth Credentials

1. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
2. Application type: **Web application**
3. Name: `Latchz MDM`
4. Authorized redirect URIs:
   ```
   https://enterpriseenrollment.mjo.gg/auth/callback
   ```
5. Click **Create**
6. Copy the **Client ID** and **Client Secret** — you'll need these

---

## Step 3 — Configure `latchz.yaml`

Update your `latchz.yaml` with the real OIDC config:

```yaml
server:
  domain: enterpriseenrollment.mjo.gg
  listen: ":8080"                          # Cloud Run uses 8080, not 443
  enrollment_domain: mjo.gg
  master_secret: "your-strong-random-secret-here"

tls:
  mode: none                               # Cloud Run terminates TLS upstream

database:
  driver: sqlite
  dsn: /data/latchz.db                    # Persistent volume mount

auth:
  provider: oidc
  oidc:
    issuer: https://accounts.google.com
    client_id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
    client_secret: "YOUR_CLIENT_SECRET"
    allowed_domains:
      - mjo.gg                             # Restricts login to mjo.gg Google accounts
```

> ⚠️ **Security**: Never commit `client_secret` to git. Use environment variables or Google Secret Manager in production.

---

### 4.1 Production-Ready Dockerfile

We use a multi-stage Dockerfile to build both the frontend and backend, resulting in a minimal production container. (This has been created for you at [Dockerfile](file:///c:/Users/Matth/Documents/projects/mdm/Dockerfile)).

### 4.2 Automated Deployment Script

A helper script has been created at [deploy.ps1](file:///c:/Users/Matth/Documents/projects/mdm/deploy.ps1) to compile and push your code to Google Cloud Build and deploy directly to Cloud Run:

```powershell
# Deploy to Cloud Run (automatically builds source in Google Cloud Build)
.\deploy.ps1 -ProjectId "YOUR_GCP_PROJECT_ID" -Region "us-central1"
```

This automates the standard deploy commands:
```bash
# Build and push image
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/latchz

# Deploy to Cloud Run
gcloud run deploy latchz \
  --image gcr.io/YOUR_PROJECT_ID/latchz \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 1
```

> Cloud Run will give you a URL like `https://latchz-xxxx-uc.a.run.app`

---

## Step 5 — DNS Configuration (Cloudflare)

### 5.1 Map Your Domain to Cloud Run

In Cloudflare, add a CNAME record:

| Type  | Name                    | Target                          | Proxy  |
|-------|-------------------------|---------------------------------|--------|
| CNAME | `enterpriseenrollment`  | `latchz-xxxx-uc.a.run.app`      | ☁️ On  |

> Windows MDM auto-discovery looks specifically for `enterpriseenrollment.<your-domain>`.

### 5.2 Verify Domain Ownership in Cloud Run

```bash
gcloud run domain-mappings create \
  --service latchz \
  --domain enterpriseenrollment.mjo.gg \
  --region us-central1
```

Follow the instructions to add the required TXT record in Cloudflare for domain verification.

---

## Step 6 — Persistent Storage

Cloud Run is stateless by default. For SQLite persistence, use **Cloud Storage FUSE** or **Cloud SQL** (Postgres).

### Option A — Cloud SQL (Postgres) — Recommended for production

Update `latchz.yaml`:
```yaml
database:
  driver: postgres
  dsn: "host=/cloudsql/PROJECT:REGION:INSTANCE user=latchz dbname=latchz sslmode=disable"
```

### Option B — Keep SQLite + Cloud Storage mount (simpler, free tier)

Mount a Cloud Storage bucket as a volume via Cloud Run volume mounts (requires Cloud Run v2).

---

## Step 7 — Verify Enrollment

Once deployed:

1. On a Windows machine joined to `mjo.gg`, go to:
   **Settings → Accounts → Access work or school → Connect**
2. Enter an `@mjo.gg` email address
3. Windows will auto-discover `https://enterpriseenrollment.mjo.gg`
4. A browser window will open for Google sign-in
5. After login, enrollment completes and the device appears in the Latchz dashboard

---

## Local Development

To run locally:

```powershell
# Build
.\build.ps1 web
.\build.ps1 go

# Run (uses latchz.yaml in project root)
go run ./cmd/latchz serve
```

The local config uses `auth.provider: dummy` to bypass login for testing.

---

## Environment Variables

All config values can be set via env vars using the `LATCHZ_` prefix:

| Env Var                          | Config Key                    |
|----------------------------------|-------------------------------|
| `LATCHZ_SERVER_DOMAIN`           | `server.domain`               |
| `LATCHZ_SERVER_MASTER_SECRET`    | `server.master_secret`        |
| `LATCHZ_DATABASE_DSN`            | `database.dsn`                |
| `LATCHZ_AUTH_OIDC_CLIENT_ID`     | `auth.oidc.client_id`         |
| `LATCHZ_AUTH_OIDC_CLIENT_SECRET` | `auth.oidc.client_secret`     |

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Enrollment fails with `0x80192F76` | TLS cert not trusted | Ensure Cloud Run TLS is active and domain mapping is verified |
| Login redirects to wrong URL | OAuth redirect URI mismatch | Add exact URL to Google OAuth credentials |
| Device doesn't appear in dashboard | Stale browser cache | Navigate to `/devices` — don't use old device ID URLs |
| DB resets on redeploy | No persistent volume | Use Cloud SQL or Storage volume mount |
