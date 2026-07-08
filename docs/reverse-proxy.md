# Latchz MDM — Running Behind a Reverse Proxy

This document explains how to deploy Latchz MDM behind a reverse proxy that terminates TLS. It covers configuration, endpoint classification, mTLS client certificate forwarding, and provides example configurations for popular reverse proxies.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Reverse Proxy (TLS Termination)                 │
│                                                                     │
│  Client HTTPS → Proxy handles TLS/443                               │
│  │                                                                  │
│  ├─ Enrollment endpoints  →  Forward as plain HTTP (no auth)        │
│  ├─ Auth endpoints        →  Forward as plain HTTP (optional auth)  │
│  ├─ Dashboard /api/*      →  Forward as plain HTTP (require auth)   │
│  └─ /omadm (mTLS)         →  Forward cert in header + plain HTTP    │
│       │                                                             │
│       ▼                                                             │
│  Latchz MDM (tls.mode: none, plain HTTP on port 8080)               │
└─────────────────────────────────────────────────────────────────────┘
```

**Key concept:** When the reverse proxy terminates TLS, Latchz runs in `tls.mode: none` (plain HTTP). The proxy is responsible for:
- TLS termination and encryption
- For mTLS endpoints, extracting the client certificate and forwarding it via a trusted header
- Optional: Enforcing authentication policies per-route

---

## Latchz Configuration

### Minimal Configuration for Reverse Proxy

```yaml
# latchz.yaml
server:
  listen: ":8080"                    # Plain HTTP, facing the reverse proxy only
  domain: mdm.example.com            # Public FQDN (used in enrollment URLs)
  master_secret: "your-strong-random-secret-here"
  trusted_proxy: true                # Trust X-Forwarded-For for rate limiting

tls:
  mode: none                         # TLS terminated by reverse proxy
  trust_proxy_client_cert: true      # Accept client cert from proxy header
  client_cert_header: "X-Forwarded-Client-Cert"  # Header carrying PEM cert

database:
  driver: sqlite
  dsn: ./latchz.db

auth:
  provider: oidc
  jwt_secret: "your-stable-jwt-secret-at-least-32-chars"
  bootstrap_admin: admin@example.com
  oidc:
    issuer: https://accounts.google.com
    client_id: "YOUR_CLIENT_ID"
    client_secret: "YOUR_CLIENT_SECRET"
    allowed_domains:
      - example.com
```

### Environment Variable Equivalents

| Config Key | Environment Variable |
|---|---|
| `server.listen` | `LATCHZ_SERVER_LISTEN` (or `PORT`) |
| `server.domain` | `LATCHZ_SERVER_DOMAIN` |
| `server.trusted_proxy` | `LATCHZ_SERVER_TRUSTED_PROXY` |
| `server.master_secret` | `LATCHZ_SERVER_MASTER_SECRET` |
| `tls.mode` | `LATCHZ_TLS_MODE` |
| `tls.trust_proxy_client_cert` | `LATCHZ_TLS_TRUST_PROXY_CLIENT_CERT` |
| `tls.client_cert_header` | `LATCHZ_TLS_CLIENT_CERT_HEADER` |
| `auth.jwt_secret` | `LATCHZ_AUTH_JWT_SECRET` |

### Critical Settings Explained

| Setting | Purpose | Default |
|---|---|---|
| `tls.mode: none` | Disables TLS in Latchz; expects proxy to terminate | `self-signed` |
| `server.trusted_proxy: true` | Trust `X-Forwarded-For` for real client IP (rate limiting, logging) | `false` |
| `tls.trust_proxy_client_cert: true` | Enable reading device client cert from proxy header | `false` |
| `tls.client_cert_header` | Header name carrying URL-encoded PEM client cert | `X-Forwarded-Client-Cert` |

**Important:** `tls.trust_proxy_client_cert` MUST only be enabled when the reverse proxy:
1. Strips any client-supplied value of `client_cert_header`
2. Sets the header itself based on the actual TLS client certificate

This prevents a malicious client from spoofing a device identity by injecting a fake certificate header.

---

## Endpoint Classification

Understanding which endpoints require which type of access is critical for configuring the reverse proxy correctly.

### Tier 1: Public Endpoints (No Authentication Required)

These endpoints are part of the Windows device enrollment discovery flow. Devices reach these endpoints before they have any certificates or tokens.

| Method | Path | Purpose | Notes |
|---|---|---|---|
| `GET/POST` | `/EnterpriseEnrollment/Enrollment.svc` | MDM discovery (MS-MDE2) | Windows auto-discovery entry point |
| `GET/POST` | `/EnrollmentServer/Discovery.svc` | Legacy MDM discovery | Alternate autodiscovery path |
| `POST` | `/xcep` | Certificate policy enrollment (MS-XCEP) | Returns CA cert for device trust |
| `GET` | `/pki/ca.pem` | Root CA certificate download | Admin utility endpoint |
| `GET` | `/api/config` | Public configuration | Returns `support_url` only |

**Proxy Configuration:** These paths should have **no authentication** and **no mTLS requirement**. They must be freely accessible to Windows devices on the network.

### Tier 2: Authentication Flow Endpoints (Rate-Limited)

These endpoints handle user login for both the admin dashboard and the device enrollment authentication flow. They are rate-limited by Latchz (20 requests/minute).

| Method | Path | Purpose | Notes |
|---|---|---|---|
| `GET` | `/auth/login` | Initiate login (OIDC redirect or builtin form) | Opens browser for user auth |
| `GET` | `/auth/callback` | OAuth2 callback | Issues session + enrollment tokens |
| `POST` | `/auth/logout` | Clear session cookie | Logout endpoint |
| `POST` | `/wstep` | Device certificate enrollment (MS-WSTEP) | Requires enrollment token from auth flow |

**Proxy Configuration:** These paths can optionally have authentication at the proxy level, but it is generally recommended to **leave proxy-level auth disabled** because:
- The `/auth/login` and `/auth/callback` endpoints are reached during Windows enrollment when the user authenticates via a browser popup
- The `/wstep` endpoint requires an enrollment token (obtained after successful auth), not mTLS
- Adding proxy-level auth here would break the enrollment flow

### Tier 3: mTLS-Required Endpoints (Device Certificate Authentication)

These endpoints require a valid device client certificate. The certificate must have been issued by the Latchz CA during the enrollment process (via `/wstep`).

| Method | Path | Purpose | Notes |
|---|---|---|---|
| `POST` | `/omadm` | OMA-DM device check-in | **Requires mTLS client certificate** |

**Proxy Configuration:** This is the most critical endpoint for reverse proxy setup:
- The proxy MUST perform mTLS verification (require and validate client cert against the Latchz CA)
- The proxy MUST forward the client certificate to Latchz via the configured header
- Without proper mTLS forwarding, enrolled devices cannot check in and receive commands

### Tier 4: Session-Authenticated Endpoints (Dashboard API)

These endpoints require a valid user session (authenticated via OIDC or built-in auth). They serve the admin dashboard.

| Method | Path | Purpose | Admin Required? |
|---|---|---|---|
| `GET` | `/api/me` | Current user info | No |
| `GET` | `/api/devices` | List devices | No |
| `GET` | `/api/devices/{id}` | Get device details | No |
| `DELETE` | `/api/devices/{id}` | Unenroll device | **Yes** |
| `POST` | `/api/devices/{id}/lock` | Lock device | **Yes** |
| `POST` | `/api/devices/{id}/wipe` | Wipe device | **Yes** |
| `POST` | `/api/devices/{id}/sync` | Sync device | **Yes** |
| `GET` | `/api/devices/{id}/commands` | Device command history | No |
| `GET` | `/api/catalog/csps` | List CSPs | No |
| `GET` | `/api/catalog` | List catalog | No |
| `GET` | `/api/catalog/{id}` | Get catalog entry | No |
| `GET` | `/api/profiles` | List profiles | No |
| `POST` | `/api/profiles` | Create profile | **Yes** |
| `GET` | `/api/profiles/{id}` | Get profile | No |
| `PUT` | `/api/profiles/{id}` | Update profile | **Yes** |
| `DELETE` | `/api/profiles/{id}` | Delete profile | **Yes** |
| `GET` | `/api/groups` | List groups | No |
| `POST` | `/api/groups` | Create group | **Yes** |
| `PUT` | `/api/groups/{id}` | Update group | **Yes** |
| `DELETE` | `/api/groups/{id}` | Delete group | **Yes** |
| `PUT` | `/api/groups/{id}/devices` | Assign device to group | **Yes** |
| `PUT` | `/api/groups/{id}/profiles` | Assign profile to group | **Yes** |
| `GET` | `/api/compliance` | Fleet compliance | No |
| `GET` | `/api/compliance/{deviceId}` | Device compliance | No |
| `GET` | `/api/system/health` | Health check | No |
| `GET` | `/emergency?token=...` | Emergency admin access | Token-based, rate-limited |
| `GET` | `/*` | Dashboard SPA | Catch-all for React app |

**Proxy Configuration:** These paths SHOULD be protected by proxy-level authentication in production. The dashboard handles its own session-based auth, but adding an additional layer at the proxy (e.g., OIDC auth, basic auth) provides defense in depth.

---

## Quick Reference: Auth Requirements Summary

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Path Pattern                      │ Proxy Auth │ Proxy mTLS              │
├──────────────────────────────────────────────────────────────────────────┤
│ /EnterpriseEnrollment/*           │ DISABLED   │ DISABLED                │
│ /EnrollmentServer/*               │ DISABLED   │ DISABLED                │
│ /xcep                             │ DISABLED   │ DISABLED                │
│ /pki/ca.pem                       │ DISABLED   │ DISABLED                │
│ /api/config                       │ DISABLED   │ DISABLED                │
│ /auth/*                           │ DISABLED   │ DISABLED                │
│ /wstep                            │ DISABLED   │ DISABLED                │
│ /omadm                            │ OPTIONAL   │ REQUIRED + FORWARD CERT │
│ /api/*                            │ RECOMMENDED│ DISABLED                │
│ /emergency                        │ OPTIONAL   │ DISABLED                │
│ /* (dashboard)                    │ RECOMMENDED│ DISABLED                │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Reverse Proxy Configuration Examples

### Nginx

```nginx
# ── SSL/TLS certificates ──────────────────────────────────────────────
# Server certificate (for TLS termination)
ssl_certificate         /etc/ssl/certs/mdm.example.com/fullchain.pem;
ssl_certificate_key     /etc/ssl/private/mdm.example.com/privkey.pem;

# Latchz Root CA (for mTLS client verification on /omadm)
# Extract from Latchz: curl -sk https://mdm.example.com/pki/ca.pem
ssl_client_certificate  /etc/ssl/certs/latchz-ca.pem;
ssl_verify_client       optional;  # optional = request but don't require globally

# ── TLS hardening ─────────────────────────────────────────────────────
ssl_protocols           TLSv1.2 TLSv1.3;
ssl_ciphers             HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;

# ── Upstream ──────────────────────────────────────────────────────────
upstream latchz {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name mdm.example.com;

    # ── Security headers ──────────────────────────────────────────────
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # ── Forward real client IP ────────────────────────────────────────
    proxy_set_header X-Real-IP        $remote_addr;
    proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host             $host;

    # ── Forward client certificate (for /omadm) ──────────────────────
    # $ssl_client_escaped_cert contains the PEM certificate, URL-encoded
    # This is CRITICAL for /omadm to authenticate enrolled devices
    proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;

    # ── Health check (no auth, no mTLS) ──────────────────────────────
    location = /api/system/health {
        proxy_pass http://latchz;
    }

    # ── Enrollment discovery (no auth, no mTLS) ─────────────────────
    location ~ ^/(EnterpriseEnrollment|EnrollmentServer)/ {
        proxy_pass http://latchz;
    }

    # ── XCEP certificate policy (no auth, no mTLS) ──────────────────
    location = /xcep {
        proxy_pass http://latchz;
    }

    # ── CA download (no auth, no mTLS) ──────────────────────────────
    location = /pki/ca.pem {
        proxy_pass http://latchz;
    }

    # ── Public API config (no auth) ─────────────────────────────────
    location = /api/config {
        proxy_pass http://latchz;
    }

    # ── Auth flow endpoints (no proxy-level auth) ───────────────────
    location ~ ^/auth/ {
        proxy_pass http://latchz;
    }

    # ── WSTEP certificate enrollment (no proxy-level auth) ──────────
    location = /wstep {
        proxy_pass http://latchz;
    }

    # ── OMA-DM device check-in (REQUIRES mTLS) ──────────────────────
    # Reject requests without a valid client certificate
    location = /omadm {
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        proxy_pass http://latchz;
    }

    # ── Dashboard API (optional: add auth here) ─────────────────────
    # Example: Uncomment the following for basic auth on /api/*
    # location /api/ {
    #     auth_basic "Latchz Admin";
    #     auth_basic_user_file /etc/nginx/.htpasswd;
    #     proxy_pass http://latchz;
    # }

    location /api/ {
        proxy_pass http://latchz;
    }

    # ── Emergency access ────────────────────────────────────────────
    location = /emergency {
        proxy_pass http://latchz;
    }

    # ── Dashboard SPA (optional: add auth here) ─────────────────────
    location / {
        proxy_pass http://latchz;
    }
}

# ── HTTP → HTTPS redirect ─────────────────────────────────────────────
server {
    listen 80;
    server_name mdm.example.com;
    return 301 https://$host$request_uri;
}
```

#### Nginx: Obtaining the Latchz CA Certificate

The mTLS verification in Nginx requires the Latchz Root CA certificate. Retrieve it after initial Latchz setup:

```bash
# Download the CA certificate from your Latchz instance
curl -sk https://mdm.example.com/pki/ca.pem -o /etc/ssl/certs/latchz-ca.pem

# Restart nginx to load the new CA
systemctl restart nginx
```

---

### Caddy (Caddyfile)

```caddy
mdm.example.com {
    # ── TLS configuration ────────────────────────────────────────────
    tls {
        client_auth {
            mode request  # Request but don't require globally
            trusted_ca_peer internal_ca
        }
    }

    # ── Global headers ──────────────────────────────────────────────
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }

    # ── Forward client cert info ────────────────────────────────────
    # Caddy's {tls_client_certificate} contains the raw PEM
    # We use a header directive per route below

    # ── OMA-DM (REQUIRES valid client cert) ─────────────────────────
    route /omadm {
        # Require valid client certificate
        @no_client_cert not expression {tls_client_certificate}
        reject @no_client_cert

        header_up X-Forwarded-Client-Cert {tls_client_certificate}
        reverse_proxy 127.0.0.1:8080
    }

    # ── Enrollment endpoints (no auth, no mTLS) ────────────────────
    route /EnterpriseEnrollment/* {
        reverse_proxy 127.0.0.1:8080
    }

    route /EnrollmentServer/* {
        reverse_proxy 127.0.0.1:8080
    }

    route /xcep {
        reverse_proxy 127.0.0.1:8080
    }

    route /pki/ca.pem {
        reverse_proxy 127.0.0.1:8080
    }

    # ── Auth flow (no proxy-level auth) ────────────────────────────
    route /auth/* {
        reverse_proxy 127.0.0.1:8080
    }

    route /wstep {
        reverse_proxy 127.0.0.1:8080
    }

    # ── API & Dashboard ────────────────────────────────────────────
    route /api/* {
        reverse_proxy 127.0.0.1:8080
    }

    route /emergency {
        reverse_proxy 127.0.0.1:8080
    }

    # ── Dashboard SPA ──────────────────────────────────────────────
    route /* {
        reverse_proxy 127.0.0.1:8080
    }
}
```

---

### Traefik (YAML)

```yaml
http:
  routers:
    # ── OMA-DM (mTLS required) ─────────────────────────────────────
    omadm:
      rule: "Host(`mdm.example.com`) && Path(`/omadm`)"
      entryPoints:
        - websecure
      middlewares:
        - forward-client-cert
        - require-client-cert
      service: latchz
      tls:
        passthrough: false

    # ── Enrollment (public) ────────────────────────────────────────
    enrollment:
      rule: "Host(`mdm.example.com`) && (PathPrefix(`/EnterpriseEnrollment`) || PathPrefix(`/EnrollmentServer`))"
      entryPoints:
        - websecure
      service: latchz

    xcep:
      rule: "Host(`mdm.example.com`) && Path(`/xcep`)"
      entryPoints:
        - websecure
      service: latchz

    ca-download:
      rule: "Host(`mdm.example.com`) && Path(`/pki/ca.pem`)"
      entryPoints:
        - websecure
      service: latchz

    # ── Auth flow ──────────────────────────────────────────────────
    auth-flow:
      rule: "Host(`mdm.example.com`) && PathPrefix(`/auth`)"
      entryPoints:
        - websecure
      service: latchz

    wstep:
      rule: "Host(`mdm.example.com`) && Path(`/wstep`)"
      entryPoints:
        - websecure
      service: latchz

    # ── Dashboard API ──────────────────────────────────────────────
    api:
      rule: "Host(`mdm.example.com`) && PathPrefix(`/api`)"
      entryPoints:
        - websecure
      service: latchz

    dashboard:
      rule: "Host(`mdm.example.com`)"
      entryPoints:
        - websecure
      service: latchz

  middlewares:
    # Forward client certificate as PEM in header
    forward-client-cert:
      forwardAuth:
        address: "https://127.0.0.1:8080"  # Not used; see headers below

    # Require valid client certificate (for /omadm)
    require-client-cert:
      plugin:
        # Note: Traefik's native mTLS support works best with TLS passthrough
        # For reverse proxy mode, use the entrypoint-level client auth

  services:
    latchz:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"

tls:
  stores:
    default:
      defaultCertificate:
        certFile: /etc/ssl/certs/mdm.example.com/fullchain.pem
        keyFile: /etc/ssl/private/mdm.example.com/privkey.pem
  options:
    default:
      minVersion: "TLS1.2"
      sniStrict: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: default
        # Client certificate verification at entrypoint level
        # For per-route mTLS, use routers with tls.passthrough or plugins
```

**Note:** Traefik's mTLS support is more naturally expressed with TLS passthrough or entrypoint-level configuration. For the cleanest mTLS setup with Traefik, consider using entrypoint-level `tls.clientAuth` with a trusted CA, then forwarding the certificate via headers.

---

## mTLS Certificate Forwarding Details

### How It Works

When a device connects to `/omadm`, the flow is:

```
1. Device presents its client certificate during TLS handshake with the proxy
2. Proxy validates the certificate against the Latchz Root CA
3. Proxy extracts the certificate in PEM format
4. Proxy forwards the PEM to Latchz in the X-Forwarded-Client-Cert header
5. Latchz's devauth module parses the PEM, verifies against its CA pool,
   computes the SHA-1 thumbprint, and looks up the device in the database
```

### Certificate Format

The `devauth.ClientCert()` function in Latchz accepts the forwarded certificate in two formats:

1. **Raw PEM:**
   ```
   -----BEGIN CERTIFICATE-----
   MIIDXTCCAkWgAwIBAgIJ...
   -----END CERTIFICATE-----
   ```

2. **URL-encoded PEM** (e.g., nginx `$ssl_client_escaped_cert`):
   ```
   %2D%2D%2D%2D%2DBEGIN%20CERTIFICATE%2D%2D%2D%2D%0AMIIDXTCCAkWgAwIBAgIJ...
   ```

The parser tries raw PEM first, then falls back to URL decoding. This ensures compatibility with both nginx and other proxy configurations.

### Security Warning

**NEVER** allow clients to set the `X-Forwarded-Client-Cert` header. The reverse proxy must:
1. Strip this header from incoming client requests
2. Set it only based on the actual TLS client certificate

In Nginx, this is handled automatically because `proxy_set_header` overwrites any client-supplied value. In other proxies, you may need explicit header stripping.

---

## Code Changes Assessment

### No Code Changes Required

The Latchz codebase already supports running behind a reverse proxy out of the box. The following existing mechanisms handle proxy deployment:

1. **`tls.mode: none`** — Runs the server in plain HTTP mode, designed for proxy/cloud platform deployment
2. **`behindProxy()` detection** — Automatically enables `X-Forwarded-For` trust when `tls.mode=none` or `server.trusted_proxy=true`
3. **`devauth.ClientCert()`** — Reads client certificates from the proxy header when `tls.trust_proxy_client_cert=true`
4. **Certificate format handling** — Supports both raw PEM and URL-encoded PEM from the proxy

### Considerations for Future Improvements

While no changes are strictly required, the following improvements could enhance the reverse proxy experience:

1. **HSTS Header in Proxy Mode:** When `tls.mode=none`, Latchz still sets `Strict-Transport-Security` in the `securityHeaders` middleware. The reverse proxy should override or remove this header if it manages HSTS itself, to avoid duplicate or conflicting values.

2. **Multiple Certificate Header Formats:** Currently only PEM is supported via the proxy header. Some proxies (e.g., AWS ALB, GCP) forward certificates in different formats (JWT, DER). Adding support for these formats would broaden proxy compatibility.

3. **Proxy Protocol Support:** Adding HAProxy PROXY protocol support would provide real client IP without relying on headers.

---

## Deployment Checklist

- [ ] Set `tls.mode: none` in Latchz configuration
- [ ] Set `server.trusted_proxy: true` (or rely on automatic detection via `tls.mode=none`)
- [ ] Set `tls.trust_proxy_client_cert: true`
- [ ] Configure `tls.client_cert_header` to match your proxy's header name
- [ ] Configure reverse proxy to terminate TLS on port 443
- [ ] Configure reverse proxy to forward to Latchz on the configured port (default 8080)
- [ ] Configure reverse proxy to forward `X-Forwarded-For` and `Host` headers
- [ ] For `/omadm`: Configure reverse proxy to require and validate client certificates
- [ ] For `/omadm`: Configure reverse proxy to forward client cert PEM to Latchz
- [ ] Strip `X-Forwarded-Client-Cert` from client requests (proxy must set it alone)
- [ ] Test enrollment flow (discovery → XCEP → WSTEP)
- [ ] Test device check-in (`/omadm` with valid device certificate)
- [ ] Test dashboard access and API endpoints

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Devices can't enroll | Discovery endpoint blocked by proxy auth | Ensure `/EnterpriseEnrollment/*` has no proxy-level auth |
| Enrollment fails at WSTEP | OAuth callback blocked | Ensure `/auth/*` and `/wstep` have no proxy-level auth |
| Devices can't check in | mTLS not configured on `/omadm` | Configure proxy to require client cert on `/omadm` |
| `/omadm` returns 401 | Client cert not forwarded | Verify `X-Forwarded-Client-Cert` header is set by proxy |
| `/omadm` returns 401 | Wrong header format | Ensure header contains PEM (raw or URL-encoded) |
| Rate limiting triggers incorrectly | `X-Forwarded-For` not trusted | Set `server.trusted_proxy: true` |
| All requests show same IP | Proxy not forwarding real IP | Configure proxy to set `X-Forwarded-For` header |
| HSTS conflicts | Both proxy and Latchz set HSTS | Configure proxy to override `Strict-Transport-Security` |
| Certificate not recognized | Wrong CA in proxy | Ensure proxy uses the Latchz Root CA (`/pki/ca.pem`) for mTLS verification |

---

## Enrollment Flow Reference

Understanding the full enrollment flow helps with proxy configuration:

```
Phase 1: Discovery (no auth, no cert)
  Device → GET/POST /EnterpriseEnrollment/Enrollment.svc
  Response: URLs for XCEP, WSTEP, and Auth service

Phase 2: User Authentication (browser)
  Device opens browser → GET /auth/login?flow=enroll
  User logs in via OIDC → GET /auth/callback
  Response: Enrollment token

Phase 3: Certificate Policy (no auth, no cert)
  Device → POST /xcep
  Response: Latchz Root CA certificate

Phase 4: Certificate Enrollment (token-based)
  Device → POST /wstep (with enrollment token)
  Response: Device client certificate signed by Latchz CA

Phase 5: OMA-DM Management (mTLS required)
  Device → POST /omadm (with device client cert)
  Response: Commands, policies, acknowledgments
```

Phases 1-4 do NOT require mTLS. Only Phase 5 (`/omadm`) requires the device's client certificate, which the device obtains in Phase 4.