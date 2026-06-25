# Latchz MDM — Holistic Review & Test-Coverage Plan

> **Remediation status (branch `security-hardening`):** All Critical/High/Medium
> findings below have been fixed, plus the requested net-new features (builtin
> username/password auth, certificate renewal/ROBO, policy retraction, TLS-layer
> revocation). Each fix ships with regression tests; Go coverage went 0 → ~35%
> (security-critical paths 55–89%), and a CI workflow (gofmt/vet/build/`-race`+
> coverage, plus a web typecheck/lint/test job) was added. See this branch's git
> history for the per-phase commits. Two items are intentionally deferred and
> noted here: server-side session revocation (stateless JWT + cookie-clear today)
> and frontend RBAC-by-role hiding of destructive controls (backend RBAC is
> enforced).

**Scope:** Whole codebase (Go backend `./internal` + `./cmd`, React/TS `./web`, config/deploy/Docker).
**Method:** Every core file read line-by-line, plus a 123-agent review workflow (10 subsystem finders → adversarial verification of each finding → completeness critics → test planners). 102 issues confirmed against the real code (9 critical / 15 high / 13 medium / 45 low / 13 info); 5 candidate findings refuted on verification.

> The README already says "POC, no security audit, not production-ready." That is accurate. This report tells you *which* gaps matter most and in what order to close them.

---

## Verdict

The **enrollment → device-management → admin trust chain is broken in the configurations the project actually documents.** Three independent paths each collapse authentication to ~nothing:

1. **Non-OIDC / unset provider** (a documented config value) → the *entire* admin API, certificate issuance, and a dev "auto-enroll" page all run **unauthenticated**.
2. **The documented Cloud Run deployment** (`tls.mode=none`, TLS terminated upstream) → device management authenticates on a **non-secret hardware ID**, because client certs are optional and `r.TLS` is always nil there.
3. **Default OIDC config** (`allowed_domains` empty) → the **first internet visitor** to finish the Google login becomes **super_admin**.

Until the Critical block below is fixed, treat the server as not safe to expose to the internet — which is exactly what an MDM must do.

What's genuinely solid is called out in **§4** so the rewrite keeps it.

---

## §1 — Security findings

### 🔴 CRITICAL

**C1. Non-OIDC / no provider disables ALL authentication (admin API + cert issuance + enrollment).**
`server.go:54` only builds `authProvider` when `provider=="oidc"`. Then three fail-open paths trigger when it's nil:
- `requireAuth` (`server.go:385-406`) — *"No auth configured — allow in dev"* → every `/api/*` route (incl. **wipe/lock/unenroll**) served with no session.
- WSTEP token validator (`server.go:136-142`) — `func(t){ return "builtin@pane.local", nil }` accepts **any** token, so `/wstep` mints a CA-signed client cert for any internet caller.
- Dev login page (`server.go:411-433`) — serves an HTML page that auto-injects an enrollment token (`test@mjo.gg`).
`config.validate()` only checks fields when provider is `oidc`, so `provider: builtin` / `ldap` (both advertised in `config.go:62`) pass validation and boot wide-open. **Fix:** fail closed — refuse to start (or 503 protected routes) when no real provider is configured; never ship an accept-any-token validator or dev bypass page in a production-capable build (guard behind a build tag).

**C2. Any internet user can become super_admin (first-login bootstrap + empty `allowed_domains` default).**
`oidc.go:452-461` grants `super_admin` to the first user row; `isEmailAllowed` returns `true` when the allowlist is empty (`oidc.go:432-435`), and `allowed_domains` defaults to `[]` (`config.go:101`). With the quickstart (Google issuer, no allowlist), whoever logs in first owns the fleet. **Fix:** require `allowed_domains` when `provider=oidc` (fail validation if empty); bootstrap the first admin out-of-band (config-provided email or one-time setup token), never via an internet-reachable flow.

**C3. Device-management auth bypass via non-secret `hardware_id`.**
`handler.go:234-320`: if no client cert is presented, `authenticateDevice` falls back to `lookupDeviceByRequest`, trusting `?hwid=` or the SyncML `Source/LocURI`. TLS uses `VerifyClientCertIfGiven` (`server.go:336,351`) — optional — and the auto-TLS path never sets `ClientAuth` at all (`tls_auto.go:63-67`); the documented Cloud Run deploy (`deploy.ps1` → `LATCHZ_TLS_MODE=none`) has no client TLS at all. Hardware IDs aren't secret (they're in logs and the provisioned `/omadm?hwid=…` URL — `wstep.go:244`). → Anyone can impersonate any enrolled device: read its queued commands, **ACK a wipe/lock**, or forge its compliance/inventory. **Fix:** require & verify an mTLS client cert for `/omadm` (`RequireAndVerifyClientCert`), or, behind a proxy, authenticate via a signed client-cert header from the proxy; delete the hwid/SourceURI fallback.

**C4. Root CA private key protected only by an unsalted SHA-256 of the master secret.**
`ca.go:277-301`: AES-256-GCM vault key = `sha256(master_secret)` — no salt, no KDF iterations, no entropy floor (`main.go:65` only checks non-empty). The shipped `latchz.yaml:5` commits a known placeholder secret. Anyone with the DB file (or a guessable secret) recovers the **root CA key** and can mint trusted device certs forever. **Fix:** derive with argon2id/scrypt + a random per-record salt stored beside the ciphertext; enforce a ≥32-byte high-entropy secret; rotate the committed placeholder out.

*(The 9 "critical" rows from the workflow are 4 distinct root causes — C1 was independently re-found by the api, server, enrollment, and cross-cutting finders, which is a high-confidence signal.)*

### 🟠 HIGH

- **Cert identity is fully attacker-controlled.** The enrollment JWT only proves an email; WSTEP never binds it to the cert. `IssueDeviceCert` copies `CommonName` straight from the device CSR (`ca.go:201`), no SAN, no link to the OIDC user or device row (`wstep.go:194-262`). **Fix:** derive Subject/SAN + a server-generated device ID from the validated token; reject CSRs that don't match.
- **Device-record hijack via `ON CONFLICT(hardware_id)`.** `wstep.go:199-211` upserts on the client-supplied `hardware_id`; enrolling with an existing device's HWID overwrites `enrolled_by` and re-points its identity. **Fix:** require proof-of-ownership (existing valid cert) for re-enroll, or key identity on a server-generated ID.
- **No RBAC anywhere.** `requireAuth` only checks that a session exists; `role` is plumbed to context and returned by `/api/me` but never enforced (`server.go:159-199`, `api/devices.go:103-202`). Any allowed-domain user can wipe/lock/unenroll every device and edit all profiles/groups. **Fix:** `requireRole(...)` middleware on mutating/destructive routes.
- **Open redirect / enrollment-token exfiltration via `appru`** (`oidc.go:292-311, 504-515`) — the callback auto-POSTs the enrollment token (`wresult`) to an attacker-controlled URL. **Plus reflected XSS** via `login_hint`/`email`/`appru` interpolated into `fmt.Fprintf` HTML (`oidc.go:228-236`). **Fix:** allowlist `appru` to expected Windows return URIs; render all HTML with `html/template` (contextual escaping).
- **Remote-DoS crash: concurrent map write on `Session.CmdMap`** (`session.go:28-37`, mutated in `HandleOMADM`/`processStatuses`/`buildSyncMLCommands` without holding the store lock). Go aborts the **whole process** on detected concurrent map write — unrecoverable by `recover()`. Two concurrent check-ins for one session crash the server. **Fix:** add a per-`Session` mutex (and move the global `store` onto the handler).
- **Enrollment bearer JWT logged in cleartext** (`wstep.go:161`) — a 20-min credential that authorizes cert issuance, in every WSTEP log line. **Fix:** never log raw tokens.
- **Compliance upsert is broken on SQLite** (also a correctness bug — see §2): `compliance_records` has no `UNIQUE(device_id,catalog_id)` in the SQLite migration but `session.go:206-214` uses `ON CONFLICT(device_id,catalog_id)` → every compliance write errors on the **default** driver.
- **`/omadm` never requires a client cert** (`server.go:336,351`) — the routing-layer side of C3.
- **Dev `/auth/login` bypass page** auto-enrolls with hardcoded `test@mjo.gg` in non-OIDC mode (`server.go:411-433`).

### 🟡 MEDIUM (hardening / abuse-resistance)

- **JWT secret regenerated every process start** (`server.go:43-48`); the documented stable-secret env var is **never read** by `config.go`. → all sessions die on restart, and tokens issued by one Cloud Run instance are rejected by another (enrollment flakes under autoscaling).
- **Stateless sessions:** logout doesn't invalidate the JWT; role/disable changes ignored for 12h (`oidc.go:276-286, 397-418`).
- **No single-use/replay or quota on enrollment tokens** → one token enrolls unlimited devices (`wstep.go:168-235`).
- **No rate limiting on any endpoint** (`server.go`) → device/account enumeration, emergency-token brute force.
- **Emergency token compared with `!=`** (`server.go:452`) — non-constant-time; and the endpoint is a stub that grants nothing.
- **Auto-TLS listeners set no timeouts/limits** (`tls_auto.go:57-67`) → Slowloris (the other TLS modes do set them).
- **SQLite PRAGMAs applied to one pooled connection only** (`db.go:44-51`) while `MaxOpenConns=10` → WAL/busy_timeout not in effect on the other 9 conns (lock contention/`SQLITE_BUSY`).
- **`master_secret` has no entropy floor** (pairs with C4).
- **Ignored `COUNT(*)` error can grant super_admin** (`oidc.go:454`) — a transient DB error leaves `count=0` → next login bootstraps as admin.
- **`os.WriteFile("last_soap_response.xml", …)` on every SOAP response** (`discovery.go:255`) — disk DoS, races, info disclosure of cert material.
- **Secrets as plaintext Cloud Run env vars** (`deploy.ps1` — master secret + DB password); **Dockerfile runs as root**, `alpine:latest` unpinned.

*(45 low + 13 info findings — TLS cipher hardening, security headers/HSTS/CSP absent, audit-log gaps, error-detail leakage, etc. — are in the full machine-readable export.)*

---

## §2 — Logic / correctness bugs & feature gaps

- **Compliance is cosmetic:** every check-in hardcodes `compliance_status='compliant'` (`handler.go:92-94`) regardless of posture; and the real compliance upsert errors on SQLite (see High). So the dashboard's compliance is meaningless today.
- **No policy retraction:** removing a profile/device from a group, or deleting a setting, never un-applies it on the device (`policy/resolver.go:95-111`). MDM must send Replace-to-default/Delete deltas.
- **No certificate renewal (ROBO):** WSTEP always demands a 20-min OIDC token, but Windows renews non-interactively with the existing cert. Devices silently drop off management after 1 year (`wstep.go`, `xcep.go:80`). Branch on `RequestType` and authenticate renewals via the presented client cert.
- **`lookupDeviceByRequest` truncates the body to 4096 bytes** (`handler.go:292-293`) then restores it — real check-ins with Results exceed that and parse-corrupt.
- **Command queue has no dedup** (`policy/resolver.go`, `devices.go:217-245`) → repeated Sync/profile-apply piles unbounded duplicate commands.
- **First-check-in interrogation can loop forever** and prevents session eviction (`handler.go:112-116, 224-227`); **in-memory session map never evicts** (memory DoS, `session.go:40-69`).
- **Remote wipe leaves the device `is_active=1` with a valid cert** (`devices.go:173-202`).
- **Postgres portability breaks** on the *recommended* backend: `handler.go:92` raw `?` without `Rebind`; `main.go:145` uses SQLite-only `randomblob`. FK constraints aren't enforced on SQLite (no `PRAGMA foreign_keys=ON`).
- **Mislabeled constant:** `OMADevDetailFreeStorage` points at the LocalTime node (`syncml.go:171`).
- **Frontend bugs:** no client-side route guards (only `Layout` `useEffect`; children fetch before auth resolves); **path injection** via unescaped `/devices/${id}` etc. in `api.ts` (no `encodeURIComponent`); `Login.tsx` renders `href={supportUrl}` from `/api/config` with no scheme allowlist (`javascript:`/`data:` sink); `ProfileDetail.handleAddPolicy` does uncaught `JSON.parse(allowed_values)`; `/catalog` & `/settings` nav links have no route (dead nav); `result_code` hex render yields `"NaN"`; `timeAgo` duplicated 3×.

---

## §3 — Correctly refuted (so you don't chase them)

The verifiers killed 5 plausible-but-wrong findings — useful to record:
- **"No body-size limit on XML parsers"** — false; all SOAP/SyncML reads use `io.LimitReader(r.Body, 1<<20)`. Combined with Go's `encoding/xml` not resolving external entities, classic **XXE / billion-laughs is low-risk** here.
- **"CSRF on POST actions"** — mitigated by `SameSite=Strict` on the session cookie.
- **Source-map exposure / device-cert-revocation-at-TLS** — downgraded after reading the actual code (revocation *is* checked on the thumbprint-lookup path; the gap is only the optional-mTLS fallback, already covered by C3).

---

## §4 — What's solid (keep this during the rewrite)

- **SQL is consistently parameterized** through `db.Rebind` — including the dynamically-assembled catalog query. No SQL injection found.
- **OIDC ID-token verification is proper** (issuer/audience/expiry/signature via `go-oidc`), `email_verified` enforced, login-state cookie provides CSRF protection on the login leg.
- **Session cookie**: `HttpOnly`, `Secure`, `SameSite=Strict`; **JWT alg pinned to HMAC** (no alg-confusion).
- **CSR signature is checked** before signing; **RSA-4096 CA**, **128-bit random serials**, AES-256-GCM at rest (the weakness is only the KDF — C4).
- **Frontend** stores no token in localStorage (httpOnly cookie), React auto-escaping; no `dangerouslySetInnerHTML` anywhere.
- Clean DI seams already exist (`HandleWSTEP(ca, db, validateToken)`, `mdm.NewHandler(db, caPool, domain)`, `api.NewHandler(db)`), which makes the test plan below cheap to land.

---

## §5 — Test-coverage plan (currently: ZERO tests)

Goal: a security-regression-first suite that ratchets coverage from ~0 → ~60%, with the Critical findings encoded as **failing tests that must turn green** as you fix them.

### 5.1 Enabling refactors (small, do first — they unblock everything)
1. Remove/gate `discovery.go:255` `os.WriteFile` debug side-effect (breaks hermetic/parallel tests).
2. Inject a `func() time.Time` clock into `pki.CA`, WSTEP timestamps, and auth token issuance (deterministic certs/goldens).
3. Move `mdm`'s package-global `var store` onto `mdm.Handler` (test isolation + it's the locus of the `CmdMap` race).
4. Add `func (s *Server) Handler() http.Handler { return s.mux }` so `httptest` can drive the full route table.
5. Add an `auth` constructor that accepts a pre-built verifier (or small `TokenVerifier` interface) so the callback flow runs against a fake OIDC server.
6. Read a **stable JWT secret** from config (also fixes the medium bug).
7. Test infra: `internal/testutil` DB helper (in-mem SQLite + embedded migrations + set/reset `db.DriverName`); a **cached RSA-4096 CA fixture** (keygen is ~hundreds of ms — generate once); an `enrolltest` harness that builds Discovery/XCEP/WSTEP SOAP + CSR + parses the provisioning doc; a golden harness with `-update` and timestamp/UUID/serial normalization.

### 5.2 Phased rollout
- **Phase 0 — green CI skeleton.** New `.github/workflows/ci.yml` using `go-version-file: go.mod` (the existing `ddf-compiler.yml` pins Go **1.24**, which *cannot build* `go.mod`'s 1.26.2). `gofmt -l`, `go vet`, `go build ./...`, one smoke test. Land the §5.1 seams. Add cross-platform `make test`/`test-race`/`cover` (current Makefile is Windows-only and points at a non-existent `./cmd/pane`).
- **Phase 1 — P0 security regressions + pure units.** The criticals as tests (below) + token/crypto/`Rebind`/`isEmailAllowed`/bootstrap units. Turn on `go test -race` and coverage **reporting** (no gate yet).
- **Phase 2 — protocol goldens + the e2e walk.** Discovery/XCEP/WSTEP/SyncML golden files; the compliance-UNIQUE regression; the `CmdMap` race under `-race`. Commit a coverage baseline and **switch the ratchet gate on**.
- **Phase 3 — API/RBAC breadth + OIDC double.** Callback XSS/open-redirect, RBAC matrix; add a Postgres service container to CI for SQL/dialect parity.
- **Phase 4 — frontend + fuzz + hardening.** Vitest job; fuzz the two unauth XML parsers (short in PR, long nightly); TLS-mode/timeout/Slowloris and session-eviction tests.

### 5.3 Coverage targets (per package): db 80% · config 70% · pki 75% · auth 70% · enrollment 65% · mdm 65% · api 60% · server 50%. Repo floor starts ~40% and ratchets to 60%. Use `go test -coverprofile` + a baseline gate (e.g. `go-test-coverage`).

### 5.4 The P0 tests that double as security regressions
| Test | Target | Pins |
|---|---|---|
| `requireAuth_fail_open_regression` | `server.go` requireAuth | C1 (admin API open when provider nil) |
| `wstep_builtin_accepts_any_token` | `server.go` validateToken + WSTEP | C1 (cert minted for any token) |
| `omadm_hardware_id_auth_bypass` | `handler.go` authenticateDevice | C3 (impersonation via hwid) |
| `auth_bootstrap_first_user_super_admin` | `oidc.go` upsertUser | C2 (first login = super_admin) |
| `isEmailAllowed_empty_default_permissive` | `oidc.go` isEmailAllowed | C2 (open default) |
| `validate_enrollment_token_rejections` | `oidc.go` Validate*Token | alg=none / HMAC-confusion / type-confusion |
| `pki_ca_issue_and_crypto_roundtrip` | `ca.go` | cert chains + key roundtrip; documents weak KDF (C4) |
| `compliance_records_sqlite_unique_upsert` | `session.go` + migration | broken compliance upsert |
| `session_cmdmap_concurrent_write_race` | `session.go` (`-race`) | remote-DoS crash |
| `wstep_device_hijack_by_hardware_id` | `wstep.go` ON CONFLICT | record hijack |
| `auth_callback_appru_openredirect_and_xss` | `oidc.go` callback | token exfil + reflected XSS |
| `e2e_enroll_walk` | full route table | Discovery→XCEP→WSTEP→OMA-DM in-memory |

Plus P1 protocol **goldens** (Discovery/XCEP/WSTEP "Template Bomb"/SyncML ordering), `Rebind` table tests, migration parity, command-queue lifecycle, policy resolver precedence; P2 **fuzz** targets for `parseSOAPEnvelope`, SyncML unmarshal, CSR decode, `ValidateEnrollmentToken`, `Rebind`. **Frontend** (vitest + RTL + msw, 19 tests): the `api.ts` 401-redirect gate, path-injection encoding, `Login` `javascript:` href, no-RBAC button exposure, loader error states, `ProfileDetail` JSON.parse crash.

---

## §6 — Suggested remediation order (security)

1. **Fail closed when no real auth provider** (C1): remove the accept-any-token validator and dev login page (build-tag them); make `allowed_domains` mandatory and fix the bootstrap (C2).
2. **Require & verify client certs on `/omadm`** (C3); delete the hwid/SourceURI fallback (or accept a signed proxy header only).
3. **Bind cert identity** to the authenticated user + a server-generated device ID; reject hijack-by-hardware_id.
4. **Replace the CA-key KDF** with argon2id + salt and enforce secret entropy (C4); rotate the committed placeholder; move secrets to Secret Manager.
5. **Add RBAC** middleware on destructive routes.
6. **Stable JWT secret** from config; stop logging tokens; `html/template` + `appru` allowlist.
7. Fix the correctness bugs that make the product not work: SQLite `UNIQUE(device_id,catalog_id)`, the Postgres placeholder/`randomblob` bugs, the `Session` mutex, and stop hardcoding `compliance_status='compliant'`.
8. Add cert renewal + policy retraction (feature gaps that an MDM can't ship without).

Then stand up CI + the Phase-1 security-regression tests so none of the above silently regress.
