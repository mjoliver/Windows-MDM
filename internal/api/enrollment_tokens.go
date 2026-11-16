package api

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/auth"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// BulkEnrollmentTokenItem describes a multi-use / time-bounded OOBE staging enrollment token.
type BulkEnrollmentTokenItem struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	TokenPrefix   string     `json:"token_prefix"`
	RawToken      string     `json:"token,omitempty"` // returned ONLY once at creation
	AutoGroupID   string     `json:"auto_group_id"`
	AutoGroupName string     `json:"auto_group_name"`
	MaxUses       int        `json:"max_uses"`
	UseCount      int        `json:"use_count"`
	ExpiresAt     *time.Time `json:"expires_at"`
	Revoked       bool       `json:"revoked"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
}

// HandleListEnrollmentTokens lists all bulk enrollment tokens.
// GET /api/enrollment/tokens
func (h *Handler) HandleListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT t.id, t.name, t.token_prefix, COALESCE(t.auto_group_id,''),
		       COALESCE(g.name,''), t.max_uses, t.use_count, t.expires_at,
		       t.revoked, COALESCE(t.created_by,''), t.created_at
		FROM bulk_enrollment_tokens t
		LEFT JOIN device_groups g ON g.id = t.auto_group_id
		ORDER BY t.created_at DESC
	`)
	if err != nil {
		slog.Error("api: listing bulk enrollment tokens", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list enrollment tokens")
		return
	}
	defer rows.Close()

	out := []BulkEnrollmentTokenItem{}
	for rows.Next() {
		var it BulkEnrollmentTokenItem
		var exp sql.NullTime
		var rev int
		if err := rows.Scan(
			&it.ID, &it.Name, &it.TokenPrefix, &it.AutoGroupID,
			&it.AutoGroupName, &it.MaxUses, &it.UseCount, &exp,
			&rev, &it.CreatedBy, &it.CreatedAt,
		); err != nil {
			continue
		}
		if exp.Valid {
			tm := exp.Time
			it.ExpiresAt = &tm
		}
		it.Revoked = rev != 0
		out = append(out, it)
	}
	respondOK(w, out)
}

// HandleCreateEnrollmentToken mints a new bulk enrollment token (returning the raw secret once).
// POST /api/enrollment/tokens
func (h *Handler) HandleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	var body struct {
		Name          string `json:"name"`
		AutoGroupID   string `json:"auto_group_id"`
		MaxUses       int    `json:"max_uses"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		respondErr(w, http.StatusBadRequest, "name is required (max 80 chars)")
		return
	}
	if body.MaxUses < 0 || body.MaxUses > 100000 {
		respondErr(w, http.StatusBadRequest, "max_uses must be between 0 (unlimited) and 100000")
		return
	}
	if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
		respondErr(w, http.StatusBadRequest, "expires_in_days must be between 0 (no expiry) and 3650")
		return
	}

	autoGroupID := strings.TrimSpace(body.AutoGroupID)
	var autoGroupName string
	if autoGroupID != "" {
		if err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT name FROM device_groups WHERE id = ?`), autoGroupID).Scan(&autoGroupName); err != nil {
			respondErr(w, http.StatusBadRequest, "auto_group_id does not exist")
			return
		}
	}

	rawToken, prefix, hashHex, err := auth.GenerateBulkToken()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	var expPtr *time.Time
	var expArg interface{}
	if body.ExpiresInDays > 0 {
		e := now.Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
		expPtr = &e
		expArg = e
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO bulk_enrollment_tokens (
			id, name, token_prefix, token_hash, auto_group_id, max_uses, use_count, expires_at, revoked, created_by, created_at
		) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?)
	`), id, name, prefix, hashHex, autoGroupID, body.MaxUses, expArg, actor, now)
	if err != nil {
		slog.Error("api: inserting bulk enrollment token", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to save enrollment token")
		return
	}

	h.audit(r, actor, "enrollment.token_create", "bulk_enrollment_token", id,
		fmt.Sprintf(`{"name":%q,"prefix":%q,"max_uses":%d,"auto_group_id":%q}`, name, prefix, body.MaxUses, autoGroupID))

	respondCreated(w, BulkEnrollmentTokenItem{
		ID:            id,
		Name:          name,
		TokenPrefix:   prefix,
		RawToken:      rawToken,
		AutoGroupID:   autoGroupID,
		AutoGroupName: autoGroupName,
		MaxUses:       body.MaxUses,
		UseCount:      0,
		ExpiresAt:     expPtr,
		Revoked:       false,
		CreatedBy:     actor,
		CreatedAt:     now,
	})
}

// HandleDeleteEnrollmentToken revokes (or deletes when ?hard=1 or already revoked) a bulk token.
// DELETE /api/enrollment/tokens/{id}
func (h *Handler) HandleDeleteEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)
	hard := r.URL.Query().Get("hard") == "1" || r.URL.Query().Get("hard") == "true"

	var alreadyRevoked int
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`SELECT revoked FROM bulk_enrollment_tokens WHERE id = ?`), id).Scan(&alreadyRevoked)
	if err == sql.ErrNoRows {
		respondErr(w, http.StatusNotFound, "enrollment token not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	if hard || alreadyRevoked != 0 {
		_, _ = h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM bulk_enrollment_tokens WHERE id = ?`), id)
		h.audit(r, actor, "enrollment.token_delete", "bulk_enrollment_token", id, "")
		respondOK(w, map[string]interface{}{"deleted": true, "revoked": true, "id": id})
		return
	}

	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`UPDATE bulk_enrollment_tokens SET revoked = 1 WHERE id = ?`), id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to revoke enrollment token")
		return
	}
	h.audit(r, actor, "enrollment.token_revoke", "bulk_enrollment_token", id, "")
	respondOK(w, map[string]interface{}{"deleted": false, "revoked": true, "id": id})
}

// HandleDownloadEnrollmentBootstrap serves a ready-to-run elevated PowerShell OOBE / Staging
// bootstrap script that installs the Latchz Root CA and launches Windows MDM enrollment.
// GET /api/enrollment/bootstrap.ps1
func (h *Handler) HandleDownloadEnrollmentBootstrap(w http.ResponseWriter, r *http.Request) {
	baseURL := strings.TrimRight(strings.TrimSpace(h.contentBaseURL), "/")
	if baseURL == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		host := r.Host
		if host == "" {
			host = "enterpriseenrollment.lab.local"
		}
		baseURL = scheme + "://" + host
	}

	script := BuildPowerShellBootstrapScript(baseURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="latchz-enroll-bootstrap.ps1"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// BuildPowerShellBootstrapScript renders the Windows 10/11 OOBE & Staging PowerShell script.
func BuildPowerShellBootstrapScript(serverBaseURL string) string {
	cleanBase := strings.TrimRight(strings.TrimSpace(serverBaseURL), "/")
	hostOnly := strings.TrimPrefix(strings.TrimPrefix(cleanBase, "https://"), "http://")
	if idx := strings.Index(hostOnly, "/"); idx >= 0 {
		hostOnly = hostOnly[:idx]
	}

	return fmt.Sprintf(`#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Latchz MDM — Windows 10/11 OOBE & Technician Staging Bootstrap Script
.DESCRIPTION
    1. Downloads and trusts the Latchz Root CA in Cert:\LocalMachine\Root.
    2. Copies the optional Bulk Enrollment Token (lzbt_...) to clipboard and launches
       Windows MDM Workplace/Device Enrollment pointed at %s, OR performs a headless
       WSTEP RequestSecurityToken enrollment verification when -HeadlessWSTEP is passed.
#>
param(
    [string]$ServerUrl = '%s',
    [string]$EnrollmentEmail = 'admin@lab.local',
    [string]$EnrollmentToken = '',
    [switch]$SkipTLSValidation,
    [switch]$HeadlessWSTEP
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($SkipTLSValidation) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

Write-Host "[1/3] Downloading Latchz Root CA from $ServerUrl/pki/ca.pem..." -ForegroundColor Cyan
$caPemPath = Join-Path $env:TEMP "latchz-root-ca.cer"
Invoke-WebRequest -Uri "$ServerUrl/pki/ca.pem" -OutFile $caPemPath -UseBasicParsing
Import-Certificate -FilePath $caPemPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Remove-Item -Force $caPemPath -ErrorAction SilentlyContinue
Write-Host "      Trusted Latchz Root CA in Cert:\LocalMachine\Root." -ForegroundColor Green

if ($HeadlessWSTEP) {
    if (-not $EnrollmentToken) {
        throw "Pass -EnrollmentToken 'lzbt_...' when using -HeadlessWSTEP."
    }
    Write-Host "[2/3] Generating RSA-2048 PKCS#10 CSR via certreq.exe..." -ForegroundColor Cyan
    $infPath = Join-Path $env:TEMP "latchz-wstep.inf"
    $reqPath = Join-Path $env:TEMP "latchz-wstep.req"
    @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[NewRequest]',
        'Subject="CN=LatchzStagedDevice"',
        'KeyLength=2048',
        'Exportable=FALSE',
        'MachineKeySet=TRUE',
        'ProviderName="Microsoft RSA SChannel Cryptographic Provider"',
        'RequestType=PKCS10'
    ) | Set-Content -Path $infPath -Encoding ASCII
    & certreq.exe -new -q -f $infPath $reqPath | Out-Null
    $csrLines = Get-Content -Path $reqPath | Where-Object { $_ -notmatch '^-----' }
    $csrB64 = ($csrLines -join '').Trim()
    Remove-Item -Force $infPath, $reqPath -ErrorAction SilentlyContinue

    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $os = Get-CimInstance Win32_OperatingSystem
    $hwId = "HW-$($bios.SerialNumber)-$($env:COMPUTERNAME)"
    $tokB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($EnrollmentToken))

    $soap = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
            xmlns:ac="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:$([guid]::NewGuid().ToString())</a:MessageID>
    <a:To s:mustUnderstand="1">$ServerUrl/wstep</a:To>
    <wsse:Security s:mustUnderstand="1">
      <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken"
                                EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$tokB64</wsse:BinarySecurityToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                                EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$csrB64</wsse:BinarySecurityToken>
      <ac:AdditionalContext>
        <ac:ContextItem Name="DeviceName"><ac:Value>$($env:COMPUTERNAME)</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="DeviceHardwareData"><ac:Value>$hwId</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="OSVersion"><ac:Value>$($os.Version)</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="DeviceManufacturer"><ac:Value>$($cs.Manufacturer)</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="DeviceModel"><ac:Value>$($cs.Model)</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="SMBIOSSerialNumber"><ac:Value>$($bios.SerialNumber)</ac:Value></ac:ContextItem>
      </ac:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>
"@

    Write-Host "[3/3] Submitting headless WSTEP RequestSecurityToken to $ServerUrl/wstep..." -ForegroundColor Cyan
    $resp = Invoke-WebRequest -Uri "$ServerUrl/wstep" -Method POST -ContentType "application/soap+xml; charset=utf-8" -Body $soap -UseBasicParsing
    Write-Host "      WSTEP Provisioning XML received (HTTP $($resp.StatusCode))." -ForegroundColor Green
    return
}

if ($EnrollmentToken) {
    Set-Clipboard -Value $EnrollmentToken -ErrorAction SilentlyContinue
    Write-Host "[2/3] Copied Bulk Enrollment Token to clipboard (paste into the Password / Bulk Token field)." -ForegroundColor Yellow
}

Write-Host "[3/3] Launching Windows MDM Enrollment for %s..." -ForegroundColor Cyan
Start-Process "ms-device-enrollment:?mode=mdm&username=$([uri]::EscapeDataString($EnrollmentEmail))"
`, hostOnly, cleanBase, hostOnly)
}
