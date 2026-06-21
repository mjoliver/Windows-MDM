param(
    [Parameter(Mandatory=$true)]
    [string]$ProjectId,
    [string]$Region = "us-central1",

    # Production secrets — pass these on the command line, don't commit them
    [Parameter(Mandatory=$true)]
    [string]$DatabaseDsn,          # e.g. postgresql://user:pass@host/db?sslmode=require
    [Parameter(Mandatory=$true)]
    [string]$MasterSecret,         # strong random string, at least 32 chars
    [Parameter(Mandatory=$true)]
    [string]$OidcClientId,
    [Parameter(Mandatory=$true)]
    [string]$OidcClientSecret
)

Write-Host "=== Latchz MDM Cloud Run Deployer ===" -ForegroundColor Cyan

# Check if gcloud is installed
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Error "gcloud CLI not found. Please install the Google Cloud SDK first."
    exit 1
}

# Ensure Artifact Registry repository exists
Write-Host "1. Checking if Artifact Registry repository 'latchz' exists..." -ForegroundColor Yellow
$repoExists = gcloud artifacts repositories list --location=$Region --project=$ProjectId --filter="name:projects/$ProjectId/locations/$Region/repositories/latchz" --format="value(name)"

if (-not $repoExists) {
    Write-Host "Creating 'latchz' Docker repository in Artifact Registry..." -ForegroundColor Yellow
    gcloud artifacts repositories create latchz `
      --repository-format=docker `
      --location=$Region `
      --project=$ProjectId `
      --description="Latchz MDM Docker repository" `
      --quiet

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create Artifact Registry repository."
        exit 1
    }
}

$imageUri = "$Region-docker.pkg.dev/$ProjectId/latchz/latchz:latest"

Write-Host "2. Submitting source code to Google Cloud Build (no local Docker required)..." -ForegroundColor Yellow
gcloud builds submit --tag $imageUri --project $ProjectId

if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Build failed."
    exit 1
}

# Build the env vars string
$envVars = @(
    "LATCHZ_SERVER_DOMAIN=enterpriseenrollment.mjo.gg",
    "LATCHZ_SERVER_ENROLLMENT_DOMAIN=mjo.gg",
    "LATCHZ_SERVER_SUPPORT_URL=https://github.com/latchzmdm/latchz/blob/main/docs/self-hosting.md",
    "LATCHZ_SERVER_MASTER_SECRET=$MasterSecret",
    "LATCHZ_TLS_MODE=none",
    "LATCHZ_DATABASE_DRIVER=postgres",
    "LATCHZ_DATABASE_DSN=$DatabaseDsn",
    "LATCHZ_AUTH_PROVIDER=oidc",
    "LATCHZ_AUTH_OIDC_ISSUER=https://accounts.google.com",
    "LATCHZ_AUTH_OIDC_CLIENT_ID=$OidcClientId",
    "LATCHZ_AUTH_OIDC_CLIENT_SECRET=$OidcClientSecret",
    "LATCHZ_AUTH_OIDC_ALLOWED_DOMAINS=mjo.gg"
) -join ","

Write-Host "3. Deploying container to Google Cloud Run..." -ForegroundColor Yellow
gcloud run deploy latchz `
  --image $imageUri `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --project $ProjectId `
  --set-env-vars $envVars

if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Run deployment failed."
    exit 1
}

Write-Host "=== Deployment Successful! ===" -ForegroundColor Green
