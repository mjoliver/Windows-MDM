# Latchz MDM - PowerShell Build Script

$ErrorActionPreference = "Stop"

$BINARY = "latchz.exe"
$WEB_SRC = "web"
$WEB_DIST = "internal/server/web_dist"
$GO_PKG = "./cmd/latchz"

function Build-Web {
    Write-Host "Building React Dashboard..." -ForegroundColor Cyan
    Set-Location $WEB_SRC
    npm install
    npm run build
    Set-Location ..
    
    if (Test-Path $WEB_DIST) {
        Remove-Item -Recurse -Force $WEB_DIST
    }
    
    Write-Host "Copying assets to Go embed directory..." -ForegroundColor Cyan
    Copy-Item -Recurse "$WEB_SRC\dist" $WEB_DIST
}

function Build-Go {
    Write-Host "Building Go Server..." -ForegroundColor Cyan
    go build -o $BINARY $GO_PKG
}

function Clean {
    Write-Host "Cleaning build output..." -ForegroundColor Cyan
    if (Test-Path $BINARY) { Remove-Item -Force $BINARY }
    if (Test-Path "$WEB_SRC\dist") { Remove-Item -Recurse -Force "$WEB_SRC\dist" }
    if (Test-Path $WEB_DIST) { Remove-Item -Recurse -Force $WEB_DIST }
}

$arg = $args[0]

switch ($arg) {
    "web" { Build-Web }
    "go" { Build-Go }
    "clean" { Clean }
    "dev" { go run $GO_PKG serve }
    default {
        Build-Web
        Build-Go
        Write-Host "Build Complete: $BINARY" -ForegroundColor Green
    }
}
