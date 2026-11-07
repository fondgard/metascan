# ==============================================================================
# MetaScan — OSINT Dependencies Installer (Windows PowerShell)
# Installs PyPI dependencies (Sherlock, Maigret) and external tools (Blackbird)
# into standard user directory without polluting the MetaScan workspace.
# Pinned to audited immutable commits for supply chain security.
# ==============================================================================

$ErrorActionPreference = "Stop"

if (-not $env:VIRTUAL_ENV -or [string]::IsNullOrWhiteSpace($env:VIRTUAL_ENV)) {
    Write-Host "[-] Error: No virtual environment is active. Please activate a virtual environment first." -ForegroundColor Red
    exit 1
}

# Supply Chain Security: Pin external repository to verified commit hash
$blackbirdCommit = "471ef970b4cd45378de1270c1b2b06687aa158b7"

# Helper function to verify SHA-256 hash for external downloaded artifacts
function Verify-FileSha256 {
    param (
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$ExpectedHash
    )
    if (-not (Test-Path $FilePath)) {
        throw "File not found for hash verification: $FilePath"
    }
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    if ($actualHash -ne $ExpectedHash.ToLower()) {
        throw "SHA-256 integrity check failed for $FilePath! Expected: $ExpectedHash, got: $actualHash"
    }
    Write-Host "[+] SHA-256 integrity verified for $(Split-Path -Leaf $FilePath)" -ForegroundColor Green
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  MetaScan: Installing OSINT Dependencies (Windows)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Install PyPI requirements
Write-Host "[*] Installing requirements from requirements.txt..." -ForegroundColor Green
$reqPath = Join-Path $PSScriptRoot "requirements.txt"
python -m pip install -r $reqPath

# 2. Setup Blackbird into UserProfile directory (pinned to audited commit)
$userDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
$blackbirdDir = Join-Path $userDir ".local\share\metascan\blackbird"

Write-Host "[*] Setting up Blackbird in external directory: $blackbirdDir..." -ForegroundColor Green

if (Test-Path "$blackbirdDir\.git") {
    Write-Host "[*] Blackbird repository already exists. Pinning to commit $blackbirdCommit..." -ForegroundColor Yellow
    git -C $blackbirdDir checkout -q $blackbirdCommit
} else {
    $parentDir = Split-Path -Parent $blackbirdDir
    if (!(Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    Write-Host "[*] Cloning Blackbird from GitHub (pinned commit: $blackbirdCommit)..." -ForegroundColor Green
    git clone https://github.com/p1ngul1n0/blackbird.git $blackbirdDir
    git -C $blackbirdDir checkout -q $blackbirdCommit
}

$bbReq = Join-Path $blackbirdDir "requirements.txt"
if (Test-Path $bbReq) {
    Write-Host "[*] Installing Blackbird Python dependencies..." -ForegroundColor Green
    python -m pip install -r $bbReq
}

# 3. Register user environment variable for instant access
$env:BLACKBIRD_PATH = Join-Path $blackbirdDir 'blackbird.py'
[System.Environment]::SetEnvironmentVariable('BLACKBIRD_PATH', (Join-Path $blackbirdDir 'blackbird.py'), 'User')

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Cyan
Write-Host "  - Sherlock:  installed via PyPI" -ForegroundColor Green
Write-Host "  - Maigret:   installed via PyPI" -ForegroundColor Green
Write-Host "  - Blackbird: $blackbirdDir\blackbird.py" -ForegroundColor Green
Write-Host "               (Pinned commit: $blackbirdCommit)" -ForegroundColor Green
Write-Host "  - BLACKBIRD_PATH environment variable set." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
