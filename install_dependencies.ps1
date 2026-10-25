# ==============================================================================
# MetaScan — OSINT Dependencies Installer (Windows PowerShell)
# Installs PyPI dependencies (Sherlock, Maigret) and external tools (Blackbird)
# into standard user directory without polluting the MetaScan workspace.
# ==============================================================================

$ErrorActionPreference = "Stop"

if (-not $env:VIRTUAL_ENV -or [string]::IsNullOrWhiteSpace($env:VIRTUAL_ENV)) {
    Write-Host "[-] Error: No virtual environment is active. Please activate a virtual environment first." -ForegroundColor Red
    exit 1
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  MetaScan: Installing OSINT Dependencies (Windows)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Install PyPI requirements
Write-Host "[*] Installing requirements from requirements.txt..." -ForegroundColor Green
$reqPath = Join-Path $PSScriptRoot "requirements.txt"
python -m pip install -r $reqPath

# 2. Setup Blackbird into UserProfile directory
$userDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
$blackbirdDir = Join-Path $userDir ".local\share\metascan\blackbird"

Write-Host "[*] Setting up Blackbird in external directory: $blackbirdDir..." -ForegroundColor Green

if (Test-Path "$blackbirdDir\.git") {
    Write-Host "[*] Blackbird repository already exists. Updating..." -ForegroundColor Yellow
    git -C $blackbirdDir pull --ff-only
} else {
    $parentDir = Split-Path -Parent $blackbirdDir
    if (!(Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    Write-Host "[*] Cloning Blackbird from GitHub..." -ForegroundColor Green
    git clone https://github.com/p1ngul1n0/blackbird.git $blackbirdDir
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
Write-Host "  - Sherlock: installed via PyPI" -ForegroundColor Green
Write-Host "  - Maigret:  installed via PyPI" -ForegroundColor Green
Write-Host "  - Blackbird: $blackbirdDir\blackbird.py" -ForegroundColor Green
Write-Host "  - BLACKBIRD_PATH environment variable set." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
