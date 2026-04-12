#Requires -Version 5.1
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
#  Helper: print a coloured status line
# ─────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan    }
function Write-Ok    { param($msg) Write-Host "[+] $msg" -ForegroundColor Green   }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow  }
function Write-Fail  { param($msg) Write-Host "[X] $msg" -ForegroundColor Red     }
function Write-Note  { param($msg) Write-Host "    $msg" -ForegroundColor DarkGray}

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   Installing check-log CLI Tool...    " -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────
#  1. Verify Python 3.8+
# ─────────────────────────────────────────────
Write-Step "Verifying Python installation..."

$pythonCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $pythonCmd = $candidate
        break
    }
}

if (-not $pythonCmd) {
    Write-Fail "Python is not installed or not in your PATH."
    Write-Host "  Install Python 3.8+ from https://python.org"
    Write-Warn "  Check 'Add Python to PATH' during installation."
    exit 1
}

# Confirm it is actually Python 3.8+
$verRaw  = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
$verParts = $verRaw -split "\."
if ([int]$verParts[0] -lt 3 -or ([int]$verParts[0] -eq 3 -and [int]$verParts[1] -lt 8)) {
    Write-Fail "Python $verRaw found, but 3.8 or newer is required."
    Write-Host "  Download the latest version from https://python.org"
    exit 1
}
Write-Ok "Python $verRaw found."

# ─────────────────────────────────────────────
#  2. Ensure pip is up to date
# ─────────────────────────────────────────────
Write-Step "Ensuring pip is up to date..."
& $pythonCmd -m pip install --upgrade pip --quiet --no-warn-script-location
Write-Ok "pip is ready."

# ─────────────────────────────────────────────
#  3. Install pipx & Force PATH Configuration
# ─────────────────────────────────────────────
Write-Step "Ensuring pipx is installed and PATH is configured..."

# Install/upgrade pipx silently
& $pythonCmd -m pip install --user pipx --upgrade --quiet --no-warn-script-location

# Define known installation paths for Windows
$pipxBinDir = "$env:USERPROFILE\.local\bin"
$pythonScriptsDir = "$env:APPDATA\Python\Scripts"

# --- A. Update Current Session PATH ---
foreach ($dir in @($pipxBinDir, $pythonScriptsDir)) {
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    if ($env:PATH -notlike "*$dir*") {
        $env:PATH = "$dir;$env:PATH"
    }
}

# --- B. Run the official pipx path configurator ---
& $pythonCmd -m pipx ensurepath --force --quiet 2>$null

# --- C. Aggressively update User Registry PATH ---
# (Guarantees permanence even if pipx ensurepath silently failed)
$currentUserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentUserPath -notlike "*$pipxBinDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$pipxBinDir;$currentUserPath", "User")
    Write-Note "Added pipx binary folder to your permanent system PATH."
}

# Determine how to call pipx for the rest of the script
if (Get-Command pipx -ErrorAction SilentlyContinue) {
    $pipxCmd = "pipx"
} else {
    $pipxCmd = "$pythonCmd -m pipx"
}

Write-Ok "pipx is configured and ready."

# ─────────────────────────────────────────────
#  4. Install check-log via pipx
# ─────────────────────────────────────────────
Write-Step "Building and isolating package via pipx..."

# Build the base argument list
$pipxArgs = @("install", "--force")

$isWebInstall = [string]::IsNullOrEmpty($PSScriptRoot)

if ($isWebInstall) {
    Write-Note "Web installer detected – pulling from GitHub..."
    $pipxArgs += "https://github.com/SkylerOnRadio/log-checker/archive/refs/heads/main.zip"
} else {
    Write-Note "Local installation detected – installing from '$PSScriptRoot'..."
    $pipxArgs += $PSScriptRoot
}

try {
    if ($pipxCmd -eq "pipx") {
        & pipx @pipxArgs
    } else {
        # Fallback: python -m pipx
        & $pythonCmd -m pipx @pipxArgs
    }
} catch {
    Write-Fail "pipx install failed: $_"
    Write-Host ""
    Write-Warn "Troubleshooting tips:"
    Write-Note "  1. Run this script as Administrator and try again."
    Write-Note "  2. Make sure you have internet access (for web install)."
    Write-Note "  3. Check the error above for missing dependencies."
    exit 1
}

Write-Ok "Successfully installed 'check-log'!"

# ─────────────────────────────────────────────
#  5. Verify the command is actually reachable
# ─────────────────────────────────────────────
Write-Step "Verifying installation..."

if (Get-Command check-log -ErrorAction SilentlyContinue) {
    Write-Ok "'check-log' is available in this session right now."
    $needsRestart = $false
} else {
    Write-Warn "'check-log' installed successfully, but requires a terminal restart to become visible."
    $needsRestart = $true
}

# ─────────────────────────────────────────────
#  6. Done
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "        INSTALLATION COMPLETE!         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""

if ($needsRestart) {
    Write-Warn "IMPORTANT: Close and reopen your terminal for PATH changes to take effect."
    Write-Host ""
}

Write-Host "Get started:" -ForegroundColor White
Write-Host "  check-log --help" -ForegroundColor Cyan
Write-Host ""