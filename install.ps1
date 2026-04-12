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
#  2. Ensure pip is up to date (silently)
# ─────────────────────────────────────────────
Write-Step "Ensuring pip is up to date..."
& $pythonCmd -m pip install --upgrade pip --quiet --no-warn-script-location
Write-Ok "pip is ready."

# ─────────────────────────────────────────────
#  3. Install / upgrade pipx
# ─────────────────────────────────────────────
Write-Step "Ensuring pipx is installed..."

$pipxInPath = [bool](Get-Command pipx -ErrorAction SilentlyContinue)

if (-not $pipxInPath) {
    Write-Note "pipx not found – installing via pip..."
    & $pythonCmd -m pip install --user pipx --upgrade --quiet --no-warn-script-location

    # Collect candidate pipx locations and add them to the current session PATH
    $extraPaths = @(
        "$env:USERPROFILE\.local\bin",
        "$env:APPDATA\Python\Scripts",
        # e.g. C:\Users\<user>\AppData\Local\Programs\Python\Python3xx\Scripts
        (& $pythonCmd -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null)
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($p in $extraPaths) {
        if ($env:PATH -notlike "*$p*") { $env:PATH = "$p;$env:PATH" }
    }

    # Make the PATH change permanent for future sessions
    & $pythonCmd -m pipx ensurepath --quiet 2>$null

    # Re-check pipx is now reachable in this session
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        # Fall back: always invoke via python -m pipx
        Write-Warn "pipx command not yet in PATH for this session – using 'python -m pipx' as a fallback."
        $pipxCmd = "$pythonCmd -m pipx"
    } else {
        $pipxCmd = "pipx"
    }
} else {
    Write-Note "pipx already installed – upgrading..."
    & $pythonCmd -m pip install --user pipx --upgrade --quiet --no-warn-script-location
    $pipxCmd = "pipx"
}
Write-Ok "pipx is ready."

Write-Step "Registering pipx bin directory in system PATH..."

# Ask pipx where it puts executables
$pipxBinDir = (& $pythonCmd -m pipx environment 2>$null |
    Select-String "PIPX_BIN_DIR" |
    ForEach-Object { ($_ -split "=", 2)[1].Trim() })

if ($pipxBinDir -and (Test-Path $pipxBinDir)) {

    # Add to current session immediately
    if ($env:PATH -notlike "*$pipxBinDir*") {
        $env:PATH = "$pipxBinDir;$env:PATH"
    }

    # Add permanently to the User PATH in the registry
    $currentUserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentUserPath -notlike "*$pipxBinDir*") {
        [System.Environment]::SetEnvironmentVariable(
            "PATH",
            "$currentUserPath;$pipxBinDir",
            "User"
        )
        Write-Ok "Added '$pipxBinDir' to your permanent PATH."
    } else {
        Write-Note "'$pipxBinDir' is already in your PATH."
    }
} else {
    Write-Warn "Could not detect pipx bin dir – run 'python -m pipx ensurepath' manually."
}

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
# Refresh PATH from registry so the newly installed tool is discoverable
$machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
$userPath    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
$env:PATH    = "$userPath;$machinePath"

if (Get-Command check-log -ErrorAction SilentlyContinue) {
    Write-Ok "'check-log' is available in this session right now."
    $needsRestart = $false
} else {
    Write-Warn "'check-log' will be available after you restart your terminal."
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