#Requires -Version 5.1
# ═══════════════════════════════════════════════════════════════
#  check-log  |  Windows Installer
#  Usage:  irm <url>/install.ps1 | iex
#       or .\install.ps1  (from repo root)
# ═══════════════════════════════════════════════════════════════
$ErrorActionPreference = "Stop"

# ── Helpers ────────────────────────────────────────────────────
function Write-Step($Text)    { Write-Host "`n── $Text " -ForegroundColor Cyan -NoNewline; Write-Host ("─" * [Math]::Max(0, 45 - $Text.Length)) -ForegroundColor DarkGray }
function Write-Info($Text)    { Write-Host "  [*] $Text" -ForegroundColor DarkCyan }
function Write-Success($Text) { Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Warn($Text)    { Write-Host "  [!] $Text" -ForegroundColor Yellow }
function Write-Fail($Text)    { Write-Host "  [x] $Text" -ForegroundColor Red; exit 1 }

function Add-ToUserPath($Dir) {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notmatch [regex]::Escape($Dir)) {
        [Environment]::SetEnvironmentVariable("PATH", "$Dir;$userPath", "User")
        Write-Info "Added $Dir to your permanent user PATH."
    }
    # Also update the current session immediately
    if ($env:PATH -notmatch [regex]::Escape($Dir)) {
        $env:PATH = "$Dir;$env:PATH"
    }
}

# ── Banner ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██╗      ██████╗  ██████╗ " -ForegroundColor Cyan
Write-Host "  ██║     ██╔═══██╗██╔════╝ " -ForegroundColor Cyan
Write-Host "  ██║     ██║   ██║██║  ███╗" -ForegroundColor Cyan
Write-Host "  ██║     ██║   ██║██║   ██║" -ForegroundColor Cyan
Write-Host "  ███████╗╚██████╔╝╚██████╔╝" -ForegroundColor Cyan
Write-Host "  ╚══════╝ ╚═════╝  ╚═════╝ " -ForegroundColor DarkCyan
Write-Host "  Windows Installer  ·  check-log`n" -ForegroundColor DarkGray

# ══════════════════════════════════════════════════════════════
# STEP 1 ── Python version check
# ══════════════════════════════════════════════════════════════
Write-Step "Checking Python"

$py = @("py", "python", "python3") |
    Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
    Select-Object -First 1

if (-not $py) {
    Write-Fail "Python not found in PATH.`n`n  Install Python 3.8+ from: https://python.org`n  IMPORTANT: Check 'Add Python to PATH' during setup."
}

$verStr = & $py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
$verParts = $verStr -split "\."
$major = [int]$verParts[0]
$minor = [int]$verParts[1]

if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
    Write-Fail "Python $verStr found — version 3.8 or newer is required.`n  Download: https://python.org/downloads"
}

Write-Success "Python $verStr  ($py)"

# ══════════════════════════════════════════════════════════════
# STEP 2 ── pipx: install if missing, always ensure latest
# ══════════════════════════════════════════════════════════════
Write-Step "Checking pipx"

$pipxInstalled = Get-Command pipx -ErrorAction SilentlyContinue
$pipxBin = "$env:USERPROFILE\.local\bin"

if ($pipxInstalled) {
    Write-Success "pipx is already installed"
    # Silently upgrade pipx itself to avoid stale installs
    Write-Info "Upgrading pipx..."
    & $py -m pip install --user pipx --upgrade --quiet 2>$null
} else {
    Write-Info "pipx not found — installing via pip..."
    & $py -m pip install --user pipx --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Could not install pipx via pip.`n  Try: $py -m pip install --user pipx"
    }
    Write-Success "pipx installed"
}

# Ensure pipx's bin directory is on PATH (both permanent registry and current session)
Add-ToUserPath $pipxBin

# Run pipx ensurepath to handle any additional shell config
& $py -m pipx ensurepath --force --quiet 2>$null | Out-Null

# Confirm pipx is reachable after PATH update
if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
    # Try running it via the python module directly as a fallback
    $script:PipxCmd = "$py -m pipx"
    Write-Warn "pipx command not found in PATH yet — will invoke via: $script:PipxCmd"
} else {
    $pipxVer = & pipx --version 2>$null
    Write-Success "pipx $pipxVer is ready"
    $script:PipxCmd = "pipx"
}

# ══════════════════════════════════════════════════════════════
# STEP 3 ── Install or upgrade check-log
# ══════════════════════════════════════════════════════════════
Write-Step "Installing check-log"

# Decide source: if run from the repo directory, use local. Otherwise use GitHub.
$isLocalInstall = $PSScriptRoot -and (Test-Path "$PSScriptRoot\pyproject.toml" -or Test-Path "$PSScriptRoot\setup.py")
$source = if ($isLocalInstall) { $PSScriptRoot } else { "git+https://github.com/SkylerOnRadio/log-checker.git@improved-install" }
$sourceLabel = if ($isLocalInstall) { "local source ($PSScriptRoot)" } else { "GitHub" }

# Check if already installed
$alreadyInstalled = $false
try {
    $listOutput = & $py -m pipx list 2>$null
    $alreadyInstalled = $listOutput -match "check-log"
} catch {}

if ($alreadyInstalled) {
    Write-Warn "check-log is already installed — reinstalling from $sourceLabel..."
    & $py -m pipx install --force $source --pip-args="--quiet" | Out-Null
    $action = "reinstalled"
} else {
    Write-Info "Downloading and building from $sourceLabel..."
    & $py -m pipx install $source --pip-args="--quiet"
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Installation failed.`n`n  Debug with: pipx install $source"
    }
    $action = "installed"
}

Write-Success "check-log $action"

# ══════════════════════════════════════════════════════════════
# STEP 4 ── Optional: Node.js / npm (for web dashboard)
# ══════════════════════════════════════════════════════════════
Write-Step "Checking optional dependencies"

$nodeOk = Get-Command node -ErrorAction SilentlyContinue
$npmOk  = Get-Command npm  -ErrorAction SilentlyContinue

if ($nodeOk -and $npmOk) {
    $nodeVer = & node --version
    $npmVer  = & npm  --version
    Write-Success "Node.js $nodeVer  /  npm $npmVer — Web Dashboard (-a) is available"
} else {
    Write-Warn "Node.js / npm not found."
    Write-Host "    The CLI works without it, but the --app web dashboard requires Node.js 18+." -ForegroundColor DarkGray
    Write-Host "    Download: https://nodejs.org" -ForegroundColor DarkGray
}

# ══════════════════════════════════════════════════════════════
# STEP 5 ── Verify
# ══════════════════════════════════════════════════════════════
Write-Step "Verifying installation"

$checkLogCmd = Get-Command check-log -ErrorAction SilentlyContinue
if ($checkLogCmd) {
    $version = & check-log --version 2>$null
    Write-Success "check-log $action successfully!  ($version)"
    Write-Host "`n  ✓ Ready. Run: " -ForegroundColor Green -NoNewline
    Write-Host "check-log --help`n" -ForegroundColor Cyan
} else {
    Write-Warn "check-log was $action but is not yet visible in this terminal session."
    Write-Host "`n  PATH was updated permanently, but you need to restart this terminal." -ForegroundColor Yellow
    Write-Host "  After restarting, verify with: " -NoNewline -ForegroundColor Yellow
    Write-Host "check-log --help`n" -ForegroundColor Cyan
}