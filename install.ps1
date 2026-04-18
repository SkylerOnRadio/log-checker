#Requires -Version 5.1
$ErrorActionPreference = "Stop"

function Write-Color($Text, $Color) { Write-Host $Text -ForegroundColor $Color }
Write-Color "`n🚀 Installing check-log..." "Cyan"

# ── 1. Find Python ──────────────────────────────────────────
$py = @("py", "python", "python3") | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
if (!$py) { 
    Write-Color "❌ Python is not installed or not in PATH." "Red"
    Write-Color "👉 Install Python 3.8+ from https://python.org (Check 'Add to PATH'!)" "Yellow"
    exit 1 
}

$ver = & $py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ([decimal]$ver -lt 3.8) { 
    Write-Color "❌ Python $ver found. Version 3.8 or newer is required." "Red"
    exit 1 
}

# ── 2. Install pipx & Setup PATH ────────────────────────────
Write-Color "[*] Configuring pipx environment..." "DarkGray"
& $py -m pip install --user pipx --upgrade --quiet

$pipxBin = "$env:USERPROFILE\.local\bin"
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")

# Aggressively update Registry PATH (permanent)
if ($userPath -notmatch [regex]::Escape($pipxBin)) {
    [Environment]::SetEnvironmentVariable("PATH", "$pipxBin;$userPath", "User")
}
# Update Current Session PATH (immediate)
if ($env:PATH -notmatch [regex]::Escape($pipxBin)) { 
    $env:PATH = "$pipxBin;$env:PATH" 
}

& $py -m pipx ensurepath --force --quiet 2>$null

# ── 3. Install check-log ────────────────────────────────────
Write-Color "[*] Downloading and compiling check-log..." "DarkGray"
$source = if ($PSScriptRoot) { $PSScriptRoot } else { "https://github.com/SkylerOnRadio/log-checker/archive/refs/heads/main.zip" }

try {
    & $py -m pipx install --force $source | Out-Null
} catch {
    Write-Color "❌ pipx install failed: $_" "Red"
    exit 1
}

# ── 4. Web Dashboard Dependency Check ───────────────────────
if (!(Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    Write-Color "`n[!] Node.js not found. The CLI will work, but the Web Dashboard (-a) requires Node.js." "DarkYellow"
    Write-Color "    Download Node.js here: https://nodejs.org/" "DarkGray"
}

# ── 5. Final Verification ───────────────────────────────────
if (Get-Command check-log -ErrorAction SilentlyContinue) {
    Write-Color "`n✅ Installation Complete! Type 'check-log --help' to begin.`n" "Green"
} else {
    Write-Color "`n✅ Installation Complete! Please CLOSE and REOPEN this terminal, then type 'check-log --help'.`n" "Yellow"
}