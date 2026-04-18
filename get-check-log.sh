#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  check-log  |  Remote Installer
#  Usage: curl -sSL <url>/get-check-log.sh | bash
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

REPO_URL="git+https://github.com/SkylerOnRadio/log-checker.git"
MIN_PYTHON_MINOR=8
TOOL_NAME="check-log"

# ── Helpers ────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}── $* ${NC}${DIM}─────────────────────────────────────${NC}"; }

# ── Banner ─────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}"
echo "  ██╗      ██████╗  ██████╗ "
echo "  ██║     ██╔═══██╗██╔════╝ "
echo "  ██║     ██║   ██║██║  ███╗"
echo "  ██║     ██║   ██║██║   ██║"
echo "  ███████╗╚██████╔╝╚██████╔╝"
echo "  ╚══════╝ ╚═════╝  ╚═════╝ "
echo -e "${NC}${DIM}  Installer  ·  check-log${NC}\n"

# ══════════════════════════════════════════════════════════════
# STEP 1 ── Python version check
# ══════════════════════════════════════════════════════════════
step "Checking Python"

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version_str=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        major=$(echo "$version_str" | cut -d. -f1)
        minor=$(echo "$version_str" | cut -d. -f2)
        if [[ "$major" -eq 3 && "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
            PYTHON="$cmd"
            success "Found Python $version_str  ($cmd)"
            break
        else
            warn "Found Python $version_str — too old, need 3.$MIN_PYTHON_MINOR+"
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    die "Python 3.$MIN_PYTHON_MINOR+ not found.\n\n  Install it:\n    Ubuntu/Debian : sudo apt install python3\n    macOS         : brew install python3\n    Arch          : sudo pacman -S python"
fi

# ══════════════════════════════════════════════════════════════
# STEP 2 ── pipx: install if missing
# ══════════════════════════════════════════════════════════════
step "Checking pipx"

install_pipx() {
    info "pipx not found — installing automatically..."

    # Detect package manager and try native install first (preferred)
    if command -v apt-get &>/dev/null; then
        info "Detected apt — running: sudo apt-get install -y pipx"
        sudo apt-get install -y pipx || true
    elif command -v brew &>/dev/null; then
        info "Detected Homebrew — running: brew install pipx"
        brew install pipx || true
    elif command -v pacman &>/dev/null; then
        info "Detected pacman — running: sudo pacman -S --noconfirm python-pipx"
        sudo pacman -S --noconfirm python-pipx || true
    elif command -v dnf &>/dev/null; then
        info "Detected dnf — running: sudo dnf install -y pipx"
        sudo dnf install -y pipx || true
    elif command -v yum &>/dev/null; then
        info "Detected yum — running: sudo yum install -y python3-pip && pip install pipx"
        sudo yum install -y python3-pip && "$PYTHON" -m pip install --user pipx --quiet || true
    fi

    # Fall back to pip if the above didn't work
    if ! command -v pipx &>/dev/null; then
        info "Falling back to: $PYTHON -m pip install --user pipx"
        "$PYTHON" -m pip install --user pipx --quiet || die "Could not install pipx via pip either.\n  Try manually: sudo apt install pipx  (or brew install pipx)"
        # Add ~/.local/bin to PATH for this session so the newly pip-installed pipx is reachable
        export PATH="$HOME/.local/bin:$PATH"
    fi

    command -v pipx &>/dev/null || die "pipx installation succeeded but the command is still not found.\n  Run: export PATH=\"\$HOME/.local/bin:\$PATH\"  then re-run this installer."
}

if command -v pipx &>/dev/null; then
    success "pipx is already installed  ($(pipx --version))"
else
    install_pipx
    success "pipx installed successfully  ($(pipx --version))"
fi

# ══════════════════════════════════════════════════════════════
# STEP 3 ── Install or upgrade check-log
# ══════════════════════════════════════════════════════════════
step "Installing $TOOL_NAME"

if pipx list 2>/dev/null | grep -q "$TOOL_NAME"; then
    warn "$TOOL_NAME is already installed — upgrading to latest..."
    pipx upgrade "$TOOL_NAME" --pip-args="--quiet" \
        || pipx install --force "$REPO_URL" --pip-args="--quiet"
    ACTION="upgraded"
else
    info "Downloading and building from GitHub..."
    pipx install "$REPO_URL" --pip-args="--quiet" \
        || die "Installation failed.\n\n  Try manually:\n    pipx install $REPO_URL"
    ACTION="installed"
fi

# ══════════════════════════════════════════════════════════════
# STEP 4 ── Ensure ~/.local/bin is on PATH (permanently)
# ══════════════════════════════════════════════════════════════
step "Updating PATH"

pipx ensurepath --quiet 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"   # also available right now in this session

# ══════════════════════════════════════════════════════════════
# STEP 5 ── Optional: Node.js check (for web dashboard)
# ══════════════════════════════════════════════════════════════
step "Checking optional dependencies"

if command -v node &>/dev/null && command -v npm &>/dev/null; then
    NODE_VER=$(node --version)
    NPM_VER=$(npm --version)
    success "Node.js $NODE_VER  /  npm $NPM_VER — Web Dashboard (-a) is available"
else
    warn "Node.js / npm not found."
    echo -e "  ${DIM}The CLI tool works without it, but the --app web dashboard requires Node.js 18+."
    echo -e "  Install: https://nodejs.org  or  brew install node${NC}"
fi

# ══════════════════════════════════════════════════════════════
# STEP 6 ── Verify
# ══════════════════════════════════════════════════════════════
step "Verifying installation"

if command -v "$TOOL_NAME" &>/dev/null; then
    VERSION=$("$TOOL_NAME" --version 2>/dev/null || echo "unknown")
    success "check-log $ACTION successfully!  ($VERSION)"
    echo -e "\n${BOLD}${GREEN}  ✓ Ready. Run:  check-log --help${NC}\n"
else
    # Installed but not yet on PATH in this shell
    warn "check-log was $ACTION but is not yet on your current PATH."
    echo -e "\n  ${YELLOW}Restart your terminal, or run:${NC}"
    echo -e "    ${CYAN}source ~/.bashrc${NC}   ${DIM}# (or ~/.zshrc if you use zsh)${NC}"
    echo -e "  Then verify with:  ${CYAN}check-log --help${NC}\n"
fi