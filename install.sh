#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  check-log  |  Local Installer
#  Usage: bash install.sh
#  Run from the root of the cloned repository.
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

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
echo -e "${NC}${DIM}  Local Installer  ·  check-log${NC}\n"

# ══════════════════════════════════════════════════════════════
# STEP 1 ── Confirm we're running from the repo root
# ══════════════════════════════════════════════════════════════
step "Locating package"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# Check for a pyproject.toml or setup.py so we fail clearly if run from the wrong place
if [[ ! -f "$SCRIPT_DIR/pyproject.toml" && ! -f "$SCRIPT_DIR/setup.py" ]]; then
    die "No pyproject.toml or setup.py found in $SCRIPT_DIR\n  Make sure you're running this from the root of the cloned repository."
fi

success "Package found at: $SCRIPT_DIR"

# ══════════════════════════════════════════════════════════════
# STEP 2 ── Python version check
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
# STEP 3 ── pipx: install if missing
# ══════════════════════════════════════════════════════════════
step "Checking pipx"

install_pipx() {
    info "pipx not found — installing automatically..."

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
        info "Detected yum — falling back to pip install"
        sudo yum install -y python3-pip 2>/dev/null || true
        "$PYTHON" -m pip install --user pipx --quiet || true
    fi

    # Final pip fallback
    if ! command -v pipx &>/dev/null; then
        info "Falling back to: $PYTHON -m pip install --user pipx"
        "$PYTHON" -m pip install --user pipx --quiet \
            || die "Could not install pipx.\n  Try manually: sudo apt install pipx  or  brew install pipx"
        export PATH="$HOME/.local/bin:$PATH"
    fi

    command -v pipx &>/dev/null \
        || die "pipx still not found after install.\n  Run: export PATH=\"\$HOME/.local/bin:\$PATH\"  then try again."
}

if command -v pipx &>/dev/null; then
    success "pipx is already installed  ($(pipx --version))"
else
    install_pipx
    success "pipx installed successfully  ($(pipx --version))"
fi

# ══════════════════════════════════════════════════════════════
# STEP 4 ── Install or upgrade check-log from local source
# ══════════════════════════════════════════════════════════════
step "Installing $TOOL_NAME"

if pipx list 2>/dev/null | grep -q "$TOOL_NAME"; then
    warn "$TOOL_NAME is already installed — reinstalling from local source..."
    pipx install --force "$SCRIPT_DIR" --pip-args="--quiet" \
        || die "Reinstallation failed. Try: pipx uninstall $TOOL_NAME && bash install.sh"
    ACTION="reinstalled"
else
    info "Building and isolating package from local source..."
    pipx install "$SCRIPT_DIR" --pip-args="--quiet" \
        || die "Installation failed.\n\n  Debug with: pipx install $SCRIPT_DIR (no --quiet)"
    ACTION="installed"
fi

# ══════════════════════════════════════════════════════════════
# STEP 5 ── Ensure ~/.local/bin is on PATH (permanently)
# ══════════════════════════════════════════════════════════════
step "Updating PATH"

pipx ensurepath --quiet 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"   # available right now in this session

# ══════════════════════════════════════════════════════════════
# STEP 6 ── Optional: Node.js check (for web dashboard)
# ══════════════════════════════════════════════════════════════
step "Checking optional dependencies"

if command -v node &>/dev/null && command -v npm &>/dev/null; then
    NODE_VER=$(node --version)
    NPM_VER=$(npm --version)
    success "Node.js $NODE_VER  /  npm $NPM_VER — Web Dashboard (-a) is available"
else
    warn "Node.js / npm not found."
    echo -e "  ${DIM}The CLI works without it, but the --app web dashboard requires Node.js 18+."
    echo -e "  Install: https://nodejs.org  or  brew install node${NC}"
fi

# ══════════════════════════════════════════════════════════════
# STEP 7 ── Verify
# ══════════════════════════════════════════════════════════════
step "Verifying installation"

if command -v "$TOOL_NAME" &>/dev/null; then
    VERSION=$("$TOOL_NAME" --version 2>/dev/null || echo "unknown")
    success "check-log $ACTION successfully!  ($VERSION)"
    echo -e "\n${BOLD}${GREEN}  ✓ Ready. Run:  check-log --help${NC}\n"
else
    warn "check-log was $ACTION but is not yet on your current PATH."
    echo -e "\n  ${YELLOW}Restart your terminal, or run:${NC}"
    echo -e "    ${CYAN}source ~/.bashrc${NC}   ${DIM}# (or ~/.zshrc if you use zsh)${NC}"
    echo -e "  Then verify with:  ${CYAN}check-log --help${NC}\n"
fi