#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=======================================${NC}"
echo -e "${CYAN}   Installing check-log CLI Tool...    ${NC}"
echo -e "${CYAN}=======================================${NC}"

if ! command -v pipx &> /dev/null; then
    echo -e "${RED}[!] Error: 'pipx' is not installed.${NC}"
    echo -e "Please install pipx first:"
    echo -e "  Ubuntu/Debian: ${YELLOW}sudo apt install pipx${NC}"
    echo -e "  macOS:         ${YELLOW}brew install pipx${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Downloading and compiling from GitHub...${NC}"
# Notice how we use the git+ URL here instead of a local directory!
if pipx install --force git+https://github.com/SkylerOnRadio/log-checker.git; then
    pipx ensurepath &> /dev/null
    echo -e "\n${GREEN}=======================================${NC}"
    echo -e "${GREEN}        INSTALLATION COMPLETE!         ${NC}"
    echo -e "${GREEN}=======================================${NC}"
    echo -e "\nTest the installation by running:"
    echo -e "  ${CYAN}check-log --help${NC}\n"
else
    echo -e "${RED}[!] Installation failed.${NC}"
    exit 1
fi