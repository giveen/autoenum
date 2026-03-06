#!/bin/bash
# autoenum.sh
# Autoenum - Automated Service Enumeration (Kali-Optimized, apt-only)
# Author: giveen
# GitHub: https://github.com/giveen/autoenum

set -euo pipefail

# === CONFIGURATION ===
DIR=$(dirname "$(readlink -f "$0")")
VERSION="3.0.3"

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NO_COLOR='\033[0m'

# === FUNCTIONS ===
usage() {
    cat << EOF
Autoenum v$VERSION
Automated service enumeration for CTFs, HTB, VulnHub, OSCP, and real engagements.

Usage: $(basename "$0") [OPTIONS]

Options:
  -nr, --no-resolve   Skip DNS resolution (use raw IP)
  -h, --help          Show this help
  -v, --version       Show version

Example:
  $(basename "$0") -nr
EOF
    exit 0
}

# === MAIN EXECUTION ===

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -nr|--no-resolve)
            export NO_RESOLVE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        -v|--version)
            echo "Autoenum v$VERSION"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# === CHECK DEPENDENCIES ===
if ! bash "$DIR/functions/check_deps.sh" --quiet; then
    echo -e "\n${RED}❌ Dependency check failed. Exiting.${NO_COLOR}"
    exit 1
fi

# === SOURCE LIBRARIES ===
source "$DIR/functions/banner.sh"
source "$DIR/functions/upgrade.sh"
source "$DIR/functions/scans.sh"
source "$DIR/functions/enum.sh"
source "$DIR/functions/help_general.sh"
source "$DIR/functions/menu.sh"

# === START ===
clear
banner
if [[ -n "$NO_RESOLVE" ]]; then
    tput setaf 2
    echo -en "\n[*] Autoenum set to noresolve mode"
    tput sgr0
    sleep 0.5
fi

get_ip
halp_meh
upgrade
menu
