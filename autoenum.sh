#!/bin/bash
# autoenum.sh
# Autoenum - Automated Service Enumeration (Kali-Optimized, apt-only)
# Author: giveen
# GitHub: https://github.com/giveen/autoenum

set -euo pipefail

# === TMUX AUTO-LAUNCH ===
# If not already inside tmux, re-exec into a new named session so secondary
# scans can open their own windows that the user can switch between.
if [[ -z "${TMUX:-}" ]]; then
    # Kill any leftover autoenum session to avoid "duplicate session" failure
    tmux kill-session -t autoenum 2>/dev/null || true
    exec tmux new-session -s autoenum "$0" "$@"
fi
export AUTOENUM_SESSION
AUTOENUM_SESSION=$(tmux display-message -p '#S' 2>/dev/null || echo "autoenum")

# === CONFIGURATION ===
DIR=$(dirname "$(readlink -f "$0")")
export DIR
VERSION="3.0.3"

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NO_COLOR='\033[0m'

# === SIGNAL HANDLING ===
_kill_enum_windows() {
    local _all=(
        redis_enum snmp_enum rpc_enum pop3_enum imap_enum dns_enum
        ftp_enum ldap_enum smtp_enum oracle_enum smb_enum http_enum
        windows_enum linux_enum
    )
    local _sess="${AUTOENUM_SESSION:-autoenum}"
    for _w in "${_all[@]}"; do
        tmux kill-window -t "${_sess}:${_w}" 2>/dev/null || true
    done
}
export -f _kill_enum_windows

_autoenum_cleanup() {
    echo -e "\n${RED}[!] Interrupted — killing background processes and enum windows...${NO_COLOR}"
    _kill_enum_windows
    kill 0
}
trap '_autoenum_cleanup' SIGINT SIGTERM

# === FUNCTIONS ===
usage() {
    cat << EOF
Autoenum v$VERSION
Automated service enumeration for CTFs, HTB, VulnHub, OSCP, and real engagements.

Usage: $(basename "$0") [TARGET] [OPTIONS]

Arguments:
  TARGET              Target IP or hostname (optional; prompts if omitted)

Options:
  -nr, --no-resolve   Skip DNS resolution (use raw IP)
  -h, --help          Show this help
  -v, --version       Show version

Examples:
  $(basename "$0") 10.129.1.93
  $(basename "$0") 10.129.1.93 -nr
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
        -*)
            echo "Unknown option: $1"
            usage
            ;;
        *)
            # Treat bare positional as target IP/hostname
            export IP="$1"
            shift
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
# Clean up any enum windows left over from a previous session
_kill_enum_windows
if [[ -n "${NO_RESOLVE:-}" ]]; then
    tput setaf 2
    echo -en "\n[*] Autoenum set to noresolve mode"
    tput sgr0
    sleep 0.5
fi

# Only prompt interactively if no IP was supplied on the command line
if [[ -z "${IP:-}" ]]; then
    get_ip
fi
halp_meh
upgrade
menu
