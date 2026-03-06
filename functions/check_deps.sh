#!/bin/bash
# functions/check_deps.sh
# Lightweight, Kali/Debian-only dependency checker using apt

set -euo pipefail

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NO_COLOR='\033[0m'

# === Tools to check (all available via apt in Kali/Debian) ===
declare -a REQUIRED_TOOLS=(
    "nmap"
    "gobuster"
    "nikto"
    "wafw00f"
    "ffuf"
    "dirb"
    "whatweb"
    "dnsrecon"
    "dnsenum"
    "masscan"
    "curl"
    "wget"
    "python3"
    "pip3"
    "nxc"
)

# === Data packages checked by directory/file presence rather than command -v ===
# Format: "apt_package_name:path_to_check"
declare -a REQUIRED_DATA_PACKAGES=(
    "seclists:/usr/share/seclists"
)

# === Helper Functions ===

log() {
    local level="$1"; shift
    local msg="$*"
    [[ "${QUIET:-}" == "1" ]] && return 0
    echo -e "${BOLD}${level}${msg}${NO_COLOR}" >&2
}

info() { log "${GREEN}INFO: ${NO_COLOR}" "$@"; }
warn() { log "${YELLOW}WARN: ${NO_COLOR}" "$@"; }
error() { log "${RED}ERROR: ${NO_COLOR}" "$@"; }
success() { log "${GREEN}✅ ${NO_COLOR}" "$@"; }

# === Check if apt is available ===
check_apt() {
    if ! command -v apt &> /dev/null; then
        error "apt not found. This tool requires a Debian-based system."
        exit 1
    fi
}

# === Install missing tools via apt ===
install_missing_tools() {
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        info "All required tools are installed."
        return 0
    fi

    info "Installing missing tools: ${missing[*]}..."

    # Update package list
    if ! sudo apt update &> /dev/null; then
        error "Failed to update package list. Check your internet connection."
        exit 1
    fi

    # Install all missing tools
    if ! sudo apt install -y "${missing[@]}"; then
        error "Failed to install some tools. Check your internet connection or try again."
        exit 1
    fi

    success "All tools installed successfully!"
}

# === Install missing data packages (checked by path, not command) ===
install_missing_data_packages() {
    local missing=()
    for entry in "${REQUIRED_DATA_PACKAGES[@]}"; do
        local pkg="${entry%%:*}"
        local path="${entry##*:}"
        if [[ ! -e "$path" ]]; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        info "All required data packages are present."
        return 0
    fi

    info "Installing missing data packages: ${missing[*]}..."

    if ! sudo apt install -y "${missing[@]}"; then
        error "Failed to install some data packages. Check your internet connection or try again."
        exit 1
    fi

    success "All data packages installed successfully!"
}

# === MAIN ===

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --quiet|-q) QUIET=1 ;;
    esac
done

# Check for apt
check_apt

# Check and install missing tools
install_missing_tools

# Check and install missing data packages
install_missing_data_packages

exit 0
