#!/bin/bash
# scans.sh
# Autoenum - Enhanced Scan Engine (Kali-Optimized, Fast, Reliable)
# Author: giveen
# GitHub: https://github.com/giveen/autoenum

set -euo pipefail

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NO_COLOR='\033[0m'

# === FUNCTIONS ===

OS_guess() {
    # Get TTL value with error handling
    ttl=$(ping -c 1 -W 3 "$IP" 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2}' | awk '{print $1}')

    # If ping failed, try one fallback method
    if [[ -z "$ttl" ]]; then
        ttl=$(nmap -n -sn "$IP" 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2}' | head -1)
    fi

    # Simple TTL-based detection
    if [[ "$ttl" =~ ^(127|128)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Windows (TTL: $ttl)${NO_COLOR}"
        [[ -n "${loot:-}" ]] && echo "windows_ttl" > "$loot/raw/windows_found"
    elif [[ "$ttl" =~ ^(255|254)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Cisco/Solaris/OpenBSD (TTL: $ttl)${NO_COLOR}"
    elif [[ "$ttl" =~ ^(63|64)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Linux (TTL: $ttl)${NO_COLOR}"
        [[ -n "${loot:-}" ]] && echo "linux_ttl" > "$loot/raw/linux_found"
    else
        if [[ -n "$ttl" ]]; then
            echo -e "${YELLOW}[-] Unknown TTL value: $ttl${NO_COLOR}"
        else
            echo -e "${RED}[-] Could not determine OS (no response)${NO_COLOR}"
        fi
    fi
}

# Ensures $loot is set and the base directories exist.
# Called at the top of every function that uses $loot so they are safe
# whether invoked via the menu (where mkbasedirs already ran) or directly.
_ensure_loot() {
    if [[ -z "${loot:-}" ]]; then
        if [[ -z "${IP:-}" ]]; then
            echo -e "${RED}[-] \$IP is not set — cannot initialise loot directory.${NO_COLOR}" >&2
            return 1
        fi
        loot="$IP/autoenum/loot"
        echo -e "${YELLOW}[*] loot not set — defaulting to $loot${NO_COLOR}"
    fi
    mkdir -p "$loot/raw" "$loot/exploits"
}

# Check a services file for Windows-specific ports/OS and write the windows_found tag.
# Requires >= 2 common Windows ports open OR nmap OS detection confirming Windows.
# Usage: _tag_os_from_scan <services_file> [os_detection_file]
_tag_os_from_scan() {
    local services_file="${1:-}"
    local os_file="${2:-}"
    [[ -z "${loot:-}" ]] && return 0
    [[ ! -s "${services_file:-}" ]] && return 0

    local win_ports=(135 139 445 3389 5985 5986 593 88)
    local win_port_count=0
    for port in "${win_ports[@]}"; do
        if grep -q "^${port}/" "$services_file" 2>/dev/null; then
            win_port_count=$(( win_port_count + 1 ))
        fi
    done

    local os_says_windows=0
    if [[ -s "${os_file:-}" ]] && grep -qi "windows" "$os_file" 2>/dev/null; then
        os_says_windows=1
    fi

    if (( win_port_count >= 2 )) || (( os_says_windows )); then
        echo -e "${GREEN}[+] Windows target confirmed (${win_port_count} Windows ports) — enabling windows_enum${NO_COLOR}"
        echo "windows_confirmed" > "$loot/raw/windows_found"
        return 0
    fi

    # Linux detection: SSH open and no Windows OS fingerprint
    local os_says_linux=0
    if [[ -s "${os_file:-}" ]] && grep -qi "linux\|unix" "$os_file" 2>/dev/null; then
        os_says_linux=1
    fi
    local has_ssh=0
    if grep -qE "^22/|^2222/" "$services_file" 2>/dev/null; then
        has_ssh=1
    fi

    if (( has_ssh )) || (( os_says_linux )); then
        echo -e "${GREEN}[+] Linux target indicated (SSH present / OS fingerprint) — enabling linux_enum${NO_COLOR}"
        echo "linux_confirmed" > "$loot/raw/linux_found"
    fi
}

# Print a compact open-ports table from an nmap -oN output file.
_print_port_summary() {
    local scan_file="${1:-}"
    [[ ! -s "$scan_file" ]] && return 0
    local ports
    ports=$(grep -E "^[0-9]+/(tcp|udp).*open" "$scan_file" 2>/dev/null) || return 0
    [[ -z "$ports" ]] && return 0
    echo -e "${BOLD}${GREEN}  ┌─ Open Ports ─────────────────────────────────────────${NO_COLOR}"
    echo "$ports" | awk '{printf "  │  %-22s %-10s %s\n", $1, $2, $3}' \
        | while IFS= read -r line; do echo -e "${GREEN}${line}${NO_COLOR}"; done
    echo -e "${BOLD}${GREEN}  └───────────────────────────────────────────────────────${NO_COLOR}"
}

# Run searchsploit --nmap on an XML file, save results to loot, and print to screen.
# Usage: _run_searchsploit <xml_file> <label> <out_txt> <out_json>
_run_searchsploit() {
    local xml="$1" label="$2" out_txt="$3" out_json="$4"
    if [[ ! -s "$xml" ]]; then
        echo -e "${YELLOW}[-] SearchSploit: no XML output to analyse (${label})${NO_COLOR}"
        return 0
    fi
    echo -e "${CYAN}[+] Running SearchSploit on ${label} results...${NO_COLOR}"
    # Capture stdout+stderr so [i]/[-] info lines are preserved in the file and on screen
    searchsploit -j --nmap "$xml" > "$out_json" 2>/dev/null || true
    searchsploit --nmap "$xml" > "$out_txt" 2>&1 || true
    cat "$out_txt"
    echo -e "${CYAN}[+] SearchSploit results saved: ${out_txt}${NO_COLOR}"
}


# Write a self-contained scan script to a temp file and launch it in a new
# tmux window.  The script signals completion by touching a done-file.
# Usage: _launch_in_window <func> <label> <done_dir> <timeout>
_launch_in_window() {
    local func="$1" label="$2" done_dir="$3" timeout="$4"
    local _script
    _script=$(mktemp /tmp/ae-XXXX.sh)

    # Build script that sources the real libraries so all helpers are available
    cat > "$_script" << ENDSCRIPT
#!/bin/bash
set +euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NO_COLOR='\033[0m'

# Target and loot path from parent
export IP='$IP'
export loot='$loot'

# Source the libraries so all helpers / enum functions are available
source '${DIR}/functions/scans.sh'
source '${DIR}/functions/enum.sh'

echo -e "\${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NO_COLOR}"
echo -e "\${BOLD}\${CYAN}  $func  •  $IP\${NO_COLOR}"
echo -e "\${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NO_COLOR}"
echo ""

$func
_exit=\$?

touch '${done_dir}/${func}.done'

echo ""
echo -e "\${BOLD}\${GREEN}━━━  $func finished  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NO_COLOR}"
echo -e "    Loot: $loot"
echo -e "\${CYAN}  Window stays open — close with: prefix+& or exit\${NO_COLOR}"
exec \$SHELL
ENDSCRIPT

    chmod +x "$_script"

    # Open a new tmux window (don't switch focus: -d) running the scan script
    tmux new-window -d -n "$func" -- bash "$_script"

    echo -e "${GREEN}  [$(date '+%H:%M:%S')] ▶ ${func} (${label})  →  tmux window '${func}'${NO_COLOR}"
}

enum_goto() {
    local timeout="${1:-300}"
    _ensure_loot || return 1

    # ── Close any leftover enum windows from a previous run ───────────────────
    local _all_enum_windows=(
        redis_enum snmp_enum rpc_enum pop3_enum imap_enum dns_enum
        ftp_enum ldap_enum smtp_enum oracle_enum smb_enum http_enum
        windows_enum linux_enum
    )
    for _w in "${_all_enum_windows[@]}"; do
        tmux kill-window -t "${AUTOENUM_SESSION:-autoenum}:${_w}" 2>/dev/null || true
    done

    # Service mapping array (service_file:enum_function)
    local services=(
        "redis:redis_enum"
        "snmp:snmp_enum"
        "rpc:rpc_enum"
        "pop3:pop3_enum"
        "imap:imap_enum"
        "dns:dns_enum"
        "ftp:ftp_enum"
        "ldap:ldap_enum"
        "smtp:smtp_enum"
        "oracle:oracle_enum"
        "smb:smb_enum"
        "http:http_enum"
    )

    # OS-specific enumerations
    local os_services=(
        "windows:windows_enum"
        "linux:linux_enum"
    )

    # ── Discover what's available ─────────────────────────────────────────────
    local found_services=()
    local found_funcs=()
    local found_os_services=()
    local found_os_funcs=()

    for service in "${services[@]}"; do
        local file="${service%%:*}"
        local func="${service##*:}"
        if [[ -s "$loot/raw/${file}_found" ]]; then
            found_services+=("$file")
            found_funcs+=("$func")
        fi
    done

    for service in "${os_services[@]}"; do
        local file="${service%%:*}"
        local func="${service##*:}"
        if [[ -s "$loot/raw/${file}_found" ]]; then
            found_os_services+=("$file")
            found_os_funcs+=("$func")
        fi
    done

    # ── Header ────────────────────────────────────────────────────────────────
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════${NO_COLOR}"
    echo -e "${BOLD}${CYAN}  SECONDARY ENUMERATION — $(date '+%H:%M:%S')${NO_COLOR}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${NO_COLOR}"

    if (( ${#found_services[@]} == 0 )) && (( ${#found_os_services[@]} == 0 )); then
        echo -e "${YELLOW}  No enumerable services detected — skipping secondary scans${NO_COLOR}"
        find "$loot/raw" -type f -empty -delete 2>/dev/null
        return 0
    fi

    if (( ${#found_services[@]} > 0 )); then
        echo -e "${GREEN}  Services detected : ${found_services[*]}${NO_COLOR}"
    fi
    if (( ${#found_os_services[@]} > 0 )); then
        echo -e "${YELLOW}  OS-specific       : ${found_os_services[*]}${NO_COLOR}"
    fi
    echo -e "${CYAN}  Timeout per scan  : ${timeout}s${NO_COLOR}"
    echo -e "${CYAN}  tmux session      : ${AUTOENUM_SESSION:-autoenum}${NO_COLOR}"
    echo -e "${CYAN}  Switch windows    : prefix+w  or  prefix+[n]${NO_COLOR}"
    echo -e "${BOLD}${CYAN}──────────────────────────────────────────────────────${NO_COLOR}\n"

    # Shared done-file directory for completion tracking
    local _done_dir
    _done_dir=$(mktemp -d /tmp/ae-done-XXXX)

    local launched=()

    # ── Launch service enums — each in its own tmux window ────────────────────
    for i in "${!found_funcs[@]}"; do
        local file="${found_services[$i]}"
        local func="${found_funcs[$i]}"
        _launch_in_window "$func" "$file" "$_done_dir" "$timeout"
        launched+=("$func")
        sleep 0.2   # slight stagger to avoid simultaneous nmap startups
    done

    # ── Wait for all service enum windows to finish ───────────────────────────
    if (( ${#launched[@]} > 0 )); then
        local _deadline=$(( $(date +%s) + timeout + 30 ))
        local _spin_chars='|/-\'
        local _spin_i=0
        echo -e "${CYAN}  Waiting for service scans to finish (scans visible in tmux windows above)${NO_COLOR}"
        while true; do
            local _done_count
            _done_count=$(find "$_done_dir" -name "*.done" 2>/dev/null | wc -l)
            (( _done_count >= ${#launched[@]} )) && break
            (( $(date +%s) > _deadline )) && {
                echo -e "\n${YELLOW}  [!] Timed out waiting for service scans${NO_COLOR}"
                break
            }
            printf '\r  %s  %d / %d complete ...' "${_spin_chars:$(( _spin_i % ${#_spin_chars} )):1}" "$_done_count" "${#launched[@]}"
            (( _spin_i++ ))
            sleep 1
        done
        printf '\r%60s\r' ''  # clear spinner line
    fi

    # ── OS-specific enums — each in its own window, waited on in sequence ─────
    for i in "${!found_os_funcs[@]}"; do
        local file="${found_os_services[$i]}"
        local func="${found_os_funcs[$i]}"
        _launch_in_window "$func" "OS: $file" "$_done_dir" "$timeout"
        launched+=("$func")

        # Wait until this OS scan signals done (OS scans depend on service results)
        local _os_deadline=$(( $(date +%s) + timeout + 30 ))
        local _spin_i=0
        echo -e "${CYAN}  Waiting for ${func} to finish...${NO_COLOR}"
        while [[ ! -f "${_done_dir}/${func}.done" ]]; do
            (( $(date +%s) > _os_deadline )) && {
                echo -e "${YELLOW}  [!] ${func} timed out${NO_COLOR}"
                break
            }
            printf '\r  %s  running ...' "${_spin_chars:$(( _spin_i % ${#_spin_chars} )):1}"
            (( _spin_i++ ))
            sleep 1
        done
        printf '\r%60s\r' ''
    done

    # ── Summary ───────────────────────────────────────────────────────────────
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════${NO_COLOR}"
    echo -e "${BOLD}${GREEN}  ENUMERATION COMPLETE — $(date '+%H:%M:%S')${NO_COLOR}"
    if (( ${#launched[@]} > 0 )); then
        echo -e "${GREEN}  Scans run : ${launched[*]}${NO_COLOR}"
    fi
    echo -e "${CYAN}  Loot dir  : $loot${NO_COLOR}"
    echo -e "${CYAN}  Results in tmux windows — switch with: prefix+w${NO_COLOR}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${NO_COLOR}\n"

    # Cleanup
    rm -rf "$_done_dir"
    find "$loot/raw" -type f -empty -delete 2>/dev/null
}

# === SCAN FUNCTIONS ===

reg() {
    banner
    _ensure_loot || return 1
    OS_guess

    # Directory setup
    local scan_dir="$IP/autoenum/reg_scan"
    mkdir -p "$scan_dir/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    # Progress feedback
    (
        for i in {1..60}; do
            sleep 10
            echo -e "${CYAN}[+] Scan progress: $((i * 10)) seconds elapsed (reg scan)${NO_COLOR}"
        done
    ) &
    local _progress_pid=$!

    # Run scans in parallel
    (
        echo -e "${BLUE}[+] Scanning top 1000 ports${NO_COLOR}"
        nmap --top-ports 1000 -sV \
            --min-rate 500 \
            --max-retries 1 \
            --host-timeout 300s \
            --max-rtt-timeout 1000ms \
            "$IP" \
            -oN "$scan_dir/top_1k" \
            -oX "$scan_dir/raw/top_1k.xml" > /dev/null 2>&1
    ) &
    local _scan1_pid=$!

    (
        echo -e "${BLUE}[+] Running comprehensive scan${NO_COLOR}"
        nmap -p- -sV -O -T4 -Pn -v "$IP" \
            --min-rate 500 \
            --max-retries 1 \
            --host-timeout 300s \
            --max-rtt-timeout 1000ms \
            -oX "$scan_dir/raw/full_scan.xml" \
            -oN "$scan_dir/raw/full_scan" > /dev/null 2>&1
    ) &
    local _scan2_pid=$!

    # Wait only on the scan jobs — not the progress timer
    wait "$_scan1_pid" "$_scan2_pid"

    # Kill progress loop
    kill "$_progress_pid" 2>/dev/null || true

    # Process scan results
    process_scans() {
        # Extract services
        awk '/open/ && !/Discovered/ && !/\|/' "$scan_dir/raw/full_scan" > "$scan_dir/ports_and_services/services_running"

        # Extract OS detection
        sed -n '/OS details:/,/exact/p' "$scan_dir/raw/full_scan" | head -n -1 | tail -n +2 | cut -d '|' -f 1 > "$scan_dir/ports_and_services/OS_detection"

        # Extract script output
        sed -n '/PORT/,/exact/p' "$scan_dir/raw/full_scan" | sed '$d' > "$scan_dir/ports_and_services/script_output"

        # Searchsploit processing
        _run_searchsploit "$scan_dir/raw/full_scan.xml" "reg scan" \
            "$loot/exploits/searchsploit_nmap" "$loot/exploits/searchsploit_nmap.json"

        # Service-specific files
        local services=("http" "smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis" "rpc" "dns")
        for service in "${services[@]}"; do
            { grep "$service" "$scan_dir/ports_and_services/services_running" || true; } \
                | sort -u > "$loot/raw/${service}_found"
        done

        # Clean HTTP ports extraction
        awk -F'/' '/open.*http/ {print $1}' "$scan_dir/ports_and_services/services_running" | sort -u > "$loot/raw/http_found"

        # Tag Windows OS from port/OS-based detection
        _tag_os_from_scan "$scan_dir/ports_and_services/services_running" "$scan_dir/ports_and_services/OS_detection"
    }

    process_scans || true
    _print_port_summary "$scan_dir/raw/full_scan"

    enum_goto
}

aggr() {
    local timeout="${1:-300}"
    banner
    _ensure_loot || return 1
    OS_guess

    # Directory setup
    mkdir -p "$IP/autoenum/aggr_scan/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    # Progress feedback
    (
        for i in {1..60}; do
            sleep 10
            echo -e "${CYAN}[+] Scan progress: $((i * 10)) seconds elapsed (aggr scan, timeout: $timeout)${NO_COLOR}"
        done
    ) &
    local _progress_pid=$!

    # Run scans in parallel
    (
        tput setaf 6; echo "Checking top 1k ports..."; tput sgr0
        nmap --top-ports 1000 -sV \
            --min-rate 500 \
            --max-retries 1 \
            --host-timeout "${timeout}s" \
            --max-rtt-timeout 1000ms \
            "$IP" \
            -oN "$IP/autoenum/aggr_scan/top_1k" > /dev/null 2>&1
    ) &
    local _aggr1_pid=$!

    (
        tput setaf 6; echo "Starting aggressive scan..."; tput sgr0
        nmap -n -A -T4 -p- \
            --min-rate 500 \
            --max-retries 1 \
            --host-timeout "${timeout}s" \
            --max-rtt-timeout 1000ms \
            -Pn -v "$IP" \
            -oX "$IP/autoenum/aggr_scan/raw/xml_out" \
            -oN "$IP/autoenum/aggr_scan/raw/full_scan" > /dev/null 2>&1

        # Wait for XML file to fully write
        while [[ ! -s "$IP/autoenum/aggr_scan/raw/xml_out" ]]; do
            sleep 1
        done

        # Run searchsploit on XML output
        _run_searchsploit "$IP/autoenum/aggr_scan/raw/xml_out" "aggr scan" \
            "$loot/exploits/aggr_searchsploit_nmap" "$loot/exploits/aggr_searchsploit_nmap.json"
    ) &
    local _aggr2_pid=$!

    # Extract open ports and services
    (
        # Poll until full_scan exists and has content rather than using a fixed sleep
        local _waited=0
        while [[ ! -s "$IP/autoenum/aggr_scan/raw/full_scan" ]] && (( _waited < 60 )); do
            sleep 1
            (( _waited++ ))
        done
        awk '/open/ && !/Discovered/ && !/\|/' "$IP/autoenum/aggr_scan/raw/full_scan" > "$IP/autoenum/aggr_scan/ports_and_services/services_running"

        # OS detection
        sed -n '/OS details:/,/exact/p' "$IP/autoenum/aggr_scan/raw/full_scan" | head -n -1 | tail -n +2 | cut -d '|' -f 1 > "$IP/autoenum/aggr_scan/ports_and_services/OS_detection"

        # Script output
        sed -n '/PORT/,/exact/p' "$IP/autoenum/aggr_scan/raw/full_scan" | sed '$d' > "$IP/autoenum/aggr_scan/ports_and_services/script_output"
    ) &
    local _extract1_pid=$!

    # Service-specific processing
    (
        # Poll until services_running exists
        local _waited=0
        while [[ ! -s "$IP/autoenum/aggr_scan/ports_and_services/services_running" ]] && (( _waited < 90 )); do
            sleep 1
            (( _waited++ ))
        done
        awk -F'/' '/http/ {print $1}' "$IP/autoenum/aggr_scan/ports_and_services/services_running" | sort -u > "$loot/raw/http_found"

        services=("smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis" "rpc" "dns")
        for service in "${services[@]}"; do
            { grep "$service" "$IP/autoenum/aggr_scan/ports_and_services/services_running" || true; } \
                | sort -u > "$loot/raw/${service}_found"
        done
    ) &
    local _extract2_pid=$!

    # Wait only on the scan/extract jobs — not the progress timer
    wait "$_aggr1_pid" "$_aggr2_pid" "$_extract1_pid" "$_extract2_pid"

    # Kill progress loop
    kill "$_progress_pid" 2>/dev/null || true

    # Tag Windows OS from port-based detection
    _tag_os_from_scan "$IP/autoenum/aggr_scan/ports_and_services/services_running"
    _print_port_summary "$IP/autoenum/aggr_scan/raw/full_scan"

    enum_goto "$timeout"
}

top_1k() {
    banner
    _ensure_loot || return 1
    OS_guess

    # Directory setup
    mkdir -p "$IP/autoenum/top_1k/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"
    t1k="$IP/autoenum/top_1k"

    # Progress feedback
    (
        for i in {1..60}; do
            sleep 10
            echo -e "${CYAN}[+] Scan progress: $((i * 10)) seconds elapsed (top 1k)${NO_COLOR}"
        done
    ) &
    local _progress_pid=$!

    # 1. Run Nmap scans
    echo -e "${YELLOW}[+] Scanning top 1k ports${NO_COLOR}"
    nmap --top-ports 1000 -sV \
        --min-rate 500 \
        --max-retries 1 \
        --host-timeout 300s \
        --max-rtt-timeout 1000ms \
        -oX "$t1k/raw/xml_out" \
        -oN "$t1k/ports_and_services/services" "$IP" > /dev/null 2>&1

    # 2. Validate XML before SearchSploit
    _run_searchsploit "$t1k/raw/xml_out" "top 1k scan" \
        "$loot/exploits/top_1k_searchsploit_nmap" "$loot/exploits/top_1k_searchsploit_nmap.json"

    # 3. Process services
    awk -F'/' '/open.*http/ {print $1}' "$t1k/ports_and_services/services" | sort -u > "$loot/raw/http_found"

    services=("smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis" "rpc" "dns")
    for service in "${services[@]}"; do
        { grep "$service" "$t1k/ports_and_services/services" || true; } \
            | sort -u > "$loot/raw/${service}_found"
    done

    # Tag Windows OS from port-based detection
    _tag_os_from_scan "$t1k/ports_and_services/services"
    _print_port_summary "$t1k/ports_and_services/services"

    # Kill progress loop
    kill "$_progress_pid" 2>/dev/null || true

    enum_goto
}

top_10k() {
    banner
    _ensure_loot || return 1
    OS_guess

    # Directory setup
    local scan_dir="$IP/autoenum/top_10k"
    mkdir -p "$scan_dir/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    # Progress feedback
    (
        for i in {1..60}; do
            sleep 10
            echo -e "${CYAN}[+] Scan progress: $((i * 10)) seconds elapsed (top 10k)${NO_COLOR}"
        done
    ) &
    local _progress_pid=$!

    echo -e "${YELLOW}[+] Starting top 10k port scan${NO_COLOR}"

    # Single combined scan: service detection + scripts + both output formats
    nmap --top-ports 10000 -sV -sC \
        --min-rate 500 \
        --max-retries 1 \
        --host-timeout 300s \
        --max-rtt-timeout 1000ms \
        "$IP" \
        -oN "$scan_dir/raw/services" \
        -oX "$scan_dir/raw/xml_out" > /dev/null 2>&1

    # Kill progress loop
    kill "$_progress_pid" 2>/dev/null || true

    # Process results
    process_results() {
        # SearchSploit processing
        _run_searchsploit "$scan_dir/raw/xml_out" "top 10k scan" \
            "$loot/exploits/top_10k_searchsploit_nmap" "$loot/exploits/top_10k_searchsploit_nmap.json"

        # Extract open ports
        { grep 'open' "$scan_dir/raw/services" || true; } > "$scan_dir/ports_and_services/services"

        # Service-specific files
        local services=(
            "smb" "snmp" "ftp" "ldap"
            "smtp" "oracle" "pop3" "imap"
            "redis" "dns" "rpc"
        )

        # Special handling for HTTP services
        awk -F'/' '/open/ && /http/ {print $1}' "$scan_dir/ports_and_services/services" | sort -u > "$loot/raw/http_found"

        # Process other services
        for service in "${services[@]}"; do
            awk -F'/' '/open/ && /'"$service"'/ {print $1}' "$scan_dir/ports_and_services/services" |
            sort -u > "$loot/raw/${service}_found"
        done

        # Cleanup empty files
        find "$loot/raw" -type f -empty -delete 2>/dev/null

        # Tag Windows OS from port-based detection
        _tag_os_from_scan "$scan_dir/ports_and_services/services"
        _print_port_summary "$scan_dir/ports_and_services/services"
        echo -e "${GREEN}[+] Scan results processed and saved${NO_COLOR}"
    }

    process_results || true

    enum_goto
}

udp() {
    banner
    _ensure_loot || return 1
    OS_guess

    # Directory setup
    mkdir -p "$IP/autoenum/udp/"{raw,ports_and_services} "$loot/raw"
    udp_dir="$IP/autoenum/udp"

    echo -e "${YELLOW}[+] Starting UDP scan (Top 100 ports)${NO_COLOR}"

    # Scan top 100 UDP ports with version detection
    nmap -sU -sV --top-ports 100 \
        --min-rate 500 \
        --max-retries 1 \
        --host-timeout 300s \
        --max-rtt-timeout 1000ms \
        -T4 "$IP" \
        -oN "$udp_dir/scan" \
        -oX "$udp_dir/raw/xml_out" > /dev/null 2>&1

    # Extract open ports
    { grep "open/udp" "$udp_dir/scan" || true; } | awk '{print $1}' | cut -d'/' -f1 > "$udp_dir/ports_and_services/open_ports"

    # Service-specific processing
    if [[ -s "$udp_dir/ports_and_services/open_ports" ]]; then
        echo -e "${GREEN}[+] Found open UDP ports: $(tr '\n' ' ' < "$udp_dir/ports_and_services/open_ports")${NO_COLOR}"
        _print_port_summary "$udp_dir/scan"

        # Common UDP services check
        services=("snmp" "ntp" "dns" "dhcp" "tftp")
        for service in "${services[@]}"; do
            { grep -i "$service" "$udp_dir/scan" || true; } | sort -u > "$loot/raw/udp_${service}_found"
        done

        # Special checks for SNMP
        if grep -q "161/udp" "$udp_dir/ports_and_services/open_ports"; then
            echo -e "${YELLOW}[+] Running SNMP checks...${NO_COLOR}"
            snmp-check "$IP" -c public >> "$udp_dir/snmp_check" 2>&1
            onesixtyone "$IP" >> "$udp_dir/onesixtyone" 2>&1
        fi
    else
        echo -e "${RED}[-] No open UDP ports found${NO_COLOR}"
    fi

    echo -e "${GREEN}[+] UDP scan completed${NO_COLOR}"
}

vuln() {
    _ensure_loot || return 1
    mkdir -p "$loot/exploits/vulns"
    vulns="$loot/exploits/vulns"
    cwd=$(pwd)

    # Check if vulscan is already installed
    if [[ ! -d "$HOME/.local/share/nmap/scripts/vulscan" ]]; then
        echo -e "${YELLOW}[+] Installing vulscan in user space...${NO_COLOR}"
        mkdir -p "$HOME/.local/share/nmap/scripts"
        git clone https://github.com/scipag/vulscan.git "$HOME/.local/share/nmap/scripts/vulscan" 2>/dev/null || {
            echo -e "${RED}[-] Failed to clone vulscan repository${NO_COLOR}"
            return 1
        }
    fi

    # First scan: vulscan
    if [[ -d "$HOME/.local/share/nmap/scripts/vulscan" ]]; then
        echo -e "${YELLOW}[+] Running vulscan...${NO_COLOR}"
        nmap -sV --script="$HOME/.local/share/nmap/scripts/vulscan/vulscan.nse" \
            --host-timeout 300s \
            "$IP" | tee -a "$vulns/vulscan" || {
            echo -e "${RED}[-] vulscan failed${NO_COLOR}"
        }
    fi

    # Second scan: standard Nmap vuln scripts
    echo -e "${YELLOW}[+] Running Nmap vuln scripts...${NO_COLOR}"
    nmap -Pn --script vuln \
        --host-timeout 300s \
        "$IP" | tee -a "$vulns/vuln" || {
        echo -e "${RED}[-] Nmap vuln scan failed${NO_COLOR}"
    }

    cd "$cwd" || return
}
