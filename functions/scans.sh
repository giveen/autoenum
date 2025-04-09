#!/bin/bash

OS_guess() {
    # Get TTL value with error handling
    ttl=$(ping -c 1 -W 3 "$IP" 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2}' | awk '{print $1}')
    
    # If ping failed, try one fallback method
    if [[ -z "$ttl" ]]; then
        ttl=$(nmap -n -sn "$IP" 2>/dev/null | awk -F'ttl=' '/ttl=/{print $2}' | head -1)
    fi

    # Simple TTL-based detection (your original logic)
    if [[ "$ttl" =~ ^(127|128)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Windows (TTL: $ttl)${NC}"
    elif [[ "$ttl" =~ ^(255|254)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Cisco/Solaris/OpenBSD (TTL: $ttl)${NC}"
    elif [[ "$ttl" =~ ^(63|64)$ ]]; then
        echo -e "${GREEN}[+] This machine is probably running Linux (TTL: $ttl)${NC}"
    else
        if [[ -n "$ttl" ]]; then
            echo -e "${YELLOW}[-] Unknown TTL value: $ttl${NC}"
        else
            echo -e "${RED}[-] Could not determine OS (no response)${NC}"
        fi
    fi
}

enum_goto() {
    # Configuration
    local MAX_PARALLEL=4  # Optimal for most systems
    local running=0
    
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

    # OS-specific enumerations (will run sequentially after services)
    local os_services=(
        "windows:windows_enum"
        "linux:linux_enum"
    )

    echo -e "${CYAN}[+] Starting service enumeration with parallel execution${NC}"
    
    # Process regular services with parallel job control
    for service in "${services[@]}"; do
        local file="${service%%:*}"
        local func="${service##*:}"
        
        if [[ -s "$loot/raw/${file}_found" ]]; then
            # Wait if we've reached max parallel processes
            while (( running >= MAX_PARALLEL )); do
                wait -n
                ((running--))
            done
            
            echo -e "${GREEN}[+] Found $file - launching $func${NC}"
            ($func || echo -e "${RED}[-] $func failed${NC}") &
            ((running++))
        fi
    done

    # Wait for all service enumerations to complete
    wait
    
    # Process OS-specific enumerations (sequential)
    for service in "${os_services[@]}"; do
        local file="${service%%:*}"
        local func="${service##*:}"
        
        if [[ -s "$loot/raw/${file}_found" ]]; then
            echo -e "${YELLOW}[+] Running OS-specific enumeration: $func${NC}"
            $func || echo -e "${RED}[-] $func failed${NC}"
        fi
    done

    # Cleanup empty files
    find "$loot/raw" -type f -empty -delete 2>/dev/null
    
    echo -e "${CYAN}[+] Enumeration complete${NC}"
}

reg() {
    banner
    upgrade
    OS_guess

    # Directory setup
    local scan_dir="$IP/autoenum/reg_scan"
    mkdir -p "$scan_dir/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    # Run scans in parallel
    (
        echo -e "${BLUE}[+] Scanning top 1000 ports${NC}"
        nmap --top-ports 1000 -sV "$IP" -oN "$scan_dir/top_1k" -oX "$scan_dir/raw/top_1k.xml"
    ) &

    (
        echo -e "${BLUE}[+] Running comprehensive scan${NC}"
        nmap -p- -sV -O -T4 -Pn -v "$IP" -oX "$scan_dir/raw/full_scan.xml" -oN "$scan_dir/raw/full_scan"
    ) &

    wait

    # Process scan results
    process_scans() {
        # Extract services
        awk '/open/ && !/Discovered/ && !/\|/' "$scan_dir/raw/full_scan" > "$scan_dir/ports_and_services/services_running"

        # Extract OS detection
        sed -n '/OS details:/,/exact/p' "$scan_dir/raw/full_scan" | head -n -1 | tail -n +2 | cut -d '|' -f 1 > "$scan_dir/ports_and_services/OS_detection"

        # Extract script output
        sed -n '/PORT/,/exact/p' "$scan_dir/raw/full_scan" | sed '$d' > "$scan_dir/ports_and_services/script_output"

        # Searchsploit processing
        if [[ -s "$scan_dir/raw/full_scan.xml" ]]; then
            searchsploit -j --nmap "$scan_dir/raw/full_scan.xml" > "$loot/exploits/searchsploit_nmap.json"
            searchsploit --nmap "$scan_dir/raw/full_scan.xml" > "$loot/exploits/searchsploit_nmap"
        fi

        # Service-specific files
        local services=("http" "smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis")
        for service in "${services[@]}"; do
            grep "$service" "$scan_dir/ports_and_services/services_running" | sort -u > "$loot/raw/${service}_found"
        done

        # Clean HTTP ports extraction
        awk -F'/' '/open.*http/ {print $1}' "$scan_dir/ports_and_services/services_running" | sort -u > "$loot/raw/http_found"
    }

    process_scans

    enum_goto
}

aggr() {
    banner
    upgrade
    OS_guess

    # Directory setup
    mkdir -p "$IP/autoenum/aggr_scan/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    # Parallel scan execution
    (
        tput setaf 6; echo "Checking top 1k ports..."; tput sgr0
        nmap --top-ports 1000 -sV "$IP" -oN "$IP/autoenum/aggr_scan/top_1k" &
    ) &

    (
        tput setaf 6; echo "Starting aggressive scan..."; tput sgr0
        nmap -n -A -T4 -p- --max-retries 1 -Pn -v "$IP" -oX "$IP/autoenum/aggr_scan/raw/xml_out" -oN "$IP/autoenum/aggr_scan/raw/full_scan"
        
        # Wait for XML file to fully write
        while [[ ! -s "$IP/autoenum/aggr_scan/raw/xml_out" ]]; do
            sleep 1
        done

        # Try XML parsing first, fall back to text if it fails
        if searchsploit -j --nmap "$IP/autoenum/aggr_scan/raw/xml_out" > "$loot/exploits/aggr_searchsploit_nmap.json" 2>/dev/null; then
            searchsploit --nmap "$IP/autoenum/aggr_scan/raw/xml_out" | tee "$loot/exploits/aggr_searchsploit_nmap"
        else
            echo -e "${RED}[-] XML parsing failed. Falling back to text-based exploit matching.${NC}"
            grep -Eo "([0-9]{1,5}/tcp|udp).*open" "$IP/autoenum/aggr_scan/raw/full_scan" | \
            while read -r service; do
                searchsploit "$(echo "$service" | awk '{print $3}')" | grep -v "No Results" >> "$loot/exploits/aggr_searchsploit_nmap"
            done
        fi
    ) &

    # Extract open ports and services
    (
        sleep 5  # Wait for full_scan to populate
        awk '/open/ && !/Discovered/ && !/\|/' "$IP/autoenum/aggr_scan/raw/full_scan" > "$IP/autoenum/aggr_scan/ports_and_services/services_running"

        # OS detection
        sed -n '/OS details:/,/exact/p' "$IP/autoenum/aggr_scan/raw/full_scan" | head -n -1 | tail -n +2 | cut -d '|' -f 1 > "$IP/autoenum/aggr_scan/ports_and_services/OS_detection"

        # Script output
        sed -n '/PORT/,/exact/p' "$IP/autoenum/aggr_scan/raw/full_scan" | sed '$d' > "$IP/autoenum/aggr_scan/ports_and_services/script_output"
    ) &

    # Service-specific processing
    (
        sleep 5  # Ensure services_running exists
        awk -F'/' '/http/ {print $1}' "$IP/autoenum/aggr_scan/ports_and_services/services_running" | sort -u > "$loot/raw/http_found"

        services=("smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis")
        for service in "${services[@]}"; do
            grep "$service" "$IP/autoenum/aggr_scan/ports_and_services/services_running" | sort -u > "$loot/raw/${service}_found"
        done
    ) &

    wait
    enum_goto
}

top_1k() {
    banner
    upgrade
    OS_guess

    # Directory setup
    mkdir -p "$IP/autoenum/top_1k/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"
    t1k="$IP/autoenum/top_1k"

    # 1. Run Nmap scans
    echo -e "${YELLOW}[+] Scanning top 1k ports${NC}"
    nmap --top-ports 1000 -sV -oX "$t1k/raw/xml_out" -oN "$t1k/ports_and_services/services" "$IP"

    # 2. Validate XML before SearchSploit
    if [[ -s "$t1k/raw/xml_out" ]] && grep -q "<nmaprun" "$t1k/raw/xml_out"; then
        echo -e "${YELLOW}[+] Running SearchSploit (XML mode)${NC}"
        searchsploit -v --xml "$t1k/raw/xml_out" > "$loot/exploits/top_1k_searchsploit_nmap.json" 2>&1
        
        # Fallback if XML parsing fails
        if grep -q "parser error" "$loot/exploits/top_1k_searchsploit_nmap.json"; then
            echo -e "${RED}[-] XML parsing failed, switching to text mode${NC}"
            searchsploit --nmap "$t1k/ports_and_services/services" > "$loot/exploits/top_1k_searchsploit_nmap"
        fi
    else
        echo -e "${RED}[-] Invalid XML, using text output${NC}"
        searchsploit --nmap "$t1k/ports_and_services/services" > "$loot/exploits/top_1k_searchsploit_nmap"
    fi

    # 3. Process services (your existing code)
    awk -F'/' '/open.*http/ {print $1}' "$t1k/ports_and_services/services" | sort -u > "$loot/raw/http_found"
    
    services=("smb" "snmp" "ftp" "ldap" "smtp" "imap" "pop3" "oracle" "redis")
    for service in "${services[@]}"; do
        grep "$service" "$t1k/ports_and_services/services" | sort -u > "$loot/raw/${service}_found"
    done

    enum_goto
}

top_10k() {
    banner
    upgrade
    OS_guess

    # Directory setup
    local scan_dir="$IP/autoenum/top_10k"
    mkdir -p "$scan_dir/"{raw,ports_and_services} "$loot/raw" "$loot/exploits"

    echo -e "${YELLOW}[+] Starting top 10k port scan with parallel execution${NC}"

    # Run scans in parallel with performance optimizations
    (
        echo -e "${BLUE}[+] Running service detection scan (min-rate 500)${NC}"
        nmap --top-ports 10000 -sV -Pn --max-retries 1 --min-rate 500 "$IP" -oN "$scan_dir/raw/services"
    ) &

    (
        echo -e "${BLUE}[+] Running script scan (max-parallelism 100)${NC}"
        nmap --top-ports 10000 -sC -Pn --max-retries 1 --max-parallelism 100 "$IP" -oN "$scan_dir/raw/scripts"
    ) &

    (
        echo -e "${BLUE}[+] Generating XML output (min-rate 250)${NC}"
        nmap --top-ports 10000 -sV -Pn --max-retries 1 --min-rate 250 "$IP" -oX "$scan_dir/raw/xml_out"
    ) &

    wait

    # Process results
    process_results() {
        # SearchSploit processing
        if [[ -s "$scan_dir/raw/xml_out" ]]; then
            echo -e "${CYAN}[+] Running SearchSploit analysis${NC}"
            searchsploit -j --nmap "$scan_dir/raw/xml_out" > "$loot/exploits/top_10k_searchsploit_nmap.json"
            searchsploit --nmap "$scan_dir/raw/xml_out" > "$loot/exploits/top_10k_searchsploit_nmap"
        else
            echo -e "${RED}[-] XML output missing or empty - skipping SearchSploit${NC}"
        fi

        # Extract open ports
        grep 'open' "$scan_dir/raw/services" > "$scan_dir/ports_and_services/services"

        # Service-specific files with improved HTTP detection
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
        echo -e "${GREEN}[+] Scan results processed and saved${NC}"
    }

    process_results

    enum_goto
}

udp() {
    banner
    upgrade
    OS_guess
    
    # Directory setup
    mkdir -p "$IP/autoenum/udp/"{raw,ports_and_services} "$loot/raw"
    udp_dir="$IP/autoenum/udp"
    
    echo -e "${YELLOW}[+] Starting UDP scan (Top 100 ports)${NC}"
    
    # Scan top 100 UDP ports with version detection
    nmap -sU -sV --top-ports 100 --max-retries 1 -T4 "$IP" -oN "$udp_dir/scan" -oX "$udp_dir/raw/xml_out" 2>&1 | tee -a "$udp_dir/scan"
    
    # Extract open ports
    grep "open/udp" "$udp_dir/scan" | awk '{print $1}' | cut -d'/' -f1 > "$udp_dir/ports_and_services/open_ports"
    
    # Service-specific processing
    if [[ -s "$udp_dir/ports_and_services/open_ports" ]]; then
        echo -e "${GREEN}[+] Found open UDP ports: $(tr '\n' ' ' < "$udp_dir/ports_and_services/open_ports")${NC}"
        
        # Common UDP services check
        services=("snmp" "ntp" "dns" "dhcp" "tftp")
        for service in "${services[@]}"; do
            grep -i "$service" "$udp_dir/scan" | sort -u > "$loot/raw/udp_${service}_found"
        done
        
        # Special checks for SNMP
        if grep -q "161/udp" "$udp_dir/ports_and_services/open_ports"; then
            echo -e "${YELLOW}[+] Running SNMP checks...${NC}"
            snmp-check "$IP" -c public >> "$udp_dir/snmp_check" 2>&1
            onesixtyone "$IP" >> "$udp_dir/onesixtyone" 2>&1
        fi
    else
        echo -e "${RED}[-] No open UDP ports found${NC}"
    fi
    
    echo -e "${GREEN}[+] UDP scan completed${NC}"
}

vuln() {
    mkdir -p "$loot/exploits/vulns"
    vulns="$loot/exploits/vulns"
    cwd=$(pwd)

    # Check if vulscan is already installed in user space
    if [[ ! -d "$HOME/.local/share/nmap/scripts/vulscan" ]]; then
        echo -e "${YELLOW}[+] Installing vulscan in user space...${NC}"
        mkdir -p "$HOME/.local/share/nmap/scripts"
        git clone https://github.com/scipag/vulscan.git "$HOME/.local/share/nmap/scripts/vulscan" 2>/dev/null || {
            echo -e "${RED}[-] Failed to clone vulscan repository${NC}"
            return 1
        }
    fi

    # First scan: vulscan (run only if installation succeeded)
    if [[ -d "$HOME/.local/share/nmap/scripts/vulscan" ]]; then
        echo -e "${YELLOW}[+] Running vulscan...${NC}"
        nmap -sV --script="$HOME/.local/share/nmap/scripts/vulscan/vulscan.nse" "$IP" | tee -a "$vulns/vulscan" || {
            echo -e "${RED}[-] vulscan failed${NC}"
        }
    fi

    # Second scan: standard Nmap vuln scripts (always run)
    echo -e "${YELLOW}[+] Running Nmap vuln scripts...${NC}"
    nmap -Pn --script vuln "$IP" | tee -a "$vulns/vuln" || {
        echo -e "${RED}[-] Nmap vuln scan failed${NC}"
    }

    cd "$cwd" || return
}

