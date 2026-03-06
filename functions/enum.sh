#!/bin/bash
# enum.sh
# Autoenum - Optimized Service Enumeration (Fast, Reliable, Accurate)
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

redis_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run redis_enum on $IP:6379${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting Redis enumeration...${NO_COLOR}"
    mkdir -p "$loot/redis"

    # Run with timeout
    timeout "$timeout" nmap -sV -p 6379 --min-rate 500 \
        --host-timeout 60s \
        "$IP" --script redis-info \
        | tee -a "$loot/redis/redis_info" 2>/dev/null || {
        echo -e "${RED}[-] Redis scan failed${NO_COLOR}"
    }

    echo "msf> use auxiliary/scanner/redis/redis_server" >> "$loot/redis/manual_cmds"
    echo -e "${GREEN}[+] Redis enum complete!${NO_COLOR}"
}

snmp_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run snmp_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting SNMP enumeration...${NO_COLOR}"
    mkdir -p "$loot/snmp"

    # Run onesixtyone with timeout
    timeout "$timeout" onesixtyone -c /usr/share/doc/onesixtyone/dict.txt "$IP" \
        | tee -a "$loot/snmp/snmpenum" 2>/dev/null || {
        echo -e "${RED}[-] onesixtyone failed${NO_COLOR}"
    }

    # Run snmp-check
    timeout "$timeout" snmp-check -c public -v 1 -d "$IP" \
        | tee -a "$loot/snmp/snmpcheck" 2>/dev/null || {
        echo -e "${RED}[-] snmp-check failed${NO_COLOR}"
    }

    # Check for timeout
    if [[ -f "$loot/snmp/snmpcheck" ]] && grep -q "SNMP request timeout" "$loot/snmp/snmpcheck"; then
        rm -f "$loot/snmp/snmpcheck"
        timeout "$timeout" snmpwalk -c public -v2c "$IP" \
            | tee -a "$loot/snmp/uderstuff" 2>/dev/null || {
            echo -e "${RED}[-] snmpwalk failed${NO_COLOR}"
        }
        if grep -q "timeout" "$loot/snmp/uderstuff"; then
            rm -f "$loot/snmp/uderstuff"
        else
            mv "$loot/snmp/uderstuff" "$loot/snmp/snmpenum"
        fi
    else
        [[ -f "$loot/snmp/snmpcheck" ]] && mv "$loot/snmp/snmpcheck" "$loot/snmp/snmpenum"
    fi

    echo "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP" >> "$loot/snmp/cmds_run"
    echo "snmp-check -c public $IP" >> "$loot/snmp/cmds_run"

    echo -e "${GREEN}[+] SNMP enum complete!${NO_COLOR}"
}

rpc_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run rpc_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting RPC enumeration...${NO_COLOR}"
    mkdir -p "$loot/rpc"

    # Get port from file
    if [[ ! -s "$loot/raw/rpc_found" ]]; then
        echo -e "${RED}[-] No RPC ports found${NO_COLOR}"
        return 0
    fi

    local port
    port=$(awk '/rpc/ {print $1}' "$loot/raw/rpc_found" | cut -d'/' -f1)

    # Run nmap rpcinfo script
    timeout "$timeout" nmap -sV -p "$port" --script=rpcinfo \
        --min-rate 500 --host-timeout 60s "$IP" \
        | tee -a "$loot/rpc/ports" 2>/dev/null || {
        echo -e "${RED}[-] nmap rpcinfo failed${NO_COLOR}"
    }

    # Query RPC services (rpcinfo, not rpcbind which is a daemon)
    timeout "$timeout" rpcinfo -p "$IP" \
        | tee -a "$loot/rpc/versions" 2>/dev/null || {
        echo -e "${RED}[-] rpcinfo query failed${NO_COLOR}"
    }

    # Check for NFS
    if grep -q "nfs" "$loot/rpc/ports"; then
        nfs_enum "$timeout" "$dry_run"
    fi

    rm -f "$loot/raw/rpc_found"
    echo -e "${GREEN}[+] RPC enum complete!${NO_COLOR}"
}

nfs_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run nfs_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting NFS enumeration...${NO_COLOR}"
    mkdir -p "$loot/nfs"

    # Run nmap
    timeout "$timeout" nmap -p 111 --script nfs* "$IP" \
        | tee "$loot/nfs/scripts" 2>/dev/null || {
        echo -e "${RED}[-] nmap nfs failed${NO_COLOR}"
    }

    # Check for share
    local share
    share=$(awk '/\|_ / {print $2}' "$loot/nfs/scripts" | head -1)
    if [[ -n "$share" ]]; then
        mkdir -p "$loot/nfs/mount"
        timeout "$timeout" sudo mount -o nolock "$IP:$share" "$loot/nfs/mount" 2>/dev/null || {
            echo -e "${RED}[-] Mount failed (try running autoenum as root)${NO_COLOR}"
        }
    fi

    echo -e "${GREEN}[+] NFS enum complete!${NO_COLOR}"
}

pop3_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run pop3_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting POP3 enumeration...${NO_COLOR}"
    mkdir -p "$loot/pop3"

    # Run nmap
    timeout "$timeout" nmap -sV --script pop3-brute "$IP" \
        | tee -a "$loot/pop3/brute" 2>/dev/null || {
        echo -e "${RED}[-] nmap pop3-brute failed${NO_COLOR}"
    }

    echo "telnet $IP 110" >> "$loot/pop3/manual_cmds"
    rm -f "$loot/raw/pop3_found"
    echo -e "${GREEN}[+] POP3 enum complete!${NO_COLOR}"
}

imap_enum() {
    echo -e "${YELLOW}[+] Work in progress${NO_COLOR}"
}

ldap_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run ldap_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting LDAP enumeration...${NO_COLOR}"
    mkdir -p "$loot/ldap"

    # Run Nmap LDAP scripts
    (
        echo -e "${YELLOW}[+] Running Nmap LDAP scripts${NO_COLOR}"
        timeout "$timeout" nmap -vv -Pn -sV -p 389,636 \
            --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' \
            "$IP" | tee "$loot/ldap/nmap_ldap_scripts.txt" 2>/dev/null || {
            echo -e "${RED}[-] Nmap LDAP scripts failed${NO_COLOR}"
        }
        echo "nmap -vv -Pn -sV -p 389,636 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP" >> "$loot/ldap/cmds_run"
    ) &

    # Run ldapsearch
    (
        echo -e "${YELLOW}[+] Running ldapsearch for base DN${NO_COLOR}"
        timeout "$timeout" ldapsearch -x -H "ldap://$IP:389" -s base namingcontexts 2>/dev/null \
            | tee "$loot/ldap/ldapsearch_base.txt" 2>/dev/null || {
            echo -e "${RED}[-] ldapsearch base failed${NO_COLOR}"
        }
        echo "ldapsearch -x -H ldap://$IP:389 -s base namingcontexts" >> "$loot/ldap/cmds_run"
    ) &

    # Run ldapwhoami
    (
        echo -e "${YELLOW}[+] Checking anonymous binding${NO_COLOR}"
        timeout "$timeout" ldapwhoami -x -H "ldap://$IP:389" 2>/dev/null \
            | tee "$loot/ldap/anonymous_bind.txt" 2>/dev/null || {
            echo -e "${RED}[-] ldapwhoami failed${NO_COLOR}"
        }
        echo "ldapwhoami -x -H ldap://$IP:389" >> "$loot/ldap/cmds_run"
    ) &

    wait

    # Check for base DN
    if grep -q "namingcontexts" "$loot/ldap/ldapsearch_base.txt"; then
        local base_dn
        base_dn=$(awk '/namingcontexts/ {print $2}' "$loot/ldap/ldapsearch_base.txt" | head -1)
        echo -e "${GREEN}[+] Found base DN: $base_dn${NO_COLOR}"

        # Run detailed enumeration
        (
            echo -e "${YELLOW}[+] Enumerating LDAP objects${NO_COLOR}"
            timeout "$timeout" ldapsearch -x -H "ldap://$IP:389" -b "$base_dn" '(objectClass=*)' 2>/dev/null \
                | tee "$loot/ldap/ldapsearch_full.txt" 2>/dev/null || {
                echo -e "${RED}[-] ldapsearch full failed${NO_COLOR}"
            }
            echo "ldapsearch -x -H ldap://$IP:389 -b '$base_dn' '(objectClass=*)'" >> "$loot/ldap/cmds_run"
        ) &

        # Check password policy
        (
            echo -e "${YELLOW}[+] Checking password policy${NO_COLOR}"
            timeout "$timeout" ldapsearch -x -H "ldap://$IP:389" -b "$base_dn" '(objectClass=pwdPolicy)' 2>/dev/null \
                | tee "$loot/ldap/password_policy.txt" 2>/dev/null || {
                echo -e "${RED}[-] ldapsearch policy failed${NO_COLOR}"
            }
        ) &
    fi

    wait

    [[ -f "$loot/raw/ldap_found" ]] && rm -f "$loot/raw/ldap_found"
    echo -e "${GREEN}[+] LDAP enumeration complete!${NO_COLOR}"
}

dns_enum() {
    echo -e "${YELLOW}[+] Work in progress - DNS enumeration not yet implemented${NO_COLOR}"
}

ftp_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run ftp_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting FTP enumeration...${NO_COLOR}"
    mkdir -p "$loot/ftp"

    # Get ports
    if [[ ! -s "$loot/raw/ftp_found" ]]; then
        echo -e "${RED}[-] No FTP ports found${NO_COLOR}"
        return 0
    fi

    while IFS= read -r port; do
        timeout "$timeout" nmap -sV -Pn -p "$port" \
            --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst \
            -v "$IP" | tee -a "$loot/ftp/ftp_scripts" 2>/dev/null || {
            echo -e "${RED}[-] nmap FTP scan failed on port $port${NO_COLOR}"
        }
        echo "nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP" >> "$loot/ftp/cmds_run"
    done < <(awk '{print $1}' "$loot/raw/ftp_found" | cut -d'/' -f1)

    rm -f "$loot/ftp/port_list"
    rm -f "$loot/raw/ftp_found"
    echo -e "${GREEN}[+] FTP enum complete!${NO_COLOR}"
}

smtp_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run smtp_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting SMTP enumeration...${NO_COLOR}"
    mkdir -p "$loot/smtp"

    # Get ports
    if [[ ! -s "$loot/raw/smtp_found" ]]; then
        echo -e "${RED}[-] No SMTP ports found${NO_COLOR}"
        return 0
    fi

    while IFS= read -r port; do
        timeout "$timeout" smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t "$IP" -p "$port" \
            | tee -a "$loot/smtp/users" 2>/dev/null || {
            echo -e "${RED}[-] smtp-user-enum failed on port $port${NO_COLOR}"
        }
        echo "nc -nvv $IP $port" >> "$loot/smtp/manual_cmds"
        echo "telnet $IP $port" >> "$loot/smtp/manual_cmds"
        echo "smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port" >> "$loot/smtp/cmds_run"
    done < <(awk '{print $1}' "$loot/raw/smtp_found" | cut -d'/' -f1)

    if [[ -f "$loot/smtp/users" ]] && grep -q "0 results" "$loot/smtp/users"; then
        rm -f "$loot/smtp/users"
    fi

    rm -f "$loot/smtp/port_list"
    rm -f "$loot/raw/smtp_found"
    echo -e "${GREEN}[+] SMTP enum complete!${NO_COLOR}"
}

oracle_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run oracle_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting Oracle enumeration...${NO_COLOR}"
    mkdir -p "$loot/oracle"

    # Run nmap
    timeout "$timeout" nmap -sV -p 1521 \
        --script=oracle-enum-users,oracle-sid-brute,oracle-tns-version \
        "$IP" | tee -a "$loot/oracle/nmap_oracle" 2>/dev/null || {
        echo -e "${RED}[-] nmap Oracle scan failed${NO_COLOR}"
    }

    # Run oscanner
    timeout "$timeout" oscanner -v -s "$IP" -P 1521 | tee -a "$loot/oracle/oscanner_out" 2>/dev/null || {
        echo -e "${RED}[-] oscanner failed${NO_COLOR}"
    }

    # Run odat
    echo -e "${YELLOW}[+] Running ODAT...${NO_COLOR}"
    timeout "$timeout" odat tnscmd -s "$IP" --version --status --ping 2>/dev/null | tee -a "$loot/oracle/odat_tnscmd" 2>/dev/null || {
        echo -e "${RED}[-] odat tnscmd failed${NO_COLOR}"
    }

    timeout "$timeout" odat sidguesser -s "$IP" 2>/dev/null | tee -a "$loot/oracle/odat_enum" 2>/dev/null || {
        echo -e "${RED}[-] odat sidguesser failed${NO_COLOR}"
    }

    rm -f "$loot/raw/oracle_found"
    echo -e "${GREEN}[+] Oracle enum complete!${NO_COLOR}"
}

http_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run http_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting HTTP enumeration...${NO_COLOR}"
    mkdir -p "$loot/http"

    # Check for ports
    if [[ ! -s "$loot/raw/http_found" ]]; then
        echo -e "${RED}[-] No HTTP ports found${NO_COLOR}"
        return 0
    fi

    mapfile -t ports < "$loot/raw/http_found"
    pct=${#ports[@]}

    # Detect whether a port speaks HTTP or HTTPS; echoes the working scheme.
    detect_http_scheme() {
        local port="$1"
        local chk_timeout=3

        # HTTP first
        if curl -sI -m "$chk_timeout" "http://$IP:$port" &>/dev/null; then
            echo "http"; return 0
        fi

        # HTTPS (skip cert validation)
        if curl -sIk -m "$chk_timeout" "https://$IP:$port" &>/dev/null; then
            echo "https"; return 0
        fi

        # Netcat fallback (plain HTTP)
        if echo -e "HEAD / HTTP/1.1\r\nHost: $IP\r\n\r\n" | nc -w "$chk_timeout" "$IP" "$port" | grep -iq "HTTP/"; then
            echo "http"; return 0
        fi

        return 1
    }

    # Gobuster with timeout
    run_gobuster() {
        local port="$1"
        local port_dir="$2"
        local scheme="${3:-http}"

        if ! curl -sIk -m 5 "$scheme://$IP:$port" &>/dev/null; then
            echo -e "${RED}[-] Port $port unresponsive - skipping gobuster${NO_COLOR}"
            return
        fi

        echo -e "${YELLOW}[+] Bruteforcing directories ($scheme port $port)${NO_COLOR}"
        timeout 300 gobuster dir \
            -t 40 \
            -u "$scheme://$IP:$port" \
            -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
            -o "$port_dir/dirs_found" \
            -k \
            --timeout 8s \
            --delay 200ms \
            --status-codes 200,204,301,302,307,401,403,500 \
            --no-error \
            --quiet

        if [[ $? -eq 124 ]]; then
            echo -e "${RED}[-] Gobuster timed out on port $port${NO_COLOR}"
        elif [[ ! -s "$port_dir/dirs_found" ]]; then
            echo -e "${YELLOW}[-] No directories found on port $port${NO_COLOR}"
        fi
    }

    # Process port
    process_port() {
        local port="$1"
        local port_dir="$loot/http/$port"

        mkdir -p "$port_dir"

        echo -e "${YELLOW}[+] Processing port $port${NO_COLOR}"

        local scheme
        scheme=$(detect_http_scheme "$port") || {
            echo -e "${RED}[-] No HTTP/HTTPS service on port $port - skipping${NO_COLOR}"
            return
        }
        echo -e "${CYAN}[+] Port $port using scheme: $scheme${NO_COLOR}"

        # Run in parallel
        (
            echo -e "${YELLOW}[+] Nikto scan${NO_COLOR}"
            timeout 120 nikto -ask=no -h "$scheme://$IP:$port" -T 123b >> "$port_dir/nikto" 2>&1
        ) &

        (
            echo -e "${YELLOW}[+] SSL scan${NO_COLOR}"
            timeout 60 sslscan --show-certificate "$IP:$port" >> "$port_dir/sslinfo" 2>&1
        ) &

        (
            echo -e "${YELLOW}[+] Fetching pages${NO_COLOR}"
            curl -sSiLk -m 15 "$scheme://$IP:$port/index.html" >> "$port_dir/landingpage" 2>&1
            curl -sSiLk -m 10 "$scheme://$IP:$port/robots.txt" >> "$port_dir/robots.txt" 2>&1
        ) &

        (
            echo -e "${YELLOW}[+] WhatWeb scan${NO_COLOR}"
            timeout 90 whatweb -a3 "$scheme://$IP:$port" >> "$port_dir/whatweb" 2>&1
        ) &

        wait

        # Run gobuster
        run_gobuster "$port" "$port_dir" "$scheme"

        # Log commands
        {
            echo "detect_http_scheme $port  # detected: $scheme"
            echo "nikto -ask=no -h $scheme://$IP:$port -T 123b"
            echo "sslscan --show-certificate $IP:$port"
            echo "curl -sSiLk $scheme://$IP:$port/{index.html,robots.txt}"
            echo "whatweb -a3 $scheme://$IP:$port"
            echo "gobuster dir -u $scheme://$IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $port_dir/dirs_found -k --timeout 8s --delay 200ms --status-codes 200,204,301,302,307,401,403,500"
        } >> "$port_dir/cmds_run"
    }

    # Run in parallel with a cap of 4 concurrent port scans
    if (( pct > 1 )); then
        echo -e "${YELLOW}[+] Scanning $pct HTTP ports in parallel${NO_COLOR}"
        local _http_running=0
        for port in "${ports[@]}"; do
            while (( _http_running >= 4 )); do
                wait -n 2>/dev/null || wait
                (( _http_running-- ))
            done
            process_port "$port" &
            (( _http_running++ ))
        done
        wait
    else
        process_port "${ports[0]}"
    fi

    echo -e "${GREEN}[+] HTTP enumeration complete!${NO_COLOR}"
}

smb_enum() {
    local timeout="${1:-300}"
    local dry_run="${2:-}"

    if [[ "$dry_run" == "--dry-run" ]]; then
        echo -e "${YELLOW}[+] Would run smb_enum on $IP${NO_COLOR}"
        return 0
    fi

    echo -e "${GREEN}[+] Starting SMB enumeration...${NO_COLOR}"
    mkdir -p "$loot/smb/shares"

    # Vulnerability checks
    echo -e "${BLUE}[+] Checking for common SMB vulnerabilities${NO_COLOR}"
    (
        timeout "$timeout" nmap --script smb-vuln-ms17-010 --script-args=unsafe=1 -p 139,445 "$IP" -oN "$loot/smb/eternalblue"
        grep -q "smb-vuln-ms17-010:" "$loot/smb/eternalblue" || rm -f "$loot/smb/eternalblue"
    ) &

    (
        timeout "$timeout" nmap --script smb-vuln-ms08-067 --script-args=unsafe=1 -p 445 "$IP" -oN "$loot/smb/08-067"
        grep -q "smb-vuln-ms08-067:" "$loot/smb/08-067" || rm -f "$loot/smb/08-067"
    ) &

    (
        timeout "$timeout" nmap --script smb-vuln* -p 139,445 "$IP" -oN "$loot/smb/gen_vulns"
    ) &

    # Share enumeration
    echo -e "${BLUE}[+] Enumerating SMB shares${NO_COLOR}"
    (
        timeout "$timeout" nmap --script smb-enum-shares -p 139,445 "$IP" -oN "$loot/smb/shares/nmap_shares"
    ) &

    (
        timeout "$timeout" smbmap -H "$IP" -R > "$loot/smb/shares/smbmap_out" 2>&1
    ) &

    # SMB client checks
    (
        attempts=(
            "smbclient -N -L //$IP"
            "smbclient -N -L \\\\\\\\$IP"
        )

        for attempt in "${attempts[@]}"; do
            eval "$attempt" > "$loot/smb/shares/smbclient_out" 2>&1
            if ! grep -q "Not enough '\\' characters in service" "$loot/smb/shares/smbclient_out"; then
                break
            fi
        done

        if grep -q "Not enough '\\' characters in service" "$loot/smb/shares/smbclient_out"; then
            rm -f "$loot/smb/shares/smbclient_out"
            echo "smbclient could not be automatically run, rerun smbclient -N -L //[IP] manually" >> "$loot/smb/notes"
        fi

        if grep -q "Error NT_STATUS_UNSUCCESSFUL" "$loot/smb/shares/smbclient_out"; then
            rm -f "$loot/smb/shares/smbclient_out"
        fi

        if [[ -s "$loot/smb/shares/smbclient_out" ]]; then
            echo "smb shares open to null login, use rpcclient -U '' -N $IP to run rpc commands" >> "$loot/smb/notes"
            echo "use smbmap -u null -p '' -H $IP -R to verify this" >> "$loot/smb/notes"
        fi
    ) &

    wait

    # Clean up bad output files
    echo -e "${BLUE}[+] Cleaning up invalid output files${NO_COLOR}"
    find "$loot/smb" -type f \( -name "*.nmap" -o -name "*.txt" \) | while read -r file; do
        if grep -q -E "QUITTING!|ERROR: Script execution failed|segmentation fault" "$file"; then
            rm -f "$file"
        fi
    done

    # Log commands
    echo -e "${BLUE}[+] Logging executed commands${NO_COLOR}"
    cat > "$loot/smb/cmds_run" << EOF
nmap --script smb-vuln-ms17-010 --script-args=unsafe=1 -p 139,445 $IP
nmap --script smb-vuln-ms08-067 --script-args=unsafe=1 -p 445 $IP
nmap --script smb-vuln* -p 139,445 $IP
nmap --script smb-enum-shares -p 139,445 $IP
smbmap -H $IP -R
smbclient -N -L //$IP
EOF

    # Cleanup
    rm -f "$loot/raw/smb_found"
    echo -e "${GREEN}[+] SMB enumeration complete!${NO_COLOR}"
    echo -e "${CYAN}[+] Results saved to: $loot/smb/${NO_COLOR}"
}

linux_enum() {
    echo -e "${YELLOW}[+] Work in progress - Linux enumeration not yet implemented${NO_COLOR}"
}

windows_enum() {
    echo -e "${YELLOW}[+] Work in progress - Windows enumeration not yet implemented${NO_COLOR}"
}
