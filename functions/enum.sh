#!/bin/bash

redis_enum (){
        mkdir $loot/redis
	tput setaf 2;echo "[+] Starting redis enum";tput sgr0
        nmap --script redis-info -sV -p 6379 $IP | tee -a $loot/redis/redis_info
        echo "msf> use auxiliary/scanner/redis/redis_server" >> $loot/redis/manual_cmds
}

snmp_enum (){
        mkdir $loot/snmp
	tput setaf 2;echo "[+] Starting snmp enum";tput sgr0
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP | tee -a $loot/snmp/snmpenum
#       create algo to check which version of snmp is runnign or pull it off a banner grab
        snmp-check -c public -v 1 -d $IP | tee -a $loot/snmp/snmpcheck
        if grep -q "SNMP request timeout" "$loot/snmp/snmpcheck";then
                rm $loot/snmp/snmpcheck
                snmpwalk -c public -v2c $IP | tee -a $loot/snmp/uderstuff
                echo "snmpwalk -c public -v2c $IP" >> $loot/snmp/cmds_run &
                if grep -q "timeout" "$loot/snmp/uderstuff";then rm $loot/snmp/uderstuff;else mv $loot/snmp/uderstuff $loot/snmp/snmpenum;fi
        else
                mv $loot/snmp/snmpcheck $loot/snmp/snmpenum
        fi
        echo "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP" >> $loot/snmp/cmds_run &
        echo "snmp-check -c public $IP" >> $loot/snmp/cmds_run &
        wait
        rm $IP/autoenum/loot/raw/snmp_found
}

rpc_enum (){
        mkdir $loot/rpc
	tput setaf 2;echo "[+] Starting rpc enum";tput sgr0
        port=$(cat $loot/raw/rpc_found | grep "rpc" | awk '{print($1)}' | cut -d '/' -f 1)
        nmap -sV -p $port --script=rpcinfo >> $loot/rpc/ports
        if grep -q "" "$loot/rpc/ports";then rm $loot/rpc/ports;fi
        rpcbind -p $IP | tee -a $loot/rpc/versions
        if grep -q "nfs" "$loot/rpc/ports";then nfs_enum;fi
        rm $loot/raw/rpc_found
}

nfs_enum (){
        mkdir $loot/nfs
	tput setaf 2;echo "[+] Starting nfs enum";tput sgr0
        nmap -p 111 --script nfs* $IP | tee $loot/nfs/scripts
        # add chunk to automount if share is found
        share=$(cat $loot/nfs/scripts | grep "|_ " -m 1 | awk '{print($2)}')
        if grep -q "mfs-showmount" "$loot/nfs/scripts";then
                mkdir $loots/nfs/mount
                # pull share location and assign it to share var
                mount -o nolock $IP:$share $loot/nfs/mount
        fi
}

pop3_enum (){
        mkdir $loot/pop3
	tput setaf 2;echo "[+] Starting pop3 enum";tput sgr0
        nmap -sV --script pop3-brute $IP | tee -a $loot/pop3/brute
        echo "telnet $IP 110" >> $loot/pop3/manual_cmds
        rm $loot/raw/pop3_found
}

imap_enum (){
        echo "[+] Work in progress"
}

ldap_enum() {
    # Create directory structure
    mkdir -p "$loot/ldap"
    echo -e "${GREEN}[+] Starting LDAP enumeration${NC}"
    
    # Run Nmap LDAP scripts (basic discovery)
    (
        echo -e "${YELLOW}[+] Running Nmap LDAP scripts${NC}"
        nmap -vv -Pn -sV -p 389,636 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' "$IP" \
        | tee "$loot/ldap/nmap_ldap_scripts.txt"
        echo "nmap -vv -Pn -sV -p 389,636 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP" \
        >> "$loot/ldap/cmds_run"
    ) &
    
    # Run ldapsearch (base DN discovery)
    (
        echo -e "${YELLOW}[+] Running ldapsearch for base DN${NC}"
        ldapsearch -x -H "ldap://$IP:389" -s base namingcontexts 2>/dev/null \
        | tee "$loot/ldap/ldapsearch_base.txt"
        echo "ldapsearch -x -H ldap://$IP:389 -s base namingcontexts" >> "$loot/ldap/cmds_run"
    ) &
    
    # Run ldapwhoami (anonymous binding check)
    (
        echo -e "${YELLOW}[+] Checking anonymous binding${NC}"
        ldapwhoami -x -H "ldap://$IP:389" 2>/dev/null \
        | tee "$loot/ldap/anonymous_bind.txt"
        echo "ldapwhoami -x -H ldap://$IP:389" >> "$loot/ldap/cmds_run"
    ) &
    
    wait
    
    # Check if we found any naming contexts
    if grep -q "namingcontexts" "$loot/ldap/ldapsearch_base.txt"; then
        base_dn=$(grep "namingcontexts" "$loot/ldap/ldapsearch_base.txt" | head -1 | cut -d' ' -f2)
        echo -e "${GREEN}[+] Found base DN: $base_dn${NC}"
        
        # Run more detailed enumeration if base DN found
        (
            echo -e "${YELLOW}[+] Enumerating LDAP objects${NC}"
            ldapsearch -x -H "ldap://$IP:389" -b "$base_dn" '(objectClass=*)' 2>/dev/null \
            | tee "$loot/ldap/ldapsearch_full.txt"
            echo "ldapsearch -x -H ldap://$IP:389 -b '$base_dn' '(objectClass=*)'" >> "$loot/ldap/cmds_run"
        ) &
        
        # Check for password policy
        (
            echo -e "${YELLOW}[+] Checking password policy${NC}"
            ldapsearch -x -H "ldap://$IP:389" -b "$base_dn" '(objectClass=pwdPolicy)' 2>/dev/null \
            | tee "$loot/ldap/password_policy.txt"
        ) &
    fi
    
    wait
    
    # Cleanup only if file exists
    [[ -f "$loot/raw/ldap_found" ]] && rm "$loot/raw/ldap_found"
    
    echo -e "${GREEN}[+] LDAP enumeration complete${NC}"
}

dns_enum (){
        mkdir $loot/dns
        # mainly for pentesting use, not neccesary rn for oscp. retest later when adding to this
        #host $IP >> $loot/dns/host_out
        #host -t mx $IP >> $loot/dns/host_out
        #host -t txt $IP >> $loot/dns/host_out
        #host -t ns $IP >> $loot/dns/host_out
        ##host -t ptr $IP >> $loot/dns/host_out
        #host -t cname $IP >> $loot/dns/host_out
        #host -t a $IP >> $loot/dns/host_out
        #for host in <list of subs>;do host -l <host> <dns server addr>;done
        #fierce -dns $IP
        #dnsenum --enum $IP
        #dnsrecon -d $IP
        #gobuster -dns $IP
         
        echo "[-] Work in progress - DNS enumeration not yet implemented"
}

ftp_enum (){
        mkdir -p $loot/ftp
        echo "[+] Starting FTP enum..."
        cat $loot/raw/ftp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/ftp/port_list
        for port in $(cat $loot/ftp/port_list);do
                nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP | tee -a $loot/ftp/ftp_scripts
        done
        echo "nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP " >> $loot/ftp/cmds_run &
        wait
        rm $loot/ftp/port_list
        rm $loot/raw/ftp_found
        echo "[+] FTP enum complete"
}

smtp_enum (){
        mkdir $loot/smtp
	echo "[+] Starting SNMP enum..."
        cat $loot/raw/snmp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/smtp/port_list
        for port in $(cat $loot/smtp/port_list);do
                smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port | tee -a $loot/smtp/users
        done
        if grep -q "0 results" "$loot/smtp/users";then rm $loot/smtp/users;fi
        echo "nc -nvv $IP $port" >> $loot/smtp/maunal_cmds
        echo "telnet $IP $port" >> $loot/smpt/manual_cmds
        echo "smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port" >> $loot/smtp/cmds_run &
        wait
        rm $loot/smtp/port_list
        rm $loot/raw/smtp_found
}

oracle_enum (){
        mkdir $loot/oracle
	echo "[+] Starting Oracle enum..."
        #swap out port with port(s) found running oracle
        nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse | tee -a $loot/oracle/nmapstuff
        oscanner -v -s $IP -P 1521 | tee -a $loot/oracle/
        echo "[+] Running ODAT..."
        odat tnscmd -s $rhost --version --status --ping 2>/dev/null | tee -a $loot/oracle/odat_tnscmd
        odat sidguesser -s $rhost 2>/dev/null | tee -a $loot/oracle/odat_enum
        rm $loot/raw/oracle_found
}

http_enum() {
    # Create directory structure
    mkdir -p "$loot/http"
    echo -e "${YELLOW}[+] HTTP enumeration starting...${NC}"
    
    # Read ports from file
    if [[ ! -s "$loot/raw/http_found" ]]; then
        echo -e "${RED}[-] No HTTP ports found to enumerate${NC}"
        return
    fi
    
    mapfile -t ports < "$loot/raw/http_found"
    pct=${#ports[@]}
    
    # Enhanced HTTP service verification
    verify_http_service() {
        local port=$1
        local timeout=3
        
        # Fast curl check
        if curl -sI -m "$timeout" "http://$IP:$port" &>/dev/null; then
            return 0
        fi
        
        # Netcat fallback
        if echo -e "HEAD / HTTP/1.1\r\nHost: $IP\r\n\r\n" | nc -w "$timeout" "$IP" "$port" | grep -iq "HTTP/"; then
            return 0
        fi
        
        return 1
    }

    # Optimized directory brute force
    run_gobuster() {
        local port=$1
        local port_dir=$2
        
        if ! curl -sI -m 5 "http://$IP:$port" &>/dev/null; then
            echo -e "${RED}[-] Port $port unresponsive - skipping gobuster${NC}"
            return
        fi
        
        echo -e "${YELLOW}[+] Bruteforcing directories (port $port)${NC}"
        timeout 300 gobuster dir \
            -t 40 \
            -u "http://$IP:$port" \
            -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
            -o "$port_dir/dirs_found" \
            -k \
            --timeout 8s \
            --delay 200ms \
            --status-codes 200,204,301,302,307,401,403,500 \
            --status-codes-blacklist "" \
            --no-error \
            --quiet
        
        if [[ $? -eq 124 ]]; then
            echo -e "${RED}[-] Gobuster timed out on port $port${NC}"
        elif [[ ! -s "$port_dir/dirs_found" ]]; then
            echo -e "${YELLOW}[-] No directories found on port $port${NC}"
        fi
    }

    # Parallel processing function
    process_port() {
        local port=$1
        local port_dir="$loot/http/$port"
        
        mkdir -p "$port_dir"
        
        echo -e "${YELLOW}[+] Processing port $port${NC}"
        
        if ! verify_http_service "$port"; then
            echo -e "${RED}[-] No HTTP service on port $port - skipping${NC}"
            return
        fi
        
        # Run all scans in parallel
        (
            echo -e "${YELLOW}[+] Nikto scan${NC}"
            timeout 120 nikto -ask=no -h "$IP:$port" -T 123b >> "$port_dir/nikto" 2>&1
        ) &
        
        (
            echo -e "${YELLOW}[+] SSL scan${NC}"
            timeout 60 sslscan --show-certificate "$IP:$port" >> "$port_dir/sslinfo" 2>&1
        ) &
        
        (
            echo -e "${YELLOW}[+] Fetching pages${NC}"
            curl -sSiLk -m 15 "$IP:$port/index.html" >> "$port_dir/landingpage" 2>&1
            curl -sSiLk -m 10 "$IP:$port/robots.txt" >> "$port_dir/robots.txt" 2>&1
        ) &
        
        (
            echo -e "${YELLOW}[+] WhatWeb scan${NC}"
            timeout 90 whatweb -a3 "$IP:$port" >> "$port_dir/whatweb" 2>&1
        ) &
        
        wait
        
        # Run gobuster with fixed status code handling
        run_gobuster "$port" "$port_dir"
        
        # Log commands
        {
            echo "verify_http_service $port"
            echo "nikto -ask=no -h $IP:$port -T 123b"
            echo "sslscan --show-certificate $IP:$port"
            echo "curl -sSiLk $IP:$port/{index.html,robots.txt}"
            echo "whatweb -a3 $IP:$port"
            echo "gobuster dir -u http://$IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $port_dir/dirs_found -k --timeout 8s --delay 200ms --status-codes 200,204,301,302,307,401,403,500 --status-codes-blacklist \"\""
        } >> "$port_dir/cmds_run"
    }

    # Main execution
    if (( pct > 1 )); then
        echo -e "${YELLOW}[+] Scanning $pct HTTP ports in parallel${NC}"
        for port in "${ports[@]}"; do
            process_port "$port" &
        done
        wait
    else
        process_port "${ports[0]}"
    fi

    echo -e "${GREEN}[+] HTTP enumeration complete!${NC}"
}

smb_enum() {
    echo -e "${YELLOW}[+] Starting SMB enumeration...${NC}"
    mkdir -p "$loot/smb/shares"
    
    # Vulnerability checks
    echo -e "${BLUE}[+] Checking for common SMB vulnerabilities${NC}"
    (
        nmap --script smb-vuln-ms17-010 --script-args=unsafe=1 -p 139,445 "$IP" -oN "$loot/smb/eternalblue"
        grep -q "smb-vuln-ms17-010:" "$loot/smb/eternalblue" || rm "$loot/smb/eternalblue"
    ) &
    
    (
        nmap --script smb-vuln-ms08-067 --script-args=unsafe=1 -p 445 "$IP" -oN "$loot/smb/08-067"
        grep -q "smb-vuln-ms08-067:" "$loot/smb/08-067" || rm "$loot/smb/08-067"
    ) &
    
    (
        nmap --script smb-vuln* -p 139,445 "$IP" -oN "$loot/smb/gen_vulns"
    ) &
    
    # Share enumeration
    echo -e "${BLUE}[+] Enumerating SMB shares${NC}"
    (
        nmap --script smb-enum-shares -p 139,445 "$IP" -oN "$loot/smb/shares/nmap_shares"
    ) &
    
    (
        smbmap -H "$IP" -R > "$loot/smb/shares/smbmap_out" 2>&1
    ) &
    
    # SMB client checks with multiple connection attempts
    (
        attempts=(
            "smbclient -N -L \\\\\\\\$IP"
            "smbclient -N -H \\\\\\$IP"
            "smbclient -N -H \\$IP"
        )
        
        for attempt in "${attempts[@]}"; do
            $attempt > "$loot/smb/shares/smbclient_out" 2>&1
            if ! grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out"; then
                break
            fi
        done
        
        if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out"; then
            rm "$loot/smb/shares/smbclient_out"
            echo "smbclient could not be automatically run, rerun smbclient -N -H [IP] manually" >> "$loot/smb/notes"
        fi
        
        if grep -q "Error NT_STATUS_UNSUCCESSFUL" "$loot/smb/shares/smbclient_out"; then
            rm "$loot/smb/shares/smbclient_out"
        fi
        
        if [[ -s "$loot/smb/shares/smbclient_out" ]]; then
            echo "smb shares open to null login, use rpcclient -U '' -N $IP to run rpc commands" >> "$loot/smb/notes"
            echo "use smbmap -u null -p '' -H $IP -R to verify this" >> "$loot/smb/notes"
        fi
    ) &
    
    wait
    
    # Clean up bad output files
    echo -e "${BLUE}[+] Cleaning up invalid output files${NC}"
    find "$loot/smb" -type f \( -name "*.nmap" -o -name "*.txt" \) | while read -r file; do
        if grep -q -E "QUITTING!|ERROR: Script execution failed|segmentation fault" "$file"; then
            rm "$file"
        fi
    done
    
    # Log commands executed
    echo -e "${BLUE}[+] Logging executed commands${NC}"
    cat > "$loot/smb/cmds_run" << EOF
nmap --script smb-vuln-ms17-010 --script-args=unsafe=1 -p 139,445 $IP
nmap --script smb-vuln-ms08-067 --script-args=unsafe=1 -p 445 $IP
nmap --script smb-vuln* -p 139,445 $IP
nmap --script smb-enum-shares -p 139,445 $IP
smbmap -H $IP -R
smbclient -N -L \\\\\\\\$IP
EOF
    
    # Cleanup
    rm -f "$loot/raw/smb_found"
    echo -e "${GREEN}[+] SMB enumeration complete!${NC}"
    echo -e "${CYAN}[+] Results saved to: $loot/smb/${NC}"
}

linux_enum (){
        #get exact snmp version
        echo "[-] Work in Progress"
}

windows_enum (){
        # get exact snmp version
        # pull entire MIB into sections
        echo "[-] Work in Progress"
}

