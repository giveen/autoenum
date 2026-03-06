#!/bin/bash

#source functions/menu/web.sh
#source functions/menu/smb.sh
#source functions/menu/dns.sh
#source functions/menu/fingerprint.sh
#source functions/menu/validate.sh
#source functions/menu/amass.sh

menu (){
    local WHITE='\033[01;37m'
    local CLEAR='\033[0m'

    # mkbasedirs defined once before the loop so it's always available
    mkbasedirs() {
        echo "[+] Checking for base dirs..."
        mkdir -p "$IP/autoenum"
        if [[ ! -d "$IP/autoenum/loot/raw" ]]; then mkdir -p "$IP/autoenum/loot/raw"; fi
        loot="$IP/autoenum/loot"
        mkdir -p "$loot/exploits"
        echo "[+] Done!"
    }

    while true; do
        [[ "${module:-}" == "" ]] && cli="Autoenum($IP) > "
        tput bold; tput setaf 1; echo -en "$cli"; tput sgr0; read -r arg

        case "$arg" in
            "")
                continue
                ;;
            "home")
                cli="Autoenum($IP) > "
                continue
                ;;
            "commands")
                halp_meh
                ;;
            "shell")
                shell_preserve
                ;;
            "reset")
                reset
                ;;
            "upgrade")
                upgrade
                ;;
            "clear")
                clear
                ;;
            "banner")
                banner
                ;;
            "ping")
                if [[ "$IP" == "dev" ]]; then
                    echo "[-] set an IP. use set target to do this"
                else
                    ping "$IP" -c 1; echo -e
                fi
                ;;
            "udp")
                echo "[~] SCAN MODE: udp"; sleep 2; echo -e
                mkbasedirs
                udp
                ;;
            "vuln")
                echo "[~] SCAN MODE: vuln"; sleep 2; echo -e
                mkbasedirs
                vuln
                ;;
            "aggr")
                echo "[~] SCAN MODE: aggr"; sleep 2; echo -e
                mkbasedirs
                aggr
                cleanup
                ;;
            "reg")
                echo "[~] SCAN MODE: reg"; sleep 2; echo -e
                mkbasedirs
                reg
                cleanup
                ;;
            "quick")
                echo "[~] SCAN MODE: quick"; sleep 2; echo -e
                nmap -sC -sV -T4 -Pn "$IP"
                ;;
            "top 1k"|"top1k")
                echo "[~] SCAN MODE: top 1k"; sleep 2; echo -e
                mkbasedirs
                top_1k
                cleanup
                ;;
            "top 10k"|"top10k")
                echo "[~] SCAN MODE: top 10k"; sleep 2; echo -e
                mkbasedirs
                top_10k
                cleanup
                ;;
            "top 1k+vuln"|"top1k+vuln")
                echo "[~] SCAN MODE: top 1k+vuln"; sleep 2; echo -e
                mkbasedirs
                top_1k
                vuln
                cleanup
                ;;
            "top 10k+vuln"|"top10k+vuln")
                echo "[~] SCAN MODE: top 10k+vuln"; sleep 2; echo -e
                mkbasedirs
                top_10k
                vuln
                cleanup
                ;;
            "aggr+vuln")
                echo "[~] SCAN MODE: aggr+vuln"; sleep 2; echo -e
                mkbasedirs
                aggr
                vuln
                cleanup
                ;;
            "reg+vuln")
                echo "[~] SCAN MODE: reg+vuln"; sleep 2; echo -e
                mkbasedirs
                reg
                vuln
                cleanup
                ;;
            "help")
                halp_meh_pws
                ;;
            "set target")
                echo -en "Enter IP/hostname > "; read -r unchecked_IP
                if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    local cwd; cwd=$(pwd)
                    ping -c 1 "$unchecked_IP" | head -n2 | tail -n1 > "$cwd/tmp"
                    if ! grep -q "64 bytes" "$cwd/tmp"; then
                        echo "[-] IP failed to resolve"
                    else
                        IP="$unchecked_IP"; tput setaf 4; echo -e "[+] IP set to $IP"; tput sgr0; echo -e
                    fi
                    rm -f "$cwd/tmp"
                elif [[ $unchecked_IP =~ [a-zA-Z0-9]\.[a-z]$ ]] || [[ $unchecked_IP =~ [a-z]\.[a-zA-Z0-9]\.[a-z]$ ]]; then
                    IP=$(host "$unchecked_IP" | head -n1 | awk '{print($4)}')
                    tput setaf 4; echo -e "$unchecked_IP resolved to $IP\n"; tput sgr0
                elif [[ $unchecked_IP == "*" ]]; then
                    IP="dev"
                    tput setaf 4; echo -e "[+] IP set to dev (testing mode)"; tput sgr0
                else
                    echo "[-] Invalid IP detected."
                    echo "[-] Example: 192.168.1.5"
                fi
                ;;
#                "use amass")
#                        echo "[*] OWASP amass set to use"
#                        OWASP_amass
#                        break
#                        ;;
#                "list modules")
                        # while base autoenum runs nmap an analysis based on services discovered, this module tatgets and deeply analyses target services while base autoenum glosses over services found
#			echo "[*] Validate"
#			echo "[*] Fingerprinting"
#			echo "[*] Web"
#			echo "[*] Samba"
#			echo "[*] DNS"
#			echo "[*] AD"
#                       menu
#                        break
#                        ;;
#                "set module")
#                        echo -en "module > ";read module
#			if [[ "$module" == "Validate" ]];then
#				module="Validate";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#				mkbasedirs
#				mkdir -p $loot/Modules/$module
#				validate_dir="$loot/Modules/$module"
#				echo "[+] Entering module: $module";sleep 1.5
#				validate
#			elif [[ "$module" == "Fingerprinting" ]];then
#				module="Fingerprinting";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                fprint_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#				fingerprint
#                        elif [[ "$module" == "Web" ]];then
#				module="Web";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                web_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                Web
#                        elif [[ "$module" == "DNS" ]];then
#				module="DNS";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                DNS_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                DNS
#                        elif [[ "$module" == "AD" ]];then
#				module="AD";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                AD_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                AD
#                        elif [[ "$module" == "Samba" ]];then
#				module="Samba";cli="Autoenum($IP)$WHITE [$module]$CLEAR > "
#                                mkbasedirs
#                                mkdir -p $loot/Modules/$module
#                                samba_dir="$loot/Modules/$module"
#                                echo "[+] Entering module: $module";sleep 1.5
#                                Samba
#                        else
#                                echo "[-] Invalid module selected"
#                        fi
#                        menu
#                        break
#                        ;;
            "exit")
                tput setaf 8; echo "[-] Terminating session..."
                tput sgr0
                sleep 1.5
                exit 0
                ;;
            *)
                tput setaf 8; echo "[-] Invalid input detected"
                tput sgr0
                ;;
        esac
    done
}
