```
                 __                                      
  ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___ 
 / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \
/ /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /
\__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/ 
                                                         
```
## Summary

Autoenum is a powerful, automated reconnaissance tool designed for **CTFs**, **HTB**, **VulnHub**, **OSCP**, and real-world penetration testing. It leverages the strengths of tools like [AutoRecon](https://github.com/Tib3rius/AutoRecon), [nmapAutomator](https://github.com/21y4d/nmapAutomator), and [Auto-Recon](https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon), while adding its own performance, reliability, and usability improvements.

Built specifically for **Kali Linux** (Debian-based), It automates service detection, runs targeted enumeration with real-time progress feedback, and ensures no tool hangs by using `timeout` controls.

All scans are optimized with `--min-rate`, `--max-parallelism`, and `--timeout` for speed and reliability. Service-specific enumerations (HTTP, SMB, SNMP, LDAP, FTP, Oracle, NFS, Redis, etc.) are handled automatically, with results saved in structured `scan/` and `loot/` directories.


If you find a bug or have a feature request, please [submit an issue on GitHub](https://github.com/giveen/autoenum/issues)


## How It Works

Autoenum automates the entire reconnaissance workflow with a **two-stage Nmap scan approach**:

1. **Service Version Scan**  
   Runs `nmap -sV` to detect service versions, enabling `searchsploit` to identify known exploits.

2. **Targeted Scan (Based on Profile)**  
   Executes a scan tailored to the selected profile (`aggr`, `reg`, `top 1k`, `top 10k`, `udp`, etc.), using optimized flags like `--min-rate 500`, `--max-parallelism 100`, and `--timeout 5` for speed and reliability.

After scans complete, Autoenum:
- Parses open ports and services from Nmap output
- Detects the target OS using **TTL-based inference** (e.g., TTL 64 = Linux, 128 = Windows)
- Extracts script output and service data
- Identifies running services (e.g., HTTP, SMB, SNMP, FTP, LDAP)

For each detected service, Autoenum **automatically launches targeted enumeration**:
- **HTTP** → `gobuster`, `nikto`, `wafw00f`, `whatweb`, `sslscan`
- **SMB** → `nmap`, `smbmap`, `rpcclient`, `smbclient`, `nmap vuln scripts`
- **SNMP** → `onesixtyone`, `snmp-check`, `snmpwalk`
- **LDAP** → `nmap`, `ldapsearch`, `ldapwhoami`
- **FTP** → `nmap`, `ftp-anon`, `ftp-vuln-cve2010-4221`
- **Oracle** → `nmap`, `odat`, `oscanner`
- **NFS** → `nmap`, `mount` (auto-mounts discovered shares)

> 🔥 **All tools run with `timeout`** to prevent hangs  
> 📊 **Results are saved in structured directories**:  
> - `scan/` – Nmap output, script results  
> - `loot/` – Service-specific outputs (e.g., `loot/http/`, `loot/smb/`)  
> - `loot/raw/` – Raw service detection files (e.g., `http_found`, `smb_found`)  

If a required tool is missing, Autoenum **auto-installs it via `apt`** — no `pip`, `go`, or `curl | bash`. It also checks for updates on every run.

> ✅ **All functionality is modular, safe, and CTF-ready**  
> ✅ **No manual intervention required** — from scan to enumeration


## Installation

Autoenum is designed for **Kali Linux** (Debian-based) and requires no external dependencies beyond standard tools.

### One-Step Installation

```bash
git clone https://github.com/giveen/autoenum.git
cd autoenum
chmod +x autoenum.sh
./autoenum.sh
```

## What's new

### Version 1.1
* First version, HTTP and SMB enumeration added as well as functionalized mess of code it was before 
* Aggressive scan added, included nmap-to-searchsploit scan for version exploit searching
* Added getopts for argument parsing to replace patchwork position-based conditionals

### Version 1.2
* Added help menu and logic to detect dependencies
* Fixed terminal breaking issue (kinda, open to ideas if there is anything better than clearing terminal output). 

### Version 1.3
* Fixed simultaneous scan issue so that both scans fire at the same time now and have a few tools for certain service enumerations to run in background as others stay in foreground to save time

### Version 1.4
* Added enumeration for various services including LDAP, SNMP, SMTP, oracle and FTP and banner
* Added file containing all commands run in case a command failed
* installs tools not detected and checks if all are up-to-date

### Version 1.4.1
* fixed searchsploit encoding issue where parts were being displayed as encoded when read from a text editor

### Version 2.0
* Autoenum now runs as a console tool similar to msfconsole. 

### Version 2.0.1
* persistent shell command

### Version 2.1 
* imap, mysql,redis enumeration

### Version 3.0
* Polished UI
* Cleaned up shell util errors and fixed escape keywords
* Added more scan options:
  * top 1k scan
  * top 10k scan
  * UDP scan
* Added Combination scans (vuln scan can be added onto any other scan)
* Added Auxilary scans:
  * Quick scan added
  * Vuln scan added
* Fixed update throwing errors issue
* Now supports URLs and FQDNs 
* Verifies the IP entered is a valid one
* aggr + reg scans now scan top 1k ports first
* Performs basic OS detecting using ttl
* searchsploit output is now sent to a JSON file for easy viewing
* nfs enum now attempts to mount discovered nfs shares
* Fixed http multiple ports not being detected issue

### Version 3.0.1
* Removed ports 47001 and 5985 from ports list to prevent them from being run through http enum
* added `-nr` flag when starting autoenum to set autoenum to not attempt to resolve an IP passed (this is good if a machine is blocking pings but we know its up)
  * Usage: `./autoenum -nr`

## Dependencies
Your OS may or may not have some installed by default. Not to worry, autoenum recognizes tools not installed and installs them for you, even updating if they aren't up-to-date!

* nmap
* nikto
* gobuster
* whatweb
* onesixtyone
* snmp-check
* snmpwalk
* fierce
* dnsenum
* dnsrecon
* sslscan
* uniscan
* snmp-user-enum
* oscanner
* wafw00f
* odat
* searchsploit
* rpcbind
* tput
* jq
* wpscan

## Thanks
Dievus

## Featured 
https://www.kitploit.com/2020/07/autoenum-automatic-service-enumeration.html
