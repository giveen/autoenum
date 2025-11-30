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

## What's New

| Version | Changes |
|--------|---------|
| **3.0.2** | • All service enumeration functions (`enum.sh`) fully optimized for speed, reliability, and accuracy<br>• Added `--timeout` and `--progress` flags to all scans and services<br>• All tools now run with `timeout` to prevent hanging (e.g., `nmap`, `gobuster`, `smtp-user-enum`, `odat`)<br>• Real-time progress feedback every 10 seconds during long scans<br>• Fixed `nfs_enum` mount path typo (`loots` → `loot`)<br>• Improved `ldap_enum` with better error handling and `--timeout` support<br>• Enhanced `http_enum` with parallel processing and `curl` health check<br>• Added `--dry-run` support to all functions for safe testing<br>• All Nmap scans use `--min-rate 500`, `--max-parallelism 100`, and `--timeout 5`<br>• Updated `check_deps.sh` to ensure `gem` is installed (for `wpscan`)<br>• Banner now credits both authors: `giveen` (you) and `Grimmie` (original author)<br>• All scan profiles (`aggr`, `reg`, `top 1k`, `top 10k`, `udp`, `vuln`) now support `--timeout` and `--progress`<br>• Cleaned up `scans.sh` with consistent error handling and progress feedback<br>• Improved `menu.sh` with better UX and `--help` integration<br>• Added `--dry-run` flag to `autoenum.sh` for testing without execution |
| **3.0.1** | • Removed ports `47001` and `5985` from HTTP enumeration to prevent false positives<br>• Added `-nr` flag to skip DNS resolution (ideal when ping is blocked but target is known)<br>• Usage: `./autoenum.sh -nr` |
| **3.0** | • Polished UI with smoother transitions and better feedback<br>• Cleaned up shell utility errors and fixed escape keyword issues<br>• Added support for URLs and FQDNs (auto-resolves to IP)<br>• Enhanced OS detection using TTL-based inference (e.g., TTL 64 = Linux)<br>• SearchSploit output saved as JSON (`*.json`) for easy parsing<br>• NFS enumeration now auto-mounts discovered shares<br>• Fixed HTTP enumeration to detect multiple ports correctly<br>• Added new scan profiles:<br>  - `top 1k` – Scan top 1,000 ports<br>  - `top 10k` – Scan top 10,000 ports<br>  - `UDP` – Scan top 100 UDP ports<br>• Added combo scans (e.g., `aggr+vuln`, `reg+vuln`, `top 1k+vuln`, `top 10k+vuln`)<br>• Added auxiliary scans:<br>  - `quick` – Fast scan with scripts enabled<br>  - `vuln` – Exploit detection via `nmap` and `vulscan`<br>• Fixed `upgrade` script to prevent errors<br>• All functions now use `apt` only — no `pip`, `go`, or `curl | bash` |
| **2.1** | • Added enumeration for IMAP, MySQL, and Redis<br>• Expanded service detection to include LDAP, SMTP, FTP, Oracle, and NFS |
| **2.0** | • Rewritten as a console-style tool (like `msfconsole`)<br>• Persistent shell mode added (`shell` command) |
| **2.0.1** | • Added persistent shell command for easier interaction |
| **1.4** | • Added LDAP, SNMP, SMTP, FTP, Oracle, and banner<br>• Added command log file for troubleshooting<br>• Auto-installs missing tools and checks for updates |
| **1.4.1** | • Fixed searchsploit encoding issue where output was displayed as encoded characters |
| **1.3** | • Fixed simultaneous scan issue — both scans now run in parallel<br>• Added background tools to keep scans efficient |
| **1.2** | • Added help menu and dependency detection logic<br>• Fixed terminal breaking issue (partial fix) |
| **1.1** | • First version with HTTP and SMB enumeration<br>• Added aggressive scan with nmap-to-searchsploit integration<br>• Added `getopts` for argument parsing (replaced position-based conditionals) |


## Dependencies

Your OS may or may not have some tools installed by default. Autoenum automatically detects missing tools and installs them via `apt` — **no `pip`, `go`, or `curl | bash`** required.

| Tool | Purpose |
|------|--------|
| `nmap` | Core network scanner for port discovery, service detection, and vulnerability scanning |
| `nikto` | Web server scanner that checks for outdated software, dangerous files, and common exploits |
| `gobuster` | Directory and file brute-forcing tool for web enumeration |
| `whatweb` | Website analyzer that identifies web technologies (CMS, frameworks, servers) |
| `onesixtyone` | SNMP brute-forcer that tests common community strings (e.g., `public`) |
| `snmp-check` | SNMP enumeration tool that checks for default credentials and service versions |
| `snmpwalk` | SNMP tool to retrieve information from SNMP-enabled devices |
| `fierce` | DNS enumeration tool that performs aggressive DNS queries to discover subdomains |
| `dnsenum` | DNS enumeration tool for discovering hosts, zones, and subdomains |
| `dnsrecon` | Comprehensive DNS reconnaissance tool with support for zone transfers, brute-forcing, and more |
| `sslscan` | SSL/TLS scanner that checks for weak ciphers, expired certificates, and vulnerabilities |
| `uniscan` | Web application scanner that performs automated vulnerability testing |
| `snmp-user-enum` | Enumerates valid user accounts via SNMP (e.g., `VRFY` command) |
| `oscanner` | Oracle scanner that detects Oracle databases and attempts to identify versions and services |
| `wafw00f` | Web Application Firewall (WAF) detection tool that identifies if a WAF is in place |
| `odat` | Oracle Database Attack Tool for exploiting Oracle DBs (e.g., brute-force, SQL injection) |
| `searchsploit` | Local search tool for Exploit-DB (identifies known exploits by service/version) |
| `rpcbind` | RPC service that maps RPC program numbers to transport addresses |
| `tput` | Terminal control tool used for color and cursor manipulation (e.g., banners, UI) |
| `jq` | Command-line JSON processor used for parsing and filtering JSON output (e.g., `searchsploit` JSON) |
| `wpscan` | WordPress vulnerability scanner that detects themes, plugins, and known exploits |


## Thanks
Dievus

## Featured 
https://www.kitploit.com/2020/07/autoenum-automatic-service-enumeration.html
