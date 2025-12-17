# osintscan

OSINT / SMB enumeration / Safe vulnerability scanning tool for Kali Linux.

## Features
- OSINT gathering (ping, whois, nslookup, traceroute)
- SMB enumeration via enum4linux (IP only)
- Conditional vulnerability scanning using Nmap NSE
- Severity-colored vulnerability output
- Safe, non-exploit checks only

## Usage
```bash
osintscan <target>

# SMB enumeration
osintscan <targetip> --enum

# Vulnerability scan (safe)
osintscan <targetip> --vuln

# Combined
osintscan <targetip> --enum --vuln
