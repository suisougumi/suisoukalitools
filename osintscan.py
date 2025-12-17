#!/usr/bin/env python3
import subprocess
import argparse
import shutil
import re

# ---------- utility ----------
def run(cmd, title, timeout=300):
    print(f"\n\033[1;34m[+] {title}\033[0m")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return f"Error: {e}"

def is_ip(target):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)

def color_vuln(line):
    if "VULNERABLE" in line or "CVE-" in line:
        return f"\033[1;31m[HIGH]\033[0m {line}"
    elif "LIKELY" in line or "Risk:" in line:
        return f"\033[1;33m[MED]\033[0m {line}"
    elif "WARNING" in line:
        return f"\033[1;33m[LOW]\033[0m {line}"
    else:
        return f"\033[1;36m[INFO]\033[0m {line}"

# ---------- argparse ----------
parser = argparse.ArgumentParser(
    description="OSINT + ENUM + Conditional Vulnerability Scanner (Kali)"
)
parser.add_argument("target", help="IP address or domain")
parser.add_argument("--enum", action="store_true", help="Run enum4linux (IP only)")
parser.add_argument("--vuln", action="store_true", help="Run vulnerability checks (IP only)")

args = parser.parse_args()
target = args.target
ip_target = is_ip(target)

# ---------- OSINT ----------
print(run(["ping", "-c", "4", target], "PING"))
print(run(["whois", target], "WHOIS"))
print(run(["nslookup", target], "NSLOOKUP"))

if shutil.which("traceroute"):
    print(run(["traceroute", target], "TRACEROUTE", 60))
elif shutil.which("tracepath"):
    print(run(["tracepath", target], "TRACEPATH", 60))

# ---------- enum4linux ----------
if args.enum:
    if not ip_target:
        print("\n[!] enum4linux is IP-only. Skipping.")
    elif not shutil.which("enum4linux"):
        print("\n[!] enum4linux not installed. Skipping.")
    else:
        print(run(["enum4linux", "-a", target], "ENUM4LINUX", 180))

# ---------- vulnerability (conditional) ----------
if args.vuln:
    if not ip_target:
        print("\n[!] Vulnerability scan is IP-only. Skipping.")
    elif not shutil.which("nmap"):
        print("\n[!] nmap not installed. Skipping.")
    else:
        print("\n\033[1;35m[*] Checking open services before vulnerability scan...\033[0m")
        port_scan = run(["nmap", "-Pn", "--top-ports", "100", target], "PORT CHECK", 120)

        if "open" not in port_scan:
            print("\n\033[1;32m[✓] No open services detected. Skipping vuln scan.\033[0m")
        else:
            print("\n\033[1;31m[!] Open services detected. Running vulnerability scan.\033[0m")
            vuln_output = run(
                ["nmap", "-sV", "--script", "vuln", target],
                "NMAP VULNERABILITY SCAN",
                300
            )

            print("\n\033[1;34m[+] Vulnerability Summary\033[0m")
            for line in vuln_output.splitlines():
                print(color_vuln(line))
