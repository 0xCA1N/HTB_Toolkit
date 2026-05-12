#!/usr/bin/env python3
"""
HTB Subdomain Fuzzer
Clean, colorful console output — only hits shown. Full results saved to file.
Supports: ffuf, gobuster, wfuzz, amass
Usage: python3 subfuzz.py <domain>
"""

import subprocess
import sys
import re
import shutil
import os
from datetime import datetime


# ── Colors ──────────────────────────────────────────────
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# ── Config ──────────────────────────────────────────────
WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    "/usr/share/seclists/Discovery/DNS/namelist.txt",
]

# Tools in preference order
TOOLS = ["ffuf", "gobuster", "wfuzz", "amass"]

# Status code colors
STATUS_COLORS = {
    "2": C.GREEN,
    "3": C.CYAN,
    "4": C.YELLOW,
    "5": C.RED,
}


def banner(domain, tool, wordlist):
    wl_short = os.path.basename(wordlist)
    print(f"""
{C.RED}{C.BOLD}  ╔═╗╦ ╦╔╗   {C.CYAN}╔═╗╦ ╦╔═╗╔═╗
{C.RED}  ╚═╗║ ║╠╩╗  {C.CYAN}╠╣ ║ ║╔═╝╔═╝
{C.RED}  ╚═╝╚═╝╚═╝  {C.CYAN}╚  ╚═╝╚═╝╚═╝{C.RESET}
{C.DIM}  ─────────────────────────────{C.RESET}
{C.DIM}  Domain:{C.RESET}    {C.WHITE}{domain}{C.RESET}
{C.DIM}  Tool:{C.RESET}      {C.WHITE}{tool}{C.RESET}
{C.DIM}  Wordlist:{C.RESET}  {C.WHITE}{wl_short}{C.RESET}
{C.DIM}  Time:{C.RESET}      {C.WHITE}{datetime.now().strftime('%H:%M:%S')}{C.RESET}
""")


def pick_tool():
    """Let user pick from available tools or auto-select."""
    available = [t for t in TOOLS if shutil.which(t)]
    if not available:
        print(f"  {C.RED}[!] No supported tools found.{C.RESET}")
        print(f"  {C.DIM}    Install one of: {', '.join(TOOLS)}{C.RESET}\n")
        sys.exit(1)

    if len(available) == 1:
        return available[0]

    print(f"  {C.BOLD}{C.WHITE}Available tools:{C.RESET}")
    for i, t in enumerate(available):
        marker = f"{C.GREEN}★{C.RESET} " if i == 0 else "  "
        print(f"    {marker}{C.CYAN}[{i + 1}]{C.RESET} {t}")
    print()

    try:
        choice = input(f"  {C.WHITE}Select tool {C.DIM}[1]{C.RESET}: ").strip()
        if choice == "" or not choice.isdigit():
            return available[0]
        idx = int(choice) - 1
        if 0 <= idx < len(available):
            return available[idx]
        return available[0]
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


def pick_wordlist():
    """Let user pick from available wordlists or auto-select."""
    available = [w for w in WORDLISTS if os.path.exists(w)]
    if not available:
        print(f"  {C.RED}[!] No wordlists found.{C.RESET}")
        print(f"  {C.DIM}    Checked: {', '.join(WORDLISTS)}{C.RESET}\n")
        sys.exit(1)

    if len(available) == 1:
        return available[0]

    print(f"  {C.BOLD}{C.WHITE}Available wordlists:{C.RESET}")
    for i, w in enumerate(available):
        name = os.path.basename(w)
        marker = f"{C.GREEN}★{C.RESET} " if i == 0 else "  "
        print(f"    {marker}{C.CYAN}[{i + 1}]{C.RESET} {name}")
    print()

    try:
        choice = input(f"  {C.WHITE}Select wordlist {C.DIM}[1]{C.RESET}: ").strip()
        if choice == "" or not choice.isdigit():
            return available[0]
        idx = int(choice) - 1
        if 0 <= idx < len(available):
            return available[idx]
        return available[0]
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


def ask_filter():
    """Ask user how to filter false positives."""
    print(f"  {C.BOLD}{C.WHITE}Response filtering:{C.RESET}")
    print(f"  {C.DIM}  Filter out responses by size to remove false positives.{C.RESET}")
    print(f"  {C.DIM}  Tip: run once, note the common response size, then re-run with filter.{C.RESET}")
    print()
    try:
        fs = input(f"  {C.WHITE}Filter size {C.DIM}(bytes, enter to auto-calibrate){C.RESET}: ").strip()
        if fs and fs.isdigit():
            return fs
        return ""
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


# ── Tool Runners ────────────────────────────────────────

def run_ffuf(domain, wordlist, filter_size, outfile):
    cmd = [
        "ffuf",
        "-u", f"http://{domain}",
        "-w", wordlist,
        "-H", f"Host: FUZZ.{domain}",
        "-t", "100",
        "-o", outfile, "-of", "csv",
        "-mc", "all",
    ]
    if filter_size:
        cmd += ["-fs", filter_size]
    else:
        cmd += ["-ac"]
    return cmd


def run_gobuster(domain, wordlist, filter_size, outfile):
    cmd = [
        "gobuster", "vhost",
        "-u", f"http://{domain}",
        "-w", wordlist,
        "-t", "100",
        "-o", outfile,
        "--no-error",
        "--append-domain",
    ]
    return cmd


def run_wfuzz(domain, wordlist, filter_size, outfile):
    cmd = [
        "wfuzz",
        "-u", f"http://{domain}",
        "-H", f"Host: FUZZ.{domain}",
        "-w", wordlist,
        "--hc", "404",
        "-f", f"{outfile},raw",
    ]
    if filter_size:
        cmd += ["--hs", filter_size]
    return cmd


def run_amass(domain, wordlist, filter_size, outfile):
    cmd = [
        "amass", "enum",
        "-passive",
        "-d", domain,
        "-o", outfile,
    ]
    return cmd


BUILD_CMD = {
    "ffuf": run_ffuf,
    "gobuster": run_gobuster,
    "wfuzz": run_wfuzz,
    "amass": run_amass,
}


# ── Parsers ─────────────────────────────────────────────

def color_status(code):
    """Return colored status code string."""
    first = str(code)[0]
    color = STATUS_COLORS.get(first, C.WHITE)
    return f"{color}{code}{C.RESET}"


def parse_ffuf(raw):
    hits = []
    for line in raw.splitlines():
        parts = line.split(",")
        # CSV: FUZZ,url,redirectlocation,position,status_code,content_length,...
        if len(parts) >= 6 and parts[4].strip().isdigit():
            status = int(parts[4].strip())
            subdomain = parts[0].strip()
            size = parts[5].strip()
            if subdomain and subdomain != "FUZZ":
                hits.append({"status": status, "subdomain": subdomain, "size": f"{size}B"})
    return hits


def parse_gobuster(raw):
    hits = []
    for line in raw.splitlines():
        # Format: Found: sub.domain.htb Status: 200 [Size: 1234]
        m = re.match(r"^Found:\s+(\S+)\s+Status:\s*(\d{3})\s+\[Size:\s*(\d+)\]", line)
        if m:
            subdomain, status, size = m.groups()
            hits.append({"status": int(status), "subdomain": subdomain, "size": f"{size}B"})
            continue
        # Older format: sub.domain.htb (Status: 200) [Size: 1234]
        m = re.match(r"^(\S+)\s+\(Status:\s*(\d{3})\)\s+\[Size:\s*(\d+)\]", line)
        if m:
            subdomain, status, size = m.groups()
            hits.append({"status": int(status), "subdomain": subdomain, "size": f"{size}B"})
    return hits


def parse_wfuzz(raw):
    hits = []
    for line in raw.splitlines():
        # Format: 000000001:   200        10 L      20 W       1234 Ch    "sub"
        m = re.match(r"^\d+:\s+C=(\d{3})\s+\d+\s+L\s+\d+\s+W\s+(\d+)\s+Ch\s+\"(.+?)\"", line)
        if m:
            status, size, subdomain = m.groups()
            hits.append({"status": int(status), "subdomain": subdomain, "size": f"{size}B"})
    return hits


def parse_amass(raw):
    hits = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "." in line:
            hits.append({"status": 0, "subdomain": line, "size": "—"})
    return hits


PARSE_OUTPUT = {
    "ffuf": parse_ffuf,
    "gobuster": parse_gobuster,
    "wfuzz": parse_wfuzz,
    "amass": parse_amass,
}


def display_hits(hits, tool):
    """Display parsed hits in a clean table."""
    if not hits:
        print(f"  {C.YELLOW}No subdomains found.{C.RESET}\n")
        return

    # Deduplicate by subdomain
    seen = set()
    unique = []
    for h in hits:
        if h["subdomain"] not in seen:
            seen.add(h["subdomain"])
            unique.append(h)

    # Sort: 2xx first, then by subdomain
    unique.sort(key=lambda h: (str(h["status"])[0] if h["status"] else "9", h["subdomain"]))

    # amass doesn't return status codes
    if tool == "amass":
        print(f"  {C.BOLD}{C.WHITE}{'SUBDOMAIN'}{C.RESET}")
        print(f"  {C.DIM}{'─' * 50}{C.RESET}")
        for h in unique:
            print(f"  {C.GREEN}{h['subdomain']}{C.RESET}")
    else:
        print(f"  {C.BOLD}{C.WHITE}{'STATUS':<10}{'SIZE':<12}{'SUBDOMAIN'}{C.RESET}")
        print(f"  {C.DIM}{'─' * 60}{C.RESET}")
        for h in unique:
            status_str = color_status(h["status"])
            print(f"  {status_str:<19} {C.DIM}{h['size']:<12}{C.RESET}{C.WHITE}{h['subdomain']}{C.RESET}")

    print(f"\n  {C.DIM}{len(unique)} unique subdomains{C.RESET}\n")


# ── /etc/hosts helper ──────────────────────────────────

def offer_hosts_update(hits, domain):
    """Offer to add discovered subdomains to /etc/hosts."""
    try:
        print(f"  {C.BOLD}{C.WHITE}Add subdomains to /etc/hosts?{C.RESET}")
        add = input(f"  {C.WHITE}[y/N]{C.RESET}: ").strip().lower()
        if add != "y":
            return

        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()

        # Try to find the IP for this domain from /etc/hosts
        ip_match = re.search(rf"^([\d.]+)\s+.*{re.escape(domain)}", hosts_content, re.MULTILINE)
        if ip_match:
            ip = ip_match.group(1)
            print(f"  {C.DIM}Found IP {ip} for {domain} in /etc/hosts{C.RESET}")
        else:
            ip = input(f"  {C.WHITE}IP address for {domain}{C.RESET}: ").strip()
            if not ip:
                print(f"  {C.YELLOW}Skipped.{C.RESET}\n")
                return

        added = 0
        for h in hits:
            sub = h["subdomain"]
            # Ensure it's a full domain
            if "." not in sub:
                sub = f"{sub}.{domain}"
            if sub not in hosts_content:
                entry = f"\n{ip} {sub}\n"
                subprocess.run(
                    ["sudo", "tee", "-a", "/etc/hosts"],
                    input=entry.encode(),
                    stdout=subprocess.DEVNULL,
                )
                print(f"  {C.GREEN}[+]{C.RESET} Added {C.WHITE}{sub}{C.RESET}")
                added += 1
            else:
                print(f"  {C.DIM}[~] {sub} already exists{C.RESET}")

        if added:
            print(f"\n  {C.GREEN}✓{C.RESET} Added {added} entries to /etc/hosts\n")
        else:
            print(f"\n  {C.DIM}All subdomains already in /etc/hosts{C.RESET}\n")

    except (KeyboardInterrupt, EOFError):
        print()


# ── Main ────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"\n  {C.YELLOW}Usage:{C.RESET} python3 {sys.argv[0]} <domain>")
        print(f"  {C.DIM}  Example: python3 {sys.argv[0]} soulmate.htb{C.RESET}\n")
        sys.exit(1)

    domain = sys.argv[1]
    # Strip protocol if provided
    domain = re.sub(r"^https?://", "", domain).rstrip("/")

    print()

    # Interactive setup
    tool = pick_tool()
    print()
    wordlist = pick_wordlist()
    print()

    filter_size = ""
    if tool != "amass":
        filter_size = ask_filter()
        print()

    # Output file
    clean_name = re.sub(r"[^\w]", "_", domain)
    outfile = f"subfuzz_{clean_name}.txt"

    banner(domain, tool, wordlist)

    # Build and run command
    cmd = BUILD_CMD[tool](domain, wordlist, filter_size, outfile)

    print(f"  {C.DIM}Running: {' '.join(cmd)}{C.RESET}")
    print(f"  {C.DIM}Saving full output → {outfile}{C.RESET}")
    print(f"  {C.YELLOW}Fuzzing...{C.RESET}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        raw = result.stdout

        # Some tools write to file directly, some to stdout
        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                file_content = f.read()
            if file_content.strip():
                raw = file_content
        else:
            with open(outfile, "w") as f:
                f.write(raw)
                if result.stderr:
                    f.write("\n--- STDERR ---\n")
                    f.write(result.stderr)

    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] Scan timed out after 30 minutes.{C.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {C.RED}[!] Scan interrupted.{C.RESET}")
        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                raw = f.read()
            if raw.strip():
                print(f"  {C.YELLOW}Partial results:{C.RESET}\n")
                hits = PARSE_OUTPUT[tool](raw)
                display_hits(hits, tool)
                print(f"  {C.GREEN}✓{C.RESET} Partial output saved to {C.BOLD}{outfile}{C.RESET}\n")
        sys.exit(0)

    # Parse and display
    hits = PARSE_OUTPUT[tool](raw)
    display_hits(hits, tool)

    # Offer to add to /etc/hosts
    if hits:
        offer_hosts_update(hits, domain)

    print(f"  {C.GREEN}✓{C.RESET} Full output saved to {C.BOLD}{outfile}{C.RESET}\n")


if __name__ == "__main__":
    main()