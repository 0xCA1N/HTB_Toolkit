#!/usr/bin/env python3
"""
HTB Enumerator
Master script that orchestrates the full enumeration pipeline.
Modes: default (all defaults, just provide IP) or manual (interactive per-tool options)
Usage:
  python3 enumerate.py <IP>              # default mode
  python3 enumerate.py <IP> --manual     # manual mode
"""

import requests
from urllib.parse import urlparse
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


# ── Default tool/wordlist config ────────────────────────
DEFAULT_NMAP_CMD = "nmap -sVC -p- --min-rate 10000"

DEFAULT_DIRBUST_TOOL = "feroxbuster"
DEFAULT_DIRBUST_WORDLISTS = [
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
]

DEFAULT_SUBFUZZ_TOOL = "ffuf"
DEFAULT_SUBFUZZ_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
]

# Status code colors
STATUS_COLORS = {
    "2": C.GREEN,
    "3": C.CYAN,
    "4": C.YELLOW,
    "5": C.RED,
}


def banner(ip):
    print(f"""
{C.RED}{C.BOLD}  ╦ ╦╔╦╗╔╗   {C.CYAN}╔═╗╔╗╔╦ ╦╔╦╗
{C.RED}  ╠═╣ ║ ╠╩╗  {C.CYAN}║╣ ║║║║ ║║║║
{C.RED}  ╩ ╩ ╩ ╚═╝  {C.CYAN}╚═╝╝╚╝╚═╝╩ ╩{C.RESET}
{C.DIM}  ─────────────────────────────{C.RESET}
{C.DIM}  Target:{C.RESET}    {C.WHITE}{ip}{C.RESET}
{C.DIM}  Time:{C.RESET}      {C.WHITE}{datetime.now().strftime('%H:%M:%S')}{C.RESET}
""")


def section(title):
    print(f"\n  {C.BOLD}{C.MAGENTA}{'━' * 50}{C.RESET}")
    print(f"  {C.BOLD}{C.MAGENTA}  ▶ {title}{C.RESET}")
    print(f"  {C.BOLD}{C.MAGENTA}{'━' * 50}{C.RESET}\n")


def step(msg):
    print(f"  {C.CYAN}[●]{C.RESET} {C.WHITE}{msg}{C.RESET}")


def success(msg):
    print(f"  {C.GREEN}[✓]{C.RESET} {C.WHITE}{msg}{C.RESET}")


def warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {C.WHITE}{msg}{C.RESET}")


def fail(msg):
    print(f"  {C.RED}[✗]{C.RESET} {C.WHITE}{msg}{C.RESET}")


def ask_continue(prompt="Continue?"):
    try:
        choice = input(f"  {C.WHITE}{prompt} {C.DIM}[Y/n]{C.RESET}: ").strip().lower()
        return choice != "n"
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


def find_script(name):
    """Find a script in common locations."""
    search_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), name),
        os.path.join(os.getcwd(), name),
        os.path.expanduser(f"~/HTB_Toolkit/{name}"),
        os.path.expanduser(f"~/Documents/{name}"),
    ]
    for path in search_paths:
        if os.path.exists(path):
            return path
    return None


def first_available(paths):
    """Return the first path that exists."""
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def color_status(code):
    first = str(code)[0]
    color = STATUS_COLORS.get(first, C.WHITE)
    return f"{color}{code}{C.RESET}"


# ── Phase 1: Hostname Discovery ────────────────────────

def discover_hostname(ip):
    step(f"Probing http://{ip} for hostname redirect...")

    try:
        response = requests.get(f"http://{ip}", allow_redirects=False, timeout=10)
    except requests.exceptions.ConnectionError:
        fail(f"Could not connect to {ip}")
        return None
    except requests.exceptions.Timeout:
        fail(f"Connection to {ip} timed out")
        return None

    location = response.headers.get("Location")
    if not location:
        warn("No redirect found — target may not have a virtual host")
        return None

    hostname = urlparse(location).hostname
    if not hostname:
        warn(f"Could not parse hostname from redirect: {location}")
        return None

    success(f"Found hostname: {C.BOLD}{hostname}{C.RESET}")

    with open("/etc/hosts", "r") as f:
        hosts_content = f.read()

    if hostname in hosts_content:
        step(f"{hostname} already in /etc/hosts, skipping")
    else:
        entry = f"\n{ip} {hostname}\n"
        subprocess.run(
            ["sudo", "tee", "-a", "/etc/hosts"],
            input=entry.encode(),
            stdout=subprocess.DEVNULL,
        )
        success(f"Added '{ip} {hostname}' to /etc/hosts")

    return hostname


# ── Phase 2: Nmap Scan ─────────────────────────────────

def parse_nmap_display(raw):
    """Parse nmap output and display pretty results (same as nmap.py)."""
    lines = raw.splitlines()
    port_lines = []
    script_blocks = {}
    current_port = None

    for line in lines:
        port_match = re.match(r"^(\d+/\w+)\s+(open)\s+(\S+)\s*(.*)", line)
        if port_match:
            port, state, service, version = port_match.groups()
            current_port = port
            port_lines.append((port, service, version.strip()))
            script_blocks[port] = []
        elif line.startswith("|") and current_port:
            script_blocks[current_port].append(line)
        elif not line.startswith("|") and not line.startswith("SF:"):
            if line.strip() and not line.startswith(" "):
                current_port = None

    if not port_lines:
        print(f"  {C.YELLOW}No open ports found.{C.RESET}\n")
        return

    print(f"  {C.BOLD}{C.WHITE}{'PORT':<16}{'SERVICE':<16}{'VERSION'}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}")

    for port, service, version in port_lines:
        print(
            f"  {C.GREEN}{C.BOLD}{port:<16}{C.RESET}"
            f"{C.CYAN}{service:<16}{C.RESET}"
            f"{C.WHITE}{version}{C.RESET}"
        )
        scripts = script_blocks.get(port, [])
        if scripts:
            for sline in scripts:
                if re.match(r"^\|[_ ](\S+?):", sline):
                    key_match = re.match(r"^(\|[_ ])(\S+?:)(.*)", sline)
                    if key_match:
                        prefix, key, val = key_match.groups()
                        print(
                            f"    {C.DIM}{prefix}{C.MAGENTA}{key}{C.RESET}"
                            f"{C.WHITE}{val}{C.RESET}"
                        )
                    else:
                        print(f"    {C.DIM}{sline}{C.RESET}")
                else:
                    print(f"    {C.DIM}{sline}{C.RESET}")
    print()


def run_nmap_default(ip):
    """Run nmap directly with pretty output."""
    outfile = f"scan_{ip.replace('.', '_')}.txt"
    cmd = f"{DEFAULT_NMAP_CMD} {ip}"

    step(f"Running: {cmd}")
    step(f"Saving full output → {outfile}")
    print(f"  {C.YELLOW}Scanning...{C.RESET}\n")

    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=900)
        raw = result.stdout
        with open(outfile, "w") as f:
            f.write(raw)
        parse_nmap_display(raw)
        success(f"Full output saved to {C.BOLD}{outfile}{C.RESET}")
    except subprocess.TimeoutExpired:
        fail("Nmap scan timed out after 15 minutes")
    except KeyboardInterrupt:
        warn("Nmap scan interrupted")


def run_nmap_manual(ip):
    """Run nmap via nmap.py interactively."""
    script = find_script("nmap.py")
    if script:
        subprocess.run(["python3", script, ip])
    else:
        warn("nmap.py not found — running directly")
        run_nmap_default(ip)


# ── Phase 3: Directory Busting ─────────────────────────

def parse_feroxbuster(raw):
    hits = []
    for line in raw.splitlines():
        m = re.match(r"^\s*(\d{3})\s+\w+\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?://\S+)", line)
        if m:
            status, lines_, words, chars, url = m.groups()
            hits.append({"status": int(status), "url": url, "size": f"{chars}c"})
    return hits


def display_dirbust_hits(hits):
    if not hits:
        print(f"  {C.YELLOW}No results found.{C.RESET}\n")
        return

    seen = set()
    unique = []
    for h in hits:
        if h["url"] not in seen:
            seen.add(h["url"])
            unique.append(h)

    unique.sort(key=lambda h: (str(h["status"])[0], h["url"]))

    print(f"  {C.BOLD}{C.WHITE}{'STATUS':<10}{'SIZE':<12}{'PATH'}{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")

    for h in unique:
        status_str = color_status(h["status"])
        print(f"  {status_str:<19} {C.DIM}{h['size']:<12}{C.RESET}{C.WHITE}{h['url']}{C.RESET}")

    print(f"\n  {C.DIM}{len(unique)} unique results{C.RESET}\n")


def run_dirbust_default(url):
    """Run feroxbuster directly with defaults, pretty output, no menus."""
    if not shutil.which(DEFAULT_DIRBUST_TOOL):
        fail(f"{DEFAULT_DIRBUST_TOOL} not found — skipping directory busting")
        return

    wordlist = first_available(DEFAULT_DIRBUST_WORDLISTS)
    if not wordlist:
        fail("No wordlists found — skipping directory busting")
        return

    clean_name = re.sub(r"[^\w]", "_", url.split("//")[-1].rstrip("/"))
    outfile = f"dirbust_{clean_name}.txt"
    wl_short = os.path.basename(wordlist)

    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", "100", "-o", outfile, "--no-state"]

    step(f"Tool: {DEFAULT_DIRBUST_TOOL} | Wordlist: {wl_short}")
    step(f"Running: {' '.join(cmd)}")
    step(f"Saving full output → {outfile}")
    print(f"  {C.YELLOW}Busting...{C.RESET}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        raw = result.stdout

        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                file_content = f.read()
            if file_content.strip():
                raw = file_content

        hits = parse_feroxbuster(raw)
        display_dirbust_hits(hits)
        success(f"Full output saved to {C.BOLD}{outfile}{C.RESET}")

    except subprocess.TimeoutExpired:
        fail("Directory busting timed out after 30 minutes")
    except KeyboardInterrupt:
        warn("Directory busting interrupted")


def run_dirbust_manual(url):
    """Run dirbust.py interactively."""
    script = find_script("dirbust.py")
    if script:
        subprocess.run(["python3", script, url])
    else:
        warn("dirbust.py not found — running with defaults")
        run_dirbust_default(url)


# ── Phase 4: Subdomain Fuzzing ─────────────────────────

def parse_ffuf_subs(raw):
    hits = []
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 6 and parts[4].strip().isdigit():
            status = int(parts[4].strip())
            subdomain = parts[0].strip()
            size = parts[5].strip()
            if subdomain and subdomain != "FUZZ":
                hits.append({"status": status, "subdomain": subdomain, "size": f"{size}B"})
    return hits


def display_subfuzz_hits(hits):
    if not hits:
        print(f"  {C.YELLOW}No subdomains found.{C.RESET}\n")
        return

    seen = set()
    unique = []
    for h in hits:
        if h["subdomain"] not in seen:
            seen.add(h["subdomain"])
            unique.append(h)

    unique.sort(key=lambda h: (str(h["status"])[0], h["subdomain"]))

    print(f"  {C.BOLD}{C.WHITE}{'STATUS':<10}{'SIZE':<12}{'SUBDOMAIN'}{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")

    for h in unique:
        status_str = color_status(h["status"])
        print(f"  {status_str:<19} {C.DIM}{h['size']:<12}{C.RESET}{C.WHITE}{h['subdomain']}{C.RESET}")

    print(f"\n  {C.DIM}{len(unique)} unique subdomains{C.RESET}\n")


def add_subs_to_hosts(hits, domain, ip):
    """Auto-add discovered subdomains to /etc/hosts."""
    with open("/etc/hosts", "r") as f:
        hosts_content = f.read()

    added = 0
    for h in hits:
        sub = h["subdomain"]
        if "." not in sub:
            sub = f"{sub}.{domain}"
        if sub not in hosts_content:
            entry = f"\n{ip} {sub}\n"
            subprocess.run(
                ["sudo", "tee", "-a", "/etc/hosts"],
                input=entry.encode(),
                stdout=subprocess.DEVNULL,
            )
            success(f"Added {C.WHITE}{sub}{C.RESET} to /etc/hosts")
            added += 1
        else:
            step(f"{sub} already in /etc/hosts, skipping")

    if added:
        success(f"Added {added} new entries to /etc/hosts")


def run_subfuzz_default(domain, ip):
    """Run ffuf directly with defaults, pretty output, no menus."""
    if not shutil.which(DEFAULT_SUBFUZZ_TOOL):
        fail(f"{DEFAULT_SUBFUZZ_TOOL} not found — skipping subdomain fuzzing")
        return

    wordlist = first_available(DEFAULT_SUBFUZZ_WORDLISTS)
    if not wordlist:
        fail("No wordlists found — skipping subdomain fuzzing")
        return

    clean_name = re.sub(r"[^\w]", "_", domain)
    outfile = f"subfuzz_{clean_name}.txt"
    wl_short = os.path.basename(wordlist)

    cmd = [
        "ffuf",
        "-u", f"http://{domain}",
        "-w", wordlist,
        "-H", f"Host: FUZZ.{domain}",
        "-t", "100",
        "-o", outfile, "-of", "csv",
        "-mc", "all",
        "-ac",
    ]

    step(f"Tool: {DEFAULT_SUBFUZZ_TOOL} | Wordlist: {wl_short}")
    step(f"Running: {' '.join(cmd)}")
    step(f"Saving full output → {outfile}")
    print(f"  {C.YELLOW}Fuzzing...{C.RESET}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        raw = result.stdout

        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                file_content = f.read()
            if file_content.strip():
                raw = file_content

        hits = parse_ffuf_subs(raw)
        display_subfuzz_hits(hits)

        if hits:
            add_subs_to_hosts(hits, domain, ip)

        success(f"Full output saved to {C.BOLD}{outfile}{C.RESET}")
        return hits

    except subprocess.TimeoutExpired:
        fail("Subdomain fuzzing timed out after 30 minutes")
        return []
    except KeyboardInterrupt:
        warn("Subdomain fuzzing interrupted")
        return []


def run_subfuzz_manual(domain):
    """Run subfuzz.py interactively."""
    script = find_script("subfuzz.py")
    if script:
        subprocess.run(["python3", script, domain])
    else:
        warn("subfuzz.py not found — running with defaults")
        run_subfuzz_default(domain, None)


# ── Phase 5: CMS Detection ─────────────────────────────

def run_cms_default(urls):
    """Run CMS detection directly against all URLs, no banner."""
    script = find_script("cms.py")
    if script:
        step(f"Scanning {len(urls)} target(s) for CMS/technologies...")
        try:
            cmd = ["python3", script, "--no-banner"] + urls
            subprocess.run(cmd, timeout=120)
        except subprocess.TimeoutExpired:
            fail("CMS detection timed out")
        except KeyboardInterrupt:
            warn("CMS detection interrupted")
    else:
        fail("cms.py not found — skipping CMS detection")


def run_cms_manual(urls):
    """Run cms.py interactively."""
    script = find_script("cms.py")
    if script:
        subprocess.run(["python3", script] + urls)
    else:
        fail("cms.py not found — skipping CMS detection")


# ── Summary ─────────────────────────────────────────────

def summary(ip, hostname, phases_run):
    print(f"\n  {C.BOLD}{C.GREEN}{'━' * 50}{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}  ✓ Enumeration Complete{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}{'━' * 50}{C.RESET}\n")

    print(f"  {C.DIM}Target:{C.RESET}     {C.WHITE}{ip}{C.RESET}")
    if hostname:
        print(f"  {C.DIM}Hostname:{C.RESET}   {C.WHITE}{hostname}{C.RESET}")
    print(f"  {C.DIM}Completed:{C.RESET}  {C.WHITE}{datetime.now().strftime('%H:%M:%S')}{C.RESET}")
    print()

    print(f"  {C.DIM}Phases completed:{C.RESET}")
    for phase in phases_run:
        print(f"    {C.GREEN}✓{C.RESET} {phase}")

    outfiles = [f for f in os.listdir(".") if f.startswith(("scan_", "dirbust_", "subfuzz_", "cms_")) and f.endswith(".txt")]
    if outfiles:
        print(f"\n  {C.DIM}Output files:{C.RESET}")
        for f in sorted(outfiles):
            print(f"    {C.CYAN}→{C.RESET} {f}")
    print()


# ── Main ────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"\n  {C.YELLOW}Usage:{C.RESET} python3 {sys.argv[0]} <IP> [--manual]")
        print(f"  {C.DIM}  Default: python3 {sys.argv[0]} 10.10.10.50{C.RESET}")
        print(f"  {C.DIM}  Manual:  python3 {sys.argv[0]} 10.10.10.50 --manual{C.RESET}\n")
        sys.exit(1)

    ip = sys.argv[1]
    manual = "--manual" in sys.argv or "-m" in sys.argv

    banner(ip)

    if manual:
        print(f"  {C.YELLOW}{C.BOLD}Mode: MANUAL{C.RESET} {C.DIM}— interactive options for each phase{C.RESET}\n")
    else:
        print(f"  {C.GREEN}{C.BOLD}Mode: DEFAULT{C.RESET} {C.DIM}— all defaults, fully automated{C.RESET}\n")

    phases_run = []
    hostname = None

    # ── Phase 1: Hostname Discovery ─────────────────
    section("Phase 1: Hostname Discovery")
    hostname = discover_hostname(ip)
    phases_run.append("Hostname Discovery")

    if not hostname:
        warn("No hostname found — will scan by IP only")
        url = f"http://{ip}"
    else:
        url = f"http://{hostname}"

    # ── Phase 2: Nmap Scan ──────────────────────────
    if manual:
        if not ask_continue("Run nmap scan?"):
            warn("Skipping nmap scan")
        else:
            section("Phase 2: Nmap Scan")
            run_nmap_manual(ip)
            phases_run.append("Nmap Scan")
    else:
        section("Phase 2: Nmap Scan")
        run_nmap_default(ip)
        phases_run.append("Nmap Scan")

    # ── Phase 3: Directory Busting ──────────────────
    if manual:
        if not ask_continue("Run directory busting?"):
            warn("Skipping directory busting")
        else:
            section("Phase 3: Directory Busting")
            run_dirbust_manual(url)
            phases_run.append("Directory Busting")
    else:
        section("Phase 3: Directory Busting")
        run_dirbust_default(url)
        phases_run.append("Directory Busting")

    # ── Phase 4: Subdomain Fuzzing ──────────────────
    discovered_subs = []
    if hostname:
        if manual:
            if not ask_continue("Run subdomain fuzzing?"):
                warn("Skipping subdomain fuzzing")
            else:
                section("Phase 4: Subdomain Fuzzing")
                run_subfuzz_manual(hostname)
                phases_run.append("Subdomain Fuzzing")
        else:
            section("Phase 4: Subdomain Fuzzing")
            hits = run_subfuzz_default(hostname, ip) or []
            discovered_subs = [h["subdomain"] for h in hits]
            phases_run.append("Subdomain Fuzzing")
    else:
        warn("No hostname discovered — skipping subdomain fuzzing")

    # ── Phase 5: CMS Detection ──────────────────────
    cms_urls = [url]
    if hostname and discovered_subs:
        for sub in discovered_subs:
            full = sub if "." in sub else f"{sub}.{hostname}"
            cms_urls.append(f"http://{full}")

    if manual:
        if not ask_continue("Run CMS detection?"):
            warn("Skipping CMS detection")
        else:
            section("Phase 5: CMS Detection")
            run_cms_manual(cms_urls)
            phases_run.append("CMS Detection")
    else:
        section("Phase 5: CMS Detection")
        run_cms_default(cms_urls)
        phases_run.append("CMS Detection")

    # ── Summary ─────────────────────────────────────
    summary(ip, hostname, phases_run)


if __name__ == "__main__":
    main()