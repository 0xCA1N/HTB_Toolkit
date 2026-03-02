#!/usr/bin/env python3
"""
HTB Directory Buster
Clean, colorful console output — only hits shown. Full results saved to file.
Supports: feroxbuster, gobuster, ffuf, dirb
Usage: python3 htb_dirbust.py <url>
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
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

# Tools in preference order
TOOLS = ["feroxbuster", "gobuster", "ffuf", "dirb"]

# Status code colors
STATUS_COLORS = {
    "2": C.GREEN,   # 2xx
    "3": C.CYAN,    # 3xx
    "4": C.YELLOW,  # 4xx (403s can be interesting)
    "5": C.RED,     # 5xx
}


def banner(url, tool, wordlist):
    wl_short = os.path.basename(wordlist)
    print(f"""
{C.RED}{C.BOLD}  ╔╦╗╦╦═╗  {C.CYAN}╔╗ ╦ ╦╔═╗╔╦╗
{C.RED}   ║║║╠╦╝  {C.CYAN}╠╩╗║ ║╚═╗ ║
{C.RED}  ═╩╝╩╩╚═  {C.CYAN}╚═╝╚═╝╚═╝ ╩{C.RESET}
{C.DIM}  ─────────────────────────────{C.RESET}
{C.DIM}  Target:{C.RESET}    {C.WHITE}{url}{C.RESET}
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


def ask_extensions():
    """Ask user for file extensions to scan."""
    print(f"  {C.BOLD}{C.WHITE}File extensions to scan:{C.RESET}")
    print(f"  {C.DIM}  Common: php, html, txt, asp, aspx, jsp, bak, old, conf{C.RESET}")
    print()
    try:
        ext = input(f"  {C.WHITE}Extensions {C.DIM}(comma-sep, enter to skip){C.RESET}: ").strip()
        if ext:
            return ",".join(e.strip().lstrip(".") for e in ext.split(",") if e.strip())
        return ""
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


# ── Tool Runners ────────────────────────────────────────

def run_feroxbuster(url, wordlist, extensions, outfile):
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", "100", "-o", outfile, "--no-state"]
    if extensions:
        cmd += ["-x", extensions]
    return cmd


def run_gobuster(url, wordlist, extensions, outfile):
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "100", "-o", outfile, "--no-error"]
    if extensions:
        cmd += ["-x", extensions]
    return cmd


def run_ffuf(url, wordlist, extensions, outfile):
    fuzz_url = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-t", "100", "-o", outfile, "-of", "csv",
           "-mc", "200,204,301,302,307,401,403,405"]
    if extensions:
        ext_str = ",".join(f".{e}" for e in extensions.split(","))
        cmd += ["-e", ext_str]
    return cmd


def run_dirb(url, wordlist, extensions, outfile):
    cmd = ["dirb", url, wordlist, "-o", outfile, "-S"]
    if extensions:
        cmd += ["-X", ",".join(f".{e}" for e in extensions.split(","))]
    return cmd


BUILD_CMD = {
    "feroxbuster": run_feroxbuster,
    "gobuster": run_gobuster,
    "ffuf": run_ffuf,
    "dirb": run_dirb,
}


# ── Parsers ─────────────────────────────────────────────

def color_status(code):
    """Return colored status code string."""
    first = str(code)[0]
    color = STATUS_COLORS.get(first, C.WHITE)
    return f"{color}{code}{C.RESET}"


def parse_feroxbuster(raw):
    hits = []
    for line in raw.splitlines():
        m = re.match(r"^\s*(\d{3})\s+\w+\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?://\S+)", line)
        if m:
            status, lines, words, chars, url = m.groups()
            hits.append({"status": int(status), "url": url, "size": f"{chars}c"})
    return hits


def parse_gobuster(raw):
    hits = []
    for line in raw.splitlines():
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d{3})\)\s+\[Size:\s*(\d+)\]", line)
        if m:
            path, status, size = m.groups()
            hits.append({"status": int(status), "url": path, "size": f"{size}B"})
    return hits


def parse_ffuf(raw):
    hits = []
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 6 and parts[4].strip().isdigit():
            status = int(parts[4].strip())
            url = parts[1].strip() if parts[1].strip().startswith("http") else parts[0].strip()
            size = parts[5].strip()
            hits.append({"status": status, "url": url, "size": f"{size}B"})
    return hits


def parse_dirb(raw):
    hits = []
    for line in raw.splitlines():
        m = re.match(r"^\+\s+(https?://\S+)\s+\(CODE:(\d{3})\|SIZE:(\d+)\)", line)
        if m:
            url, status, size = m.groups()
            hits.append({"status": int(status), "url": url, "size": f"{size}B"})
    return hits


PARSE_OUTPUT = {
    "feroxbuster": parse_feroxbuster,
    "gobuster": parse_gobuster,
    "ffuf": parse_ffuf,
    "dirb": parse_dirb,
}


def display_hits(hits):
    """Display parsed hits in a clean table."""
    if not hits:
        print(f"  {C.YELLOW}No results found.{C.RESET}\n")
        return

    # Deduplicate by URL
    seen = set()
    unique = []
    for h in hits:
        if h["url"] not in seen:
            seen.add(h["url"])
            unique.append(h)

    # Sort: 2xx first, then 3xx, then rest
    unique.sort(key=lambda h: (str(h["status"])[0], h["url"]))

    # Header
    print(f"  {C.BOLD}{C.WHITE}{'STATUS':<10}{'SIZE':<12}{'PATH'}{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")

    for h in unique:
        status_str = color_status(h["status"])
        print(f"  {status_str:<19} {C.DIM}{h['size']:<12}{C.RESET}{C.WHITE}{h['url']}{C.RESET}")

    print(f"\n  {C.DIM}{len(unique)} unique results{C.RESET}\n")


# ── Main ────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"\n  {C.YELLOW}Usage:{C.RESET} python3 {sys.argv[0]} <url>")
        print(f"  {C.DIM}  Example: python3 {sys.argv[0]} http://10.10.10.50{C.RESET}\n")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"http://{url}"

    print()

    # Interactive setup
    tool = pick_tool()
    print()
    wordlist = pick_wordlist()
    print()
    extensions = ask_extensions()
    print()

    # Output file
    clean_name = re.sub(r"[^\w]", "_", url.split("//")[-1].rstrip("/"))
    outfile = f"dirbust_{clean_name}.txt"

    banner(url, tool, wordlist)

    # Build and run command
    cmd = BUILD_CMD[tool](url, wordlist, extensions, outfile)

    print(f"  {C.DIM}Running: {' '.join(cmd)}{C.RESET}")
    print(f"  {C.DIM}Saving full output → {outfile}{C.RESET}")
    print(f"  {C.YELLOW}Busting...{C.RESET}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        raw = result.stdout

        # Some tools write to file directly, some to stdout
        if os.path.exists(outfile):
            with open(outfile, "r") as f:
                file_content = f.read()
            if len(file_content) > len(raw):
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
                display_hits(hits)
                print(f"  {C.GREEN}✓{C.RESET} Partial output saved to {C.BOLD}{outfile}{C.RESET}\n")
        sys.exit(0)

    # Parse and display
    hits = PARSE_OUTPUT[tool](raw)
    display_hits(hits)

    print(f"  {C.GREEN}✓{C.RESET} Full output saved to {C.BOLD}{outfile}{C.RESET}\n")


if __name__ == "__main__":
    main()