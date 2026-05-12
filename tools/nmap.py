#!/usr/bin/env python3
"""
HTB Nmap Scanner
Clean, colorful console output — full results saved to file.
Usage: python3 htb_scan.py <target_ip>
"""

import subprocess
import sys
import re
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


def banner(target):
    print(f"""
{C.RED}{C.BOLD}  ╦ ╦╔╦╗╔╗   {C.CYAN}╔═╗╔═╗╔═╗╔╗╔
{C.RED}  ╠═╣ ║ ╠╩╗  {C.CYAN}╚═╗║  ╠═╣║║║
{C.RED}  ╩ ╩ ╩ ╚═╝  {C.CYAN}╚═╝╚═╝╩ ╩╝╚╝{C.RESET}
{C.DIM}  ─────────────────────────────{C.RESET}
{C.DIM}  Target:{C.RESET}  {C.WHITE}{target}{C.RESET}
{C.DIM}  Time:{C.RESET}    {C.WHITE}{datetime.now().strftime('%H:%M:%S')}{C.RESET}
""")


def parse_and_display(raw_output):
    """Parse nmap output — display open ports with service info and script output."""
    lines = raw_output.splitlines()
    port_lines = []
    script_blocks = {}
    current_port = None

    for line in lines:
        # Match open port lines: "80/tcp open http Apache httpd 2.4.41"
        port_match = re.match(
            r"^(\d+/\w+)\s+(open)\s+(\S+)\s*(.*)", line
        )
        if port_match:
            port, state, service, version = port_match.groups()
            current_port = port
            port_lines.append((port, service, version.strip()))
            script_blocks[port] = []
        # Script output lines start with "|" or "| "
        elif line.startswith("|") and current_port:
            script_blocks[current_port].append(line)
        # End of script output for a port
        elif not line.startswith("|") and not line.startswith("SF:"):
            if line.strip() and not line.startswith(" "):
                current_port = None

    if not port_lines:
        print(f"  {C.YELLOW}No open ports found.{C.RESET}\n")
        return

    # Header
    print(f"  {C.BOLD}{C.WHITE}{'PORT':<16}{'SERVICE':<16}{'VERSION'}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}")

    # Port rows + script output
    for port, service, version in port_lines:
        print(
            f"  {C.GREEN}{C.BOLD}{port:<16}{C.RESET}"
            f"{C.CYAN}{service:<16}{C.RESET}"
            f"{C.WHITE}{version}{C.RESET}"
        )

        scripts = script_blocks.get(port, [])
        if scripts:
            for sline in scripts:
                # Colorize script headers like "|_http-title:" vs regular lines
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


def main():
    if len(sys.argv) != 2:
        print(f"\n  {C.YELLOW}Usage:{C.RESET} python3 {sys.argv[0]} <target_ip>\n")
        sys.exit(1)

    target = sys.argv[1]
    outfile = f"scan_{target.replace('.', '_')}.txt"

    banner(target)

    cmd = f"nmap -sVC -p- --min-rate 10000 {target}"
    print(f"  {C.DIM}Running: {cmd}{C.RESET}")
    print(f"  {C.DIM}Saving full output → {outfile}{C.RESET}")
    print(f"  {C.YELLOW}Scanning...{C.RESET}\n")

    try:
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=900
        )
        raw = result.stdout
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] Scan timed out after 15 minutes.{C.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {C.RED}[!] Scan interrupted.{C.RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"  {C.RED}[!] nmap not found. Install it first.{C.RESET}")
        sys.exit(1)

    # Save full output
    with open(outfile, "w") as f:
        f.write(raw)

    # Display clean results
    parse_and_display(raw)

    print(f"  {C.GREEN}✓{C.RESET} Full output saved to {C.BOLD}{outfile}{C.RESET}\n")


if __name__ == "__main__":
    main()