#!/usr/bin/env python3
"""
HTB CMS Detector
Fingerprints CMS, frameworks, and web technologies on target URLs.
Checks headers, meta tags, common paths, and optionally runs WhatWeb.
Usage: python3 cms_detect.py <url> [url2] [url3] ...
"""

import requests
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


# ── CMS Fingerprints ───────────────────────────────────

CMS_PATHS = {
    "WordPress": [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/",
        "/wp-includes/",
        "/xmlrpc.php",
        "/wp-json/",
    ],
    "Joomla": [
        "/administrator/",
        "/components/",
        "/modules/",
        "/plugins/",
        "/templates/",
        "/configuration.php",
    ],
    "Drupal": [
        "/user/login",
        "/core/misc/drupal.js",
        "/sites/default/",
        "/misc/drupal.js",
        "/core/CHANGELOG.txt",
        "/CHANGELOG.txt",
    ],
    "Magento": [
        "/admin/",
        "/skin/frontend/",
        "/js/mage/",
        "/downloader/",
        "/app/etc/local.xml",
    ],
    "phpMyAdmin": [
        "/phpmyadmin/",
        "/pma/",
        "/phpMyAdmin/",
        "/myadmin/",
    ],
    "Tomcat": [
        "/manager/html",
        "/manager/status",
        "/host-manager/html",
    ],
    "GitLab": [
        "/users/sign_in",
        "/-/explore",
    ],
    "Grafana": [
        "/api/health",
        "/login",
    ],
    "Jenkins": [
        "/login",
        "/api/json",
    ],
    "Webmin": [
        "/session_login.cgi",
    ],
    "Laravel": [
        "/_debugbar/",
        "/telescope/",
    ],
    "ColdFusion": [
        "/CFIDE/administrator/",
        "/CFIDE/",
    ],
}

# HTML patterns to look for in page source
HTML_SIGNATURES = {
    "WordPress": [
        r'wp-content/',
        r'wp-includes/',
        r'<meta name=["\']generator["\'] content=["\']WordPress[\s\d.]*["\']',
        r'wp-json',
    ],
    "Joomla": [
        r'<meta name=["\']generator["\'] content=["\']Joomla',
        r'/media/system/js/',
        r'/templates/\w+/',
        r'com_content',
    ],
    "Drupal": [
        r'Drupal\.settings',
        r'<meta name=["\']Generator["\'] content=["\']Drupal',
        r'sites/default/files',
        r'drupal\.js',
    ],
    "Magento": [
        r'Mage\.Cookies',
        r'/skin/frontend/',
        r'magento',
    ],
    "GitLab": [
        r'gitlab-ce',
        r'gitlab-ee',
        r'<meta content=["\']GitLab',
    ],
    "Grafana": [
        r'grafana-app',
        r'<title>Grafana</title>',
    ],
    "Jenkins": [
        r'<title>Dashboard \[Jenkins\]</title>',
        r'jenkins-version',
        r'X-Jenkins',
    ],
    "Laravel": [
        r'laravel_session',
        r'csrf-token',
    ],
}

# Response header fingerprints
HEADER_SIGNATURES = {
    "X-Powered-By": {
        r"PHP": "PHP",
        r"ASP\.NET": "ASP.NET",
        r"Express": "Express.js",
        r"Servlet": "Java Servlet",
    },
    "X-Generator": {
        r"WordPress": "WordPress",
        r"Joomla": "Joomla",
        r"Drupal": "Drupal",
    },
    "Server": {
        r"Apache": "Apache",
        r"nginx": "Nginx",
        r"IIS": "Microsoft IIS",
        r"Werkzeug": "Flask/Werkzeug",
        r"gunicorn": "Gunicorn (Python)",
        r"Jetty": "Jetty (Java)",
        r"openresty": "OpenResty",
    },
    "X-Jenkins": {
        r".*": "Jenkins",
    },
    "X-Drupal-Cache": {
        r".*": "Drupal",
    },
    "X-Redirect-By": {
        r"WordPress": "WordPress",
    },
}

# Cookie fingerprints
COOKIE_SIGNATURES = {
    r"PHPSESSID": "PHP",
    r"JSESSIONID": "Java",
    r"ASP\.NET_SessionId": "ASP.NET",
    r"laravel_session": "Laravel",
    r"wp-settings": "WordPress",
    r"joomla": "Joomla",
    r"grafana_session": "Grafana",
}


def banner(urls):
    targets = urls[0] if len(urls) == 1 else f"{urls[0]} (+{len(urls) - 1} more)"
    print(f"""
{C.RED}{C.BOLD}  ╔═╗╔╦╗╔═╗  {C.CYAN}╔╦╗╔═╗╔╦╗╔═╗╔═╗╔╦╗
{C.RED}  ║  ║║║╚═╗  {C.CYAN} ║║║╣  ║ ║╣ ║   ║
{C.RED}  ╚═╝╩ ╩╚═╝  {C.CYAN}═╩╝╚═╝ ╩ ╚═╝╚═╝ ╩{C.RESET}
{C.DIM}  ─────────────────────────────{C.RESET}
{C.DIM}  Targets:{C.RESET}   {C.WHITE}{targets}{C.RESET}
{C.DIM}  Time:{C.RESET}      {C.WHITE}{datetime.now().strftime('%H:%M:%S')}{C.RESET}
""")


def detect_from_headers(headers):
    """Check response headers for technology fingerprints."""
    findings = []

    for header_name, patterns in HEADER_SIGNATURES.items():
        value = headers.get(header_name, "")
        if value:
            for pattern, tech in patterns.items():
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append({
                        "tech": tech,
                        "source": "header",
                        "detail": f"{header_name}: {value}",
                    })

    return findings


def detect_from_cookies(cookies):
    """Check cookies for technology fingerprints."""
    findings = []
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    for pattern, tech in COOKIE_SIGNATURES.items():
        if re.search(pattern, cookie_str, re.IGNORECASE):
            findings.append({
                "tech": tech,
                "source": "cookie",
                "detail": f"Cookie matches: {pattern}",
            })

    return findings


def detect_from_html(html):
    """Check page source for CMS/framework signatures."""
    findings = []

    for cms, patterns in HTML_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                findings.append({
                    "tech": cms,
                    "source": "html",
                    "detail": f"Pattern: {pattern}",
                })
                break  # one match per CMS is enough

    # Check meta generator tag specifically
    gen_match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )
    if gen_match:
        findings.append({
            "tech": gen_match.group(1),
            "source": "meta",
            "detail": f"Generator: {gen_match.group(1)}",
        })

    return findings


def detect_from_paths(url, session):
    """Probe common CMS paths and check responses."""
    findings = []
    url = url.rstrip("/")

    for cms, paths in CMS_PATHS.items():
        for path in paths:
            try:
                resp = session.get(
                    f"{url}{path}",
                    allow_redirects=False,
                    timeout=5,
                )
                if resp.status_code in (200, 301, 302, 403):
                    findings.append({
                        "tech": cms,
                        "source": "path",
                        "detail": f"{path} → {resp.status_code}",
                        "status": resp.status_code,
                    })
                    break  # one confirmed path per CMS is enough
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue

    return findings


def detect_from_robots(url, session):
    """Check robots.txt for CMS clues."""
    findings = []
    try:
        resp = session.get(f"{url.rstrip('/')}/robots.txt", timeout=5)
        if resp.status_code == 200 and len(resp.text) > 10:
            text = resp.text.lower()
            cms_clues = {
                "WordPress": ["wp-admin", "wp-includes", "wp-content"],
                "Joomla": ["administrator", "/components/", "/modules/"],
                "Drupal": ["/core/", "/sites/", "/modules/"],
                "Magento": ["/downloader/", "/app/", "/skin/"],
            }
            for cms, clues in cms_clues.items():
                for clue in clues:
                    if clue in text:
                        findings.append({
                            "tech": cms,
                            "source": "robots.txt",
                            "detail": f"Found '{clue}' in robots.txt",
                        })
                        break

            # Also capture interesting disallowed paths
            interesting = []
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        interesting.append(path)

            if interesting:
                findings.append({
                    "tech": "robots.txt",
                    "source": "info",
                    "detail": f"Disallowed: {', '.join(interesting[:10])}",
                })

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        pass

    return findings


def run_whatweb(url):
    """Run WhatWeb if available for deeper fingerprinting."""
    if not shutil.which("whatweb"):
        return []

    findings = []
    try:
        result = subprocess.run(
            ["whatweb", "--color=never", "-a", "3", url],
            capture_output=True, text=True, timeout=30,
        )
        if result.stdout.strip():
            findings.append({
                "tech": "WhatWeb",
                "source": "tool",
                "detail": result.stdout.strip(),
            })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return findings


def scan_target(url, use_whatweb=True):
    """Run all detection methods against a single URL."""
    all_findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)"})

    # 1. Fetch main page
    print(f"  {C.CYAN}[●]{C.RESET} Fetching {C.WHITE}{url}{C.RESET}")
    try:
        resp = session.get(url, allow_redirects=True, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}[✗]{C.RESET} Could not connect to {url}\n")
        return []
    except requests.exceptions.Timeout:
        print(f"  {C.RED}[✗]{C.RESET} Connection timed out\n")
        return []

    # 2. Headers
    print(f"  {C.CYAN}[●]{C.RESET} Checking response headers...")
    all_findings.extend(detect_from_headers(resp.headers))

    # 3. Cookies
    print(f"  {C.CYAN}[●]{C.RESET} Checking cookies...")
    all_findings.extend(detect_from_cookies(resp.cookies))

    # 4. HTML source
    print(f"  {C.CYAN}[●]{C.RESET} Analyzing page source...")
    all_findings.extend(detect_from_html(resp.text))

    # 5. robots.txt
    print(f"  {C.CYAN}[●]{C.RESET} Checking robots.txt...")
    all_findings.extend(detect_from_robots(url, session))

    # 6. Common CMS paths
    print(f"  {C.CYAN}[●]{C.RESET} Probing CMS paths...")
    all_findings.extend(detect_from_paths(url, session))

    # 7. WhatWeb
    if use_whatweb and shutil.which("whatweb"):
        print(f"  {C.CYAN}[●]{C.RESET} Running WhatWeb...")
        all_findings.extend(run_whatweb(url))

    return all_findings


def display_results(url, findings):
    """Display findings in a clean table."""
    if not findings:
        print(f"\n  {C.YELLOW}No technologies detected.{C.RESET}\n")
        return

    # Separate WhatWeb output from structured findings
    whatweb_output = [f for f in findings if f["source"] == "tool"]
    info_findings = [f for f in findings if f["source"] == "info"]
    tech_findings = [f for f in findings if f["source"] not in ("tool", "info")]

    # Deduplicate tech findings by tech name
    seen = set()
    unique = []
    for f in tech_findings:
        key = f["tech"].lower().split()[0]  # normalize
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: confirmed (path) first, then by source
    source_order = {"path": 0, "meta": 1, "html": 2, "header": 3, "cookie": 4, "robots.txt": 5}
    unique.sort(key=lambda f: source_order.get(f["source"], 9))

    # Display tech findings
    if unique:
        print(f"\n  {C.BOLD}{C.WHITE}{'TECHNOLOGY':<20}{'SOURCE':<14}{'DETAIL'}{C.RESET}")
        print(f"  {C.DIM}{'─' * 65}{C.RESET}")

        for f in unique:
            source_colors = {
                "path": C.GREEN,
                "meta": C.GREEN,
                "html": C.CYAN,
                "header": C.CYAN,
                "cookie": C.YELLOW,
                "robots.txt": C.MAGENTA,
            }
            sc = source_colors.get(f["source"], C.WHITE)
            print(
                f"  {C.WHITE}{C.BOLD}{f['tech']:<20}{C.RESET}"
                f"{sc}{f['source']:<14}{C.RESET}"
                f"{C.DIM}{f['detail']}{C.RESET}"
            )

    # Display robots.txt info
    if info_findings:
        print()
        for f in info_findings:
            print(f"  {C.MAGENTA}[i]{C.RESET} {C.DIM}{f['detail']}{C.RESET}")

    # Display WhatWeb output
    if whatweb_output:
        print(f"\n  {C.BOLD}{C.WHITE}WhatWeb Results:{C.RESET}")
        print(f"  {C.DIM}{'─' * 65}{C.RESET}")
        for f in whatweb_output:
            # Parse WhatWeb output into cleaner format
            for line in f["detail"].splitlines():
                line = line.strip()
                if line:
                    print(f"  {C.DIM}{line}{C.RESET}")

    count = len(unique)
    print(f"\n  {C.DIM}{count} technologies identified{C.RESET}\n")


# ── Main ────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"\n  {C.YELLOW}Usage:{C.RESET} python3 {sys.argv[0]} <url> [url2] [url3] ...")
        print(f"  {C.DIM}  Example: python3 {sys.argv[0]} http://soulmate.htb{C.RESET}")
        print(f"  {C.DIM}  Multi:   python3 {sys.argv[0]} http://soulmate.htb http://ftp.soulmate.htb{C.RESET}\n")
        sys.exit(1)

    urls = []
    for arg in sys.argv[1:]:
        if not arg.startswith("-"):
            url = arg if arg.startswith("http") else f"http://{arg}"
            urls.append(url)

    use_whatweb = "--no-whatweb" not in sys.argv
    show_banner = "--no-banner" not in sys.argv

    if show_banner:
        banner(urls)

    # Output file
    clean_name = re.sub(r"[^\w]", "_", urls[0].split("//")[-1].rstrip("/"))
    outfile = f"cms_{clean_name}.txt"

    all_output = []

    for url in urls:
        if len(urls) > 1:
            print(f"  {C.BOLD}{C.MAGENTA}{'━' * 50}{C.RESET}")
            print(f"  {C.BOLD}{C.MAGENTA}  ▶ {url}{C.RESET}")
            print(f"  {C.BOLD}{C.MAGENTA}{'━' * 50}{C.RESET}\n")

        findings = scan_target(url, use_whatweb)
        display_results(url, findings)

        # Collect for file output
        all_output.append(f"=== {url} ===")
        for f in findings:
            all_output.append(f"[{f['source']}] {f['tech']}: {f['detail']}")
        all_output.append("")

    # Save output
    with open(outfile, "w") as f:
        f.write("\n".join(all_output))

    print(f"  {C.GREEN}✓{C.RESET} Full output saved to {C.BOLD}{outfile}{C.RESET}\n")


if __name__ == "__main__":
    main()