import requests
from urllib.parse import urlparse
import subprocess
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <IP>")
    sys.exit(1)

ip = sys.argv[1]

# get redirect dont follow it
response = requests.get(f"http://{ip}", allow_redirects=False)

#get hostname
location = response.headers.get("Location")

with open("/etc/hosts", "r") as f:
    hosts_content = f.read()

#add to /etc/hosts
hostname = urlparse(location).hostname
if hostname in hosts_content:
    print(f"[*] {hostname} already in /etc/hosts, skipping")
elif (location):
    print(f"[+] Found hostname: {hostname}")

    # Add to /etc/hosts
    entry = f"\n{ip} {hostname}\n"
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input=entry.encode(), stdout=subprocess.DEVNULL)
    print(f"[+] Added '{entry.strip()}' to /etc/hosts")
else:
    print("[-] No redirect found")