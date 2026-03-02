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

#add to /etc/hosts
if (location):
    hostname = urlparse(location).hostname
    print(f"[+] Found hostname: {hostname}")

    # Add to /etc/hosts
    entry = f"{ip} {hostname}"
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input=entry.encode(), stdout=subprocess.DEVNULL)
    print(f"[+] Added '{entry}' to /etc/hosts")
else:
    print("[-] No redirect found")