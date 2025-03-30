#!/usr/bin/env python3

import subprocess
import re
import csv
import sys
import os
from datetime import datetime

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

# Log file
LOG_FILE = "ip_info_free_log.txt"
TIMESTAMP = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# GeoLite2 database files
GEOIP_DB = "GeoLite2-City-Locations-en.csv"
GEOIP_BLOCKS = "GeoLite2-City-Blocks-IPv4.csv"

# Check dependencies
def check_dependencies():
    missing = False
    for cmd in ['whois', 'traceroute', 'dig']:
        if not any(os.path.isfile(f"/usr/bin/{cmd}") or os.path.isfile(f"/bin/{cmd}") for cmd in [cmd]):
            print(f"{RED}Error: {cmd} is not installed. Install it with: sudo apt install {cmd}{NC}")
            missing = True
    if not os.path.exists(GEOIP_DB) or not os.path.exists(GEOIP_BLOCKS):
        print(f"{RED}GeoLite2 database files not found.{NC}")
        print("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print(f"Required files: {GEOIP_DB}, {GEOIP_BLOCKS}")
        missing = True
    if missing:
        sys.exit(1)

# Convert IP to decimal
def ip_to_decimal(ip):
    octets = ip.split('.')
    return (int(octets[0]) * 16777216) + (int(octets[1]) * 65536) + (int(octets[2]) * 256) + int(octets[3])

# Get geolocation from GeoLite2
def get_geolite_info(ip):
    print(f"{YELLOW}Extracting location info from GeoLite2...{NC}")
    ip_dec = ip_to_decimal(ip)

    block_match = None
    with open(GEOIP_BLOCKS, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            network, start_ip, end_ip = row[0], int(row[1]), int(row[2])
            if ip_dec >= start_ip and ip_dec <= end_ip:
                block_match = row
                break

    if not block_match:
        print("GeoLite2 Match: Not found")
        return

    geoname_id = block_match[5]
    location = {}
    with open(GEOIP_DB, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if row[0] == geoname_id:
                location = {
                    'country': row[5].strip('"'),
                    'city': row[7].strip('"'),
                    'latitude': row[8].strip('"'),
                    'longitude': row[9].strip('"')
                }
                break

    print(f"{GREEN}Geolocation:{NC}")
    print(f"  Country: {location.get('country', 'Unknown')}")
    print(f"  City: {location.get('city', 'Unknown')}")
    print(f"  Latitude: {location.get('latitude', 'N/A')}")
    print(f"  Longitude: {location.get('longitude', 'N/A')}")
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{TIMESTAMP}] GEOLITE: {ip} - {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')} (Lat: {location.get('latitude', 'N/A')}, Lon: {location.get('longitude', 'N/A')})\n")

# Get whois information
def get_whois_info(ip):
    print(f"{YELLOW}Extracting whois information...{NC}")
    try:
        whois_output = subprocess.check_output(['whois', ip], stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        whois_output = ""

    country = re.search(r'country:\s*(\S+)', whois_output, re.I)
    org = re.search(r'(org-name|organization):\s*(.+)', whois_output, re.I)
    netname = re.search(r'netname:\s*(\S+)', whois_output, re.I)
    descr = re.search(r'descr:\s*(.+)', whois_output, re.I)
    abuse_email = re.search(r'(abuse-mailbox|abuse-c:.*\n.*email:)\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', whois_output, re.I)

    print(f"{GREEN}Whois Information:{NC}")
    print(f"  Country: {country.group(1) if country else 'Unknown'}")
    print(f"  Organization: {org.group(2).strip() if org else 'Unknown'}")
    print(f"  Network Name: {netname.group(1) if netname else 'Unknown'}")
    print(f"  Description: {descr.group(1).strip() if descr else 'Unknown'}")
    print(f"  Abuse Contact: {abuse_email.group(2) if abuse_email else 'N/A'}")
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{TIMESTAMP}] WHOIS: {ip} - {org.group(2).strip() if org else 'Unknown'}, {netname.group(1) if netname else 'Unknown'}, Abuse: {abuse_email.group(2) if abuse_email else 'N/A'}\n")

# Get traceroute path
def get_traceroute_info(ip):
    print(f"{YELLOW}Extracting traceroute path...{NC}")
    try:
        traceroute_output = subprocess.check_output(['traceroute', '-m', '15', ip], stderr=subprocess.DEVNULL, text=True)
        lines = traceroute_output.splitlines()[1:]  # Skip first line
    except subprocess.CalledProcessError:
        lines = []

    print(f"{GREEN}Network Path:{NC}")
    for line in lines:
        hop_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        hop_name = re.search(r'\S+\s+\((?:\d+\.\d+\.\d+\.\d+)\)\s*(.*)', line)
        if hop_ip:
            print(f"  Hop: {hop_ip.group(1)} ({hop_name.group(1).strip() if hop_name else 'N/A'})")
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{TIMESTAMP}] TRACEROUTE: {ip} - Path traced\n")

# Get DNS information
def get_dns_info(ip):
    print(f"{YELLOW}Extracting DNS information...{NC}")
    try:
        dns_output = subprocess.check_output(['dig', '+short', '-x', ip], stderr=subprocess.DEVNULL, text=True).strip().rstrip('.')
    except subprocess.CalledProcessError:
        dns_output = ""

    print(f"{GREEN}DNS Information:{NC}")
    print(f"  Reverse DNS: {dns_output if dns_output else 'N/A'}")
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{TIMESTAMP}] DNS: {ip} - Reverse DNS: {dns_output if dns_output else 'N/A'}\n")

# Main function
def main():
    check_dependencies()

    if len(sys.argv) != 2:
        print(f"{RED}Please provide an IP address: {sys.argv[0]} <IP_ADDRESS>{NC}")
        print("Example: ./ip_info_free.py 8.8.8.8")
        sys.exit(1)

    ip = sys.argv[1]
    print(f"{BLUE}===================================={NC}")
    print(f"{BLUE}IP Information for {ip}{NC}")
    print(f"{BLUE}===================================={NC}")
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{TIMESTAMP}] INFO: Started tracing {ip}\n")

    get_geolite_info(ip)
    print("")
    get_whois_info(ip)
    print("")
    get_traceroute_info(ip)
    print("")
    get_dns_info(ip)
    print(f"{BLUE}===================================={NC}")

if __name__ == "__main__":
    main()
