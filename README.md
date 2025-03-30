# IP Info Free

A Python script to extract detailed IP information using free tools and the GeoLite2 database, without relying on APIs.

## Features
- **Geolocation**: Country, City, Latitude, Longitude (via GeoLite2).
- **Whois**: Registration details like Organization, Network Name, and Abuse Contact.
- **Traceroute**: Network path showing intermediate hops.
- **DNS**: Reverse DNS lookup for hostname.
- Colored terminal output and logging to `ip_info_free_log.txt`.

## Requirements
- **Python 3**: Pre-installed on most Linux systems.
- **Command-line Tools**: `whois`, `traceroute`, `dnsutils`.
- **GeoLite2 Database**: Free CSV files from MaxMind:
  - `GeoLite2-City-Locations-en.csv`
  - `GeoLite2-City-Blocks-IPv4.csv`

## Installation
1. **Install dependencies** (on Debian/Ubuntu):
   ```bash
   sudo apt update
   sudo apt install whois traceroute dnsutils
