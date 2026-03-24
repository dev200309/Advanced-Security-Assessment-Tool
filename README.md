# Advanced-Security-Assessment-Tool
Advanced Security Assessment Tool (ASAT) – A powerful multi-phase automated scanner for Network, Subdomain, Web App, API, and Cloud vulnerability testing. Features 5-phase reconnaissance, OWASP Top 10 mapping, and detailed JSON/Text reporting. Happy Hacking!


# Happy Hacking - Advanced Security Assessment Tool (ASAT) 

**Happy Hacking (ASAT)** is a multi-phase automated security assessment tool designed for network, subdomain, and web application testing.

## Prerequisites

The tool requires **Python 3** and the following dependencies to function properly.
Furthermore, the system requires `nmap` for advanced port scanning and OS detection.

### 1. Install System Dependencies
```bash
# For Debian/Ubuntu-based systems
sudo apt update
sudo apt install nmap -y
```

### 2. Install Python Dependencies
```bash
pip3 install python-nmap requests dnspython whois colorama beautifulsoup4
```

---

## Usage Guide

Because the script utilizes raw sockets and SYN scanning features of `nmap`, it must be run with **Root/Sudo privileges**.

### Basic Usage

**Run a complete scan (All Phases)** against a target:
```bash
sudo python3 happyhacking.py -t <target> --all
```
*Example:* `sudo python3 happyhacking.py -t example.com --all`

### Available Arguments

| Argument | Long Argument | Description |
| :--- | :--- | :--- |
| `-t` | `--target` | **(Required)** Target domain or IP address. |
| | `--phase` | Scan phase to run (`1`=Network, `2`=Subdomain, `3`=Web, `4`=API, `5`=Cloud). Can be specified multiple times. |
| | `--all` | Run all scan phases (`1`, `2`, `3`, `4`, and `5`). |
| `-o` | `--output` | Output file for the report. If not specified, a timestamped file is generated automatically. |
| | `--format` | Report format (Choices: `txt`, `json`. Default: `txt`). |
| `-v` | `--verbose` | Enable verbose output for more detailed logs during execution. |
| | `--no-banner`| Suppress the banner display at startup. |
| `-h` | `--help` | Show the help message and exit. |

---

## Scan Phases Explained

The tool is divided into five major scan phases that you can trigger individually or together:

### Phase 1: Network Scan (`--phase 1`)
Performs network reconnaissance and scanning.
- **Host Discovery**: Ping sweeps and DNS resolution.
- **Port Scanning**: Comprehensive `SYN` scan using `nmap` (1-65535 ports).
- **Banner Grabbing**: Fetches service banners and detects sensitive information.
- **Network Info**: WHOIS, GeoIP, and Traceroute.
- **Vulnerability Checks**: Anonymous FTP, SMB signing, plaintext protocols (Telnet).
- **Firewall/IDS Detection**: Inconsistent port states inspection.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 1`

### Phase 2: Subdomain Scan (`--phase 2`)
Performs subdomain discovery and analysis.
- Connects to sources like DNS zone transfers and bruteforce mechanisms to find mapped assets.
- Checks for potential subdomain takeover risks.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 2`

### Phase 3: Web Application Scan (`--phase 3`)
Performs active and passive web vulnerability checks.
- Checks for advanced Injections: SQL Injection (SQLi), Server-Side Template Injection (SSTI), OS Command Injection (Time & Output based), Cross-Site Scripting (XSS), SSRF, and Path Traversal.
- Performs rigorous Authentication Bypass attempts (SQLi, Default Credentials, Rate Limiting/Lockout checks).
- Validates misconfigurations: Missing security headers, exposed sensitive info/admin panels (with exact HTTP status codes), clickjacking, and file uploads.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 3`

### Phase 4: API Security Scan (`--phase 4`)
Targets hidden and undocumented API routes.
- Discovers hidden/unauthorized JSON endpoints (e.g. `/api/v1/`).
- Hunts for publicly exposed documentation files like `swagger.json` and `openapi.yaml`.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 4`

### Phase 5: Cloud Infrastructure & Bucket Hunting (`--phase 5`)
Reconnaissance layer hunting for misconfigured public cloud storage.
- Dynamically searches for poorly-secured AWS S3 buckets linked to the target domain (e.g. `target-backup.s3.amazonaws.com`).
- Assesses and reports if any discovered buckets allow unauthorized public directory listing.

*Example:* `sudo python3 happyhacking.py -t example.com --phase 5`

### Combining Phases
You can combine multiple phases if you don't want to run all of them:
```bash
sudo python3 happyhacking.py -t example.com --phase 1 --phase 3
```

---

## Reporting

By default, the tool outputs a `.txt` report file with a timestamp in the current directory if run successfully.
You can format it as JSON or specify a custom filename.

**Save as JSON format:**
```bash
sudo python3 happyhacking.py -t example.com --all --format json -o output_report.json
```

**Save as a specific Text file:**
```bash
sudo python3 happyhacking.py -t example.com --all -o scan_results.txt
```

---

> ⚠️ **DISCLAIMER:** This tool is for authorized security testing only! Unauthorized use against systems you don't own is illegal! By using this tool, you agree to use it responsibly and ethically.
