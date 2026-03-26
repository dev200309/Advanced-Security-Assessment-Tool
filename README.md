# 🦅 Happy Hacking - Advanced Security Assessment Tool (ASAT)

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](https://github.com/inso-somani/Advanced-Security-Assessment-Tool)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

**ASAT** is an elite, multi-phase automated security scanner designed to hunt for deep-seated vulnerabilities across Network, Web, API, and Cloud infrastructures. It transforms raw data into actionable security intelligence using a modular strike-team architecture.

---

## 🚀 Key Features

*   **⚡ High-Speed Recon**: Parallelized subdomain discovery and port scanning.
*   **🌐 Deep Web Analysis**: Targeted injection testing (SSTI, CRLF, SQLi, SSRF) and Request Smuggling.
*   **🛡️ Multi-Cloud Hunter**: Native support for AWS, Azure, GCP, DigitalOcean, and Firebase exposure checks.
*   **🔗 API Strike Force**: Advanced GraphQL introspection, JWT analysis, and Secret leakage scans.
*   **📊 Dynamic Reporting**: Real-time severity-marked logs with detailed text and JSON report generation.

---

## 🛠️ Installation & Setup

### 1. System Requirements
The system requires `nmap` for advanced fingerprinting and network level checks.

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap -y

# Kali Linux
sudo apt install nmap -y
```

### 2. Python Environment
Install the core strike-suite dependencies:

```bash
pip3 install python-nmap requests dnspython whois colorama beautifulsoup4
```

---

## 🎮 Command Center

| Command | Action |
| :--- | :--- |
| `-t`, `--target` | **(Required)** The target domain or IP to assess. |
| `--phase` | Select specific strikes (`1-5`). Can be multiple. |
| `--all` | Launch the full 5-phase offensive. |
| `-o`, `--output` | Destination for the mission report. |
| `--format` | Choose your intel format: `txt` (default) or `json`. |
| `-v`, `--verbose` | Activate high-detail combat logging. |

### Battle Examples:
```bash
# Full 5-Phase Assault
sudo python3 happyhacking.py -t example.com --all

# API & Cloud Targeted Strike (Phases 4 & 5)
sudo python3 happyhacking.py -t target.com --phase 4 --phase 5

# Fast Network Discovery
sudo python3 happyhacking.py -t 192.168.1.1 --phase 1 -v
```

---

## 📂 The 5 Strike Phases

### 🛰️ Phase 1: Network Recon
*   **Discovery**: Host resolution, reverse DNS, and GeoIP positioning.
*   **Scanning**: Full 65535-port SYN scan with OS fingerprinting.
*   **Encrypted Intel**: SSL/TLS cipher analysis (identifying weak RC4, DES, export ciphers).
*   **Email Security**: Comprehensive record audit (SPF, DKIM, DMARC).

### 📡 Phase 2: Subdomain Strike
*   **Discovery**: Multi-source subdomain hunting and brute-force mapping.
*   **Takeover Hunter**: Detection of dangling DNS records and potential hijack opportunities.

### 🌎 Phase 3: Web Offensive
*   **Injection Lab**: Advanced SSTI, OS Command Injection, SSRF, and SQLi testing.
*   **Ambush Detection**: HTTP Request Smuggling (CL.TE), CRLF, and Host Header Injection.
*   **Persistence Check**: Web Cache Poisoning and WebSocket security analysis.

### 🧬 Phase 4: API Deep Scan
*   **Schema Exposure**: GraphQL Introspection and mutation discovery.
*   **Token Audit**: Deep JWT analysis (alg:none, weak HMAC, payload leakage).
*   **Access Control**: CORS wildcard checks, Rate Limiting, and Mass Assignment testing.
*   **Secret Hunter**: Automated regex detection for AWS, Stripe, and GitHub keys in responses.

### ☁️ Phase 5: Cloud Hunter
*   **Multi-Cloud**: AWS S3 (with Write-Access test), Azure Blob, GCP Storage, and DO Spaces discovery.
*   **DB Exposure**: Firebase Realtime and Firestore leakage testing.
*   **CDN Recon**: CloudFront origin leak and HSTS header validation.

---

## 🧪 Severity Indicators

ASAT uses a high-visibility danger-marking system for real-time analysis:

*   `[☠ CRITICAL]` - Immediate action required (RCE, Secret Leaks).
*   `[☢ HIGH]` - Severe risk (Injections, Smuggling).
*   `[⚠ MEDIUM]` - Significant vulnerability (CORS misconfig, Weak SSL/TLS).
*   `[ℹ LOW]` - Minor security improvement (Missing headers).

---

> ⚠️ **LEGAL DISCLAIMER:** This tool is for authorized security testing only! Unauthorized use against systems you do not own is strictly illegal and unethical. The developer assumes no liability for misuse.

**Happy Hacking! 🦅**
