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


from asat.core.config import *
from asat.core.models import *

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
            if response and len(response) > 40 and response[0:4] in [b"\xffSMB", b"\xfeSMB"]:
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

