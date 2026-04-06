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

