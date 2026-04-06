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
                    if '<title>Index of' in response.text and '<h1>Index of' in response.text:
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
                    test_content = 'test_put_content_' + str(int(time.time()))
                    test_url = urljoin(self.target, f'/test-{int(time.time())}.txt')
                    response = self.session.request(method, test_url, data=test_content)
                    
                    if response.status_code in [200, 201, 204]:
                        is_vulnerable = False
                        if method == 'PUT':
                            verify_response = self.session.get(test_url)
                            if verify_response.status_code == 200 and test_content in verify_response.text:
                                is_vulnerable = True
                        else:
                            # Keep DELETE detection conservative as it's harder to reliably verify without creating a file first
                            pass
                            
                        if is_vulnerable:
                            print(f"{CRITICAL} HTTP method {method} is allowed and functional! (Status: {response.status_code})")
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
                        "you have an error in your sql syntax",
                        "unclosed quotation mark after the character string",
                        "microsoft oledb sql server driver error",
                        "syntax error at or near",
                        "pg_query(): query failed",
                        "pdoexception: sqlstate",
                        "sqlite/jdbc driver db error",
                        "sqlite3::query"
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
                    
                    content_type = response.headers.get('Content-Type', '').lower()
                    if payload in response.text and '<script>' in payload and 'text/html' in content_type:
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
                # Get baseline for comparison
                baseline_resp = None
                try:
                    baseline_resp = self.session.post(form_action, data={'username': 'admin', 'password': 'wrongpass_random_baseline_123'}, allow_redirects=False)
                except:
                    pass
                baseline_loc = baseline_resp.headers.get('Location', '') if baseline_resp else ''
                
                for user_payload, pass_payload in auth_bypass_payloads:
                    try:
                        time.sleep(0.1)
                        data = {'username': user_payload, 'password': pass_payload}
                        resp = self.session.post(form_action, data=data, allow_redirects=False)
                        # If bypass works, server likely redirects (301/302) to a dashboard instead of returning back to login
                        if resp.status_code in [301, 302] and 'login' not in resp.headers.get('Location', '').lower() and resp.headers.get('Location', '') != baseline_loc:
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
                        if resp.status_code in [301, 302] and 'login' not in resp.headers.get('Location', '').lower() and resp.headers.get('Location', '') != baseline_loc:
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

