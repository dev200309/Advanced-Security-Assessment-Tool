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
                    print(f"{WARNING} API Endpoint Discovered: {path} (Status: {response.status_code})")
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
                    print(f"{CRITICAL} API Documentation Exposed: {path}")
                    finding = Finding("API Documentation Exposed", f"Swagger/OpenAPI documentation publicly accessible at {path}", RiskRating.HIGH, "Restrict access to API documentation to internal IP addresses or authenticated developers.", "API")
                    self.report.add_finding(finding)
            except:
                pass

