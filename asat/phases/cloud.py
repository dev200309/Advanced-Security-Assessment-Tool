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
                    print(f"{CRITICAL} Public S3 Bucket Discovered (Listable): {bucket_url}")
                    finding = Finding("Public S3 Bucket", f"S3 Bucket '{bucket_name}' allows public directory listing.", RiskRating.CRITICAL, "Configure S3 bucket ACL to block public access.", "Cloud")
                    self.report.add_finding(finding)
                elif response.status_code == 403 and 'AccessDenied' in response.text:
                    if self.verbose:
                        print(f"{INFO} S3 Bucket exists but is private: {bucket_url}")
            except:
                pass

