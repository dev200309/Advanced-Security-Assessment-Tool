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

