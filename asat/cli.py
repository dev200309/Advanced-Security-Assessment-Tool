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
from asat.phases.network import NetworkScanner
from asat.phases.subdomain import SubdomainScanner
from asat.phases.web import WebScanner
from asat.phases.api import APIScanner
from asat.phases.cloud import CloudScanner

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

