#!/usr/bin/env python3
"""
Advanced Security Assessment Tool (ASAT) 
Author: Dev Somani
Happy Hacking! 🚀
"""

import sys
try:
    from asat.cli import SecurityAssessmentTool
except ImportError as e:
    import colorama
    print(colorama.Fore.RED + f"[!] Failed to import ASAT modules: {e}")
    print("Please ensure you are running this from the project root and all dependencies are installed.")
    sys.exit(1)

def main():
    app = SecurityAssessmentTool()
    app.run()

if __name__ == "__main__":
    main()
