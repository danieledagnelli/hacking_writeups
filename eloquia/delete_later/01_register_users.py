#!/usr/bin/env python3
"""
01_register_users.py - Register test users on eloquia.htb and qooqle.htb
"""

import requests
import sys
import os
import re
import random
import string
import argparse
import shutil

# Import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (TARGET_ELOQUIA, TARGET_QOOQLE, TMP_DIR,
                    save_credentials, load_credentials, ensure_dirs,
                    header, separator)

def clear_tmp():
    """Clear all files in tmp folder"""
    if os.path.exists(TMP_DIR):
        shutil.rmtree(TMP_DIR)
    ensure_dirs()

def get_csrf(html):
    """Extract CSRF token from HTML"""
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

def register_eloquia(username, password):
    """Register on Eloquia"""
    session = requests.Session()

    # Get registration page
    reg_page = session.get(f"{TARGET_ELOQUIA}/accounts/register/")
    csrf = get_csrf(reg_page.text)

    if not csrf:
        return False, "Could not get CSRF token"

    # Submit registration
    resp = session.post(f"{TARGET_ELOQUIA}/accounts/register/",
        data={
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'email': f"{username}@ghost.local",
            'password1': password,
            'password2': password
        },
        headers={'Referer': f"{TARGET_ELOQUIA}/accounts/register/"},
        allow_redirects=False
    )

    if resp.status_code == 302:
        return True, "Registered successfully"
    elif 'already exists' in resp.text.lower():
        return True, "Already registered"
    else:
        # Try to extract error
        error = re.search(r'<li>([^<]+)</li>', resp.text)
        if error:
            return False, error.group(1)
        return False, f"HTTP {resp.status_code}"

def register_qooqle(username, password):
    """Register on Qooqle"""
    session = requests.Session()

    # Get registration page
    reg_page = session.get(f"{TARGET_QOOQLE}/register/")
    csrf = get_csrf(reg_page.text)

    if not csrf:
        return False, "Could not get CSRF token"

    # Submit registration (Qooqle needs first_name, last_name)
    resp = session.post(f"{TARGET_QOOQLE}/register/",
        data={
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'first_name': username,
            'last_name': 'User',
            'password1': password,
            'password2': password
        },
        headers={'Referer': f"{TARGET_QOOQLE}/register/"},
        allow_redirects=False
    )

    if resp.status_code == 302:
        return True, "Registered successfully"
    elif 'already exists' in resp.text.lower():
        return True, "Already registered"
    else:
        error = re.search(r'<li>([^<]+)</li>', resp.text)
        if error:
            return False, error.group(1)
        return False, f"HTTP {resp.status_code}"

def main():
    parser = argparse.ArgumentParser(description='Register test users')
    parser.add_argument('--new', action='store_true',
                        help='Force create new user (clears tmp folder)')
    args = parser.parse_args()

    # If --new, clear everything and start fresh
    if args.new:
        clear_tmp()
        print(header("01 - REGISTER USERS"))
        print("[*] --new flag: Cleared tmp folder")
        print()
    else:
        ensure_dirs()

    # Check if credentials already exist (unless --new flag)
    existing_user, existing_pass = load_credentials()
    if existing_user and not args.new:
        print(header("01 - REGISTER USERS"))
        print(f"[*] Existing credentials found: {existing_user}")
        print()

        # Verify they still work
        print("[1/2] Verifying Eloquia login...")
        session = requests.Session()
        login_page = session.get(f"{TARGET_ELOQUIA}/accounts/login/")
        csrf = get_csrf(login_page.text)
        if csrf:
            session.post(f"{TARGET_ELOQUIA}/accounts/login/",
                data={
                    'csrfmiddlewaretoken': csrf,
                    'username': existing_user,
                    'password': existing_pass
                },
                headers={'Referer': f"{TARGET_ELOQUIA}/accounts/login/"}
            )
            if 'sessionid' in session.cookies:
                print(f"[+] Credentials valid on Eloquia")

                print("[2/2] Verifying Qooqle login...")
                session2 = requests.Session()
                login_page = session2.get(f"{TARGET_QOOQLE}/login/")
                csrf = get_csrf(login_page.text)
                if csrf:
                    session2.post(f"{TARGET_QOOQLE}/login/",
                        data={
                            'csrfmiddlewaretoken': csrf,
                            'username': existing_user,
                            'password': existing_pass
                        },
                        headers={'Referer': f"{TARGET_QOOQLE}/login/"}
                    )
                    if 'sessionid' in session2.cookies:
                        print(f"[+] Credentials valid on Qooqle")
                        print()
                        print(separator())
                        print(f"Using existing account: {existing_user}")
                        print("Next: python3 02a_login_eloquia.py")
                        print(separator())
                        return

        print("[-] Existing credentials invalid, creating new account...")
        print()

    # Generate new credentials
    suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
    username = f"ghost{suffix}"
    password = f"P@ss{suffix}123!"

    print(header("01 - REGISTER USERS"))
    print(f"[*] Username: {username}")
    print(f"[*] Password: {password}")
    print()

    # Register on Eloquia
    print("[1/2] Registering on eloquia.htb...")
    success, msg = register_eloquia(username, password)
    if success:
        print(f"[+] Eloquia: {msg}")
    else:
        print(f"[-] Eloquia FAILED: {msg}")
        sys.exit(1)

    # Register on Qooqle
    print("[2/2] Registering on qooqle.htb...")
    success, msg = register_qooqle(username, password)
    if success:
        print(f"[+] Qooqle: {msg}")
    else:
        print(f"[-] Qooqle FAILED: {msg}")
        sys.exit(1)

    # Save credentials
    save_credentials(username, password)

    print()
    print(separator())
    print("[+] BOTH REGISTRATIONS SUCCESSFUL")
    print(f"Username: {username}")
    print(f"Saved to: {TMP_DIR}/")
    print("Next: python3 02a_login_eloquia.py")
    print(separator())

if __name__ == "__main__":
    main()
