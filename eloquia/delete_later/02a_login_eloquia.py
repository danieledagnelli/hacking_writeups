#!/usr/bin/env python3
"""
02a_login_eloquia.py - Login to eloquia.htb and save session
"""

import requests
import sys
import os
import re

# Import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (TARGET_ELOQUIA, COOKIE_DIR, load_credentials, ensure_dirs,
                    header, separator)

def get_csrf(html):
    """Extract CSRF token from HTML"""
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

def main():
    ensure_dirs()

    username, password = load_credentials()
    if not username:
        print("[-] No credentials found. Run: python3 01_register_users.py")
        sys.exit(1)

    print(header("02a - LOGIN TO ELOQUIA"))
    print(f"[*] User: {username}")
    print()

    session = requests.Session()

    # Get login page
    print("[1/2] Getting login page...")
    login_page = session.get(f"{TARGET_ELOQUIA}/accounts/login/")
    csrf = get_csrf(login_page.text)

    if not csrf:
        print("[-] Failed to get CSRF token")
        sys.exit(1)

    # Submit login
    print("[2/2] Logging in...")
    resp = session.post(f"{TARGET_ELOQUIA}/accounts/login/",
        data={
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'password': password
        },
        headers={'Referer': f"{TARGET_ELOQUIA}/accounts/login/"}
    )

    if 'sessionid' in session.cookies:
        session_id = session.cookies.get('sessionid')
        print(f"[+] SUCCESS: Logged in!")
        print(f"    Session: {session_id[:20]}...")

        # Save cookies to file (Netscape format for curl compatibility)
        cookie_file = os.path.join(COOKIE_DIR, "eloquia.txt")
        with open(cookie_file, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            for cookie in session.cookies:
                secure = "TRUE" if cookie.secure else "FALSE"
                http_only = "TRUE" if cookie.has_nonstandard_attr('HttpOnly') else "FALSE"
                expires = str(int(cookie.expires)) if cookie.expires else "0"
                f.write(f"{cookie.domain}\tFALSE\t{cookie.path}\t{secure}\t{expires}\t{cookie.name}\t{cookie.value}\n")
        print(f"    Saved to: {cookie_file}")

        print()
        print(separator())
        print("Login successful! Next: python3 02b_login_qooqle.py")
        print(separator())
    else:
        print(f"[-] FAILED: No session cookie")
        print(f"    Check credentials or target availability")
        sys.exit(1)

if __name__ == "__main__":
    main()
