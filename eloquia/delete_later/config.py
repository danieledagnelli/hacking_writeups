#!/usr/bin/env python3
"""
config.py - Shared configuration for Eloquia exploit scripts
"""

import os
import subprocess

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")
COOKIE_DIR = os.path.join(TMP_DIR, "cookies")

# Target settings
TARGET_IP = "10.129.244.81"
TARGET_ELOQUIA = "http://eloquia.htb"
TARGET_QOOQLE = "http://qooqle.htb"

# OAuth settings
CLIENT_ID = "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi"
REDIRECT_URI = "http://eloquia.htb/accounts/oauth2/qooqle/callback/"

# Callback settings
CALLBACK_PORT = 8888

def get_callback_ip():
    """Get tun0 IP for callbacks"""
    try:
        result = subprocess.run(['ip', 'addr', 'show', 'tun0'],
                                capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1].split('/')[0]
    except:
        pass
    return "10.10.15.49"

def ensure_dirs():
    """Create required directories"""
    os.makedirs(TMP_DIR, exist_ok=True)
    os.makedirs(COOKIE_DIR, exist_ok=True)

def load_credentials():
    """Load saved credentials"""
    ensure_dirs()
    try:
        with open(os.path.join(TMP_DIR, "username.txt")) as f:
            username = f.read().strip()
        with open(os.path.join(TMP_DIR, "password.txt")) as f:
            password = f.read().strip()
        return username, password
    except FileNotFoundError:
        return None, None

def save_credentials(username, password):
    """Save credentials to tmp"""
    ensure_dirs()
    with open(os.path.join(TMP_DIR, "username.txt"), "w") as f:
        f.write(username)
    with open(os.path.join(TMP_DIR, "password.txt"), "w") as f:
        f.write(password)

# Simple output helpers
def header(title):
    return f"=== {title} ==="

def separator():
    return "=" * 50
