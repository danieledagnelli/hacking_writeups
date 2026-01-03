#!/usr/bin/env python3
"""
00_setup.py - Update /etc/hosts with target IP
"""

import subprocess
import sys
import os

# Import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import TARGET_IP, header, separator

def check_connectivity(ip):
    """Check if target is reachable"""
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '3', ip],
                                capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def update_hosts(ip, hostnames):
    """Update /etc/hosts with target entries"""
    hosts_file = "/etc/hosts"

    # Read current hosts
    with open(hosts_file) as f:
        lines = f.readlines()

    # Filter out old entries
    new_lines = [l for l in lines if 'eloquia.htb' not in l and 'qooqle.htb' not in l]

    # Add new entry
    new_lines.append(f"{ip}\t{' '.join(hostnames)}\n")

    # Write back (needs sudo)
    try:
        with open(hosts_file, 'w') as f:
            f.writelines(new_lines)
        return True
    except PermissionError:
        return False

def main():
    print(header("00 - SETUP / UPDATE HOSTS"))
    print(f"[*] Target IP: {TARGET_IP}")
    print()

    # Check connectivity
    print("[1/2] Checking connectivity...")
    if check_connectivity(TARGET_IP):
        print("[+] Target is reachable")
    else:
        print("[-] WARNING: Target not responding to ping (may still work)")

    # Update /etc/hosts
    print("[2/2] Updating /etc/hosts...")
    hostnames = ['eloquia.htb', 'qooqle.htb']

    if update_hosts(TARGET_IP, hostnames):
        print("[+] /etc/hosts updated")
    else:
        # Try with sudo
        print("    Trying with sudo...")
        try:
            # Remove old entries
            subprocess.run(['sudo', 'sed', '-i', '/eloquia.htb/d', '/etc/hosts'], check=True)
            subprocess.run(['sudo', 'sed', '-i', '/qooqle.htb/d', '/etc/hosts'], check=True)
            # Add new entry
            entry = f"{TARGET_IP}\t{' '.join(hostnames)}\n"
            proc = subprocess.run(['sudo', 'tee', '-a', '/etc/hosts'],
                                  input=entry.encode(), capture_output=True)
            if proc.returncode == 0:
                print("[+] /etc/hosts updated (via sudo)")
            else:
                raise Exception("tee failed")
        except Exception as e:
            print(f"[-] Failed: {e}")
            print(f"    Run manually:")
            print(f"    sudo sed -i '/eloquia.htb/d' /etc/hosts")
            print(f"    echo '{TARGET_IP} {' '.join(hostnames)}' | sudo tee -a /etc/hosts")
            sys.exit(1)

    # Verify
    print()
    print("[+] Verification:")
    with open("/etc/hosts") as f:
        for line in f:
            if 'eloquia' in line or 'qooqle' in line:
                print(f"    {line.strip()}")

    print()
    print(separator())
    print("Setup complete! Next: python3 01_register_users.py")
    print(separator())

if __name__ == "__main__":
    main()
