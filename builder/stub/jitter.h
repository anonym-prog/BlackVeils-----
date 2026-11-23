/* blackveil/builder/stub/jitter.h */
#ifndef BLACKVEIL_JITTER_H
#define BLACKVEIL_JITTER_H

#include <windows.h>

/* Compute a beacon sleep with ±jitter_pct randomness applied. */
DWORD bv_jittered_sleep(DWORD base_ms, DWORD jitter_pct);

/* Sleep in small increments, re-seeding the PRNG so short timeline
 * analysis cannot infer the beacon interval from a single sample. */
void bv_jittered_sleep_ex(DWORD base_ms, DWORD jitter_pct);

#endif
