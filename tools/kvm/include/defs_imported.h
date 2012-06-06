
// Definitions imported from QEMU and Rabbits
#ifndef _DEFS_IMPORTED_
#define _DEFS_IMPORTED_

#include <inttypes.h>
#include "qemu-queue.h"     // taken from qemu-kvm

#define TARGET_LONG_ALIGNMENT 4
#define TARGET_LONG_BITS 32
typedef uint32_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));

#define CPU_NB_REGS32 8
#define CPU_NB_REGS CPU_NB_REGS32
#define NUM_CORE_REGS (CPU_NB_REGS + 8)

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT     0x08
#define BP_GDB                0x10
#define BP_CPU                0x20

struct kvm_sw_breakpoint {
    target_ulong pc;
    target_ulong saved_insn;
    int use_count;
    QTAILQ_ENTRY(kvm_sw_breakpoint) entry;
};

typedef struct CPUWatchpoint {
    target_ulong vaddr;
    target_ulong len_mask;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
} CPUWatchpoint;

QTAILQ_HEAD(kvm_sw_breakpoint_head, kvm_sw_breakpoint);

/* Taken From Rabbits/rabbits/qemu/sc_qemu/bswap.h */

static inline int ldl_le_p(const void *ptr)
{
    const uint8_t *p = ptr;
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline uint64_t ldq_le_p(const void *ptr)
{
    const uint8_t *p = ptr;
    uint32_t v1, v2;
    v1 = ldl_le_p(p);
    v2 = ldl_le_p(p + 4);
    return v1 | ((uint64_t)v2 << 32);
}

static inline void stw_le_p(void *ptr, int v)
{
    uint8_t *p = ptr;
    p[0] = v;
    p[1] = v >> 8;
}

static inline void stl_le_p(void *ptr, int v)
{
    uint8_t *p = ptr;
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    uint8_t *p = ptr;
    stl_le_p(p, (uint32_t)v);
    stl_le_p(p + 4, v >> 32);
}

/* Taken From Rabbits/rabbits/qemu/sc_qemu/cpu-all.h */

#define ldl_p(p) ldl_le_p(p)
#define ldq_p(p) ldq_le_p(p)

#define stw_p(p, v) stw_le_p(p, v)
#define stl_p(p, v) stl_le_p(p, v)
#define stq_p(p, v) stq_le_p(p, v)

#endif // _DEFS_IMPORTED_
