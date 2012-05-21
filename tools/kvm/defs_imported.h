
// Definitions imported from QEMU and Rabbits
#ifndef _DEFS_IMPORTED_
#define _DEFS_IMPORTED_

//#define CONFIG_X86_64
#define TARGET_LONG_ALIGNMENT 4

#ifdef CONFIG_X86_64
#define TARGET_LONG_BITS 64
typedef uint64_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#else
#define TARGET_LONG_BITS 32
typedef uint32_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#endif

/*
#define CPU_NB_REGS64 16
#define CPU_NB_REGS32 8

#ifdef CONFIG_X86_64
#define CPU_NB_REGS CPU_NB_REGS64
#else
#define CPU_NB_REGS CPU_NB_REGS32
#endif

#define NUM_CORE_REGS (CPU_NB_REGS * 2 + 25)
*/


/* Taken From /home/hamayun/workspace/Rabbits-sls/rabbits/qemu/sc_qemu/bswap.h */

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

/* Taken From /home/hamayun/workspace/Rabbits-sls/rabbits/qemu/sc_qemu/cpu-all.h */

#define ldl_p(p) ldl_le_p(p)
#define ldq_p(p) ldq_le_p(p)

#define stw_p(p, v) stw_le_p(p, v)
#define stl_p(p, v) stl_le_p(p, v)
#define stq_p(p, v) stq_le_p(p, v)

#endif // _DEFS_IMPORTED_
