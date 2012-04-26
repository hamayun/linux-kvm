
// Definitions imported from QEMU and Rabbits
#ifndef _DEFS_IMPORTED_
#define _DEFS_IMPORTED_

#define TARGET_LONG_ALIGNMENT 4

#ifdef CONFIG_X86_64
#define TARGET_LONG_BITS 64
typedef uint64_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#else
#define TARGET_LONG_BITS 32
typedef uint32_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));
#endif

#define CPU_NB_REGS64 16
#define CPU_NB_REGS32 8

#ifdef CONFIG_X86_64
#define CPU_NB_REGS CPU_NB_REGS64
#else
#define CPU_NB_REGS CPU_NB_REGS32
#endif

#define NUM_CORE_REGS (CPU_NB_REGS * 2 + 25)

#endif // _DEFS_IMPORTED_
