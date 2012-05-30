
#ifndef __GDB_SRV_ARCH__
#define __GDB_SRV_ARCH__

#include "include/defs_imported.h"

int kvm_arch_get_registers(CPUState *env);
int kvm_arch_put_registers(CPUState *env);

void cpu_synchronize_state(CPUState *env);
int kvm_arch_memory_rw_debug(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

void kvm_arch_enable_sw_breakpoints(CPUState *env);
int kvm_arch_insert_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp);
int kvm_arch_remove_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp);

int kvm_arch_insert_hw_breakpoint(target_ulong addr, target_ulong len, int type);
int kvm_arch_remove_hw_breakpoint(target_ulong addr, target_ulong len, int type);
void kvm_arch_remove_all_hw_breakpoints(void);

int kvm_handle_debug(CPUState * env);
void kvm_arch_update_guest_debug(CPUState *env, struct kvm_guest_debug *dbg);

int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr, target_ulong len, int type);
int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr, target_ulong len, int type);
void kvm_remove_all_breakpoints(CPUState *current_env);

#endif // __GDB_SRV_ARCH__