
#ifndef __GDB_SRV_ARCH__
#define __GDB_SRV_ARCH__

#include "include/defs_imported.h"

int kvm_arch_get_registers(CPUState *env);
int kvm_arch_put_registers(CPUState *env);

int kvm_cpu_synchronize_state(CPUState *env);
void qemu_cond_init(pthread_cond_t *cond);
void qemu_mutex_init(pthread_mutex_t *mutex);
void qemu_kvm_wait_io_event(CPUState *env);
int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap);

int kvm_arch_handle_debug(CPUState * env);
int kvm_arch_memory_rw_debug(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);

int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr, target_ulong len, int type);
int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr, target_ulong len, int type);
int kvm_remove_all_breakpoints(CPUState *current_env);

#endif // __GDB_SRV_ARCH__