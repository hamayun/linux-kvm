#ifndef __KVM_RUN_H__
#define __KVM_RUN_H__

#include "kvm_imported.h"

void * kvm_internal_init(struct kvm_import_t *ki, uint32_t num_cpus, uint64_t ram_size /* MBs */,
						 const char * kernel, const char * boot_loader, void * kvm_userspace_mem_addr);
int kvm_run_cpus(void);
void kvm_help(void);

#endif
