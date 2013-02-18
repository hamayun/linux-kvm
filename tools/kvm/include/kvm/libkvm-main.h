#ifndef __KVM_RUN_H__
#define __KVM_RUN_H__

#include "kvm_import_export.h"

void * kvm_internal_init(struct kvm_import_export_t * kie, uint32_t num_cpus,
                         uint64_t ram_size /* MBs */);

void * kvm_cpu_internal_init(void * kvm_instance, void * sc_kvm_cpu, int cpu_id);
void kvm_setup_bios_and_ram(void * kvm_instance, void * kvm_userspace_mem_addr,
                            const char * kernel, const char * boot_loader);
int kvm_run_cpu(void * kvm_cpu_inst);
int kvm_internal_exit(void);
void kvm_help(void);

#endif
