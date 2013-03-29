#ifndef __KVM_RUN_H__
#define __KVM_RUN_H__

#include "kvm_import_export.h"

#define KVM_CPU_OK			 		 0
#define KVM_CPU_RETRY 				-1
#define KVM_CPU_BLOCK_AFTER_KICK 	-2
#define KVM_CPU_PANIC 				-3
#define KVM_CPU_SHUTDOWN 			-4

#define SYSTEMC_SYNC_PORT		0x1000
#define SYSTEMC_WAIT_PORT   	0x2000
#define SYSTEMC_TEST_N_SET_PORT	0x3000
#define ANNOTATION_BASEPORT 	0x4000

void * kvm_internal_init(struct kvm_import_export_t * kie, uint32_t node_id,
						uint32_t num_cpus, uint64_t ram_size /* MBs */);
int kvm_setup_bios_and_ram(void * kvm_instance, uintptr_t * kvm_userspace_mem_addr,
                            const char * kernel, const char * boot_loader);
void * kvm_cpu_internal_init(void * kvm_instance, void * sc_kvm_cpu, int cpu_id);

int kvm_cpu_init_received(void * kvm_cpu_inst);
int kvm_cpu_sipi_received(void * kvm_cpu_inst);
int kvm_cpu_is_runnable(void * kvm_cpu_inst);

int kvm_cpu_reset(void *vcpu);
int kvm_cpu_execute(void *vcpu);
void kvm_cpu_kick(void * kick_cpu);

int kvm_internal_exit(void);
void kvm_help(void);

#endif
