#ifndef KVM__KVM_CPU_H
#define KVM__KVM_CPU_H

#include <linux/kvm.h>    /* for struct kvm_regs */

#include <pthread.h>
#include <defs_imported.h>

struct kvm;

struct kvm_cpu {
	pthread_t           thread;     /* VCPU thread */
	unsigned long		cpu_id;

	struct kvm         *kvm;        /* parent KVM */
	int                 vcpu_fd;    /* For VCPU ioctls() */
	struct kvm_run	   *kvm_run;

	struct kvm_regs		regs;
	struct kvm_sregs	sregs;
	struct kvm_fpu		fpu;
	struct kvm_msrs	   *msrs;       /* dynamically allocated */
	target_ulong        dr[8];      /* debug registers */

	u8                  is_running;
	u8                  paused;

	struct kvm_coalesced_mmio_ring	*ring;

    CPUWatchpoint * watchpoint_hit;
    int kvm_vcpu_dirty;
    int32_t exception_injected;
    struct kvm_cpu *next_cpu;

    pthread_cond_t halt_cond;
    int thread_kicked;
    struct kvm_work_item *queued_work_first, *queued_work_last;
    int queued_work_size;
};

typedef struct kvm_cpu CPUState;

struct kvm_cpu *kvm_cpu__init(struct kvm *kvm, unsigned long cpu_id);
void kvm_cpu__delete(struct kvm_cpu *vcpu);
void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu);
void kvm_cpu__setup_cpuid(struct kvm_cpu *vcpu);
void * kvm_cpu__run(struct kvm_cpu *vcpu, int *retry_to_run);
void kvm_cpu__reboot(void);

int kvm_cpu__get_debug_fd(void);
void kvm_cpu__set_debug_fd(int fd);
void kvm_cpu__show_code(struct kvm_cpu *vcpu);
void kvm_cpu__show_registers(struct kvm_cpu *vcpu);
void kvm_cpu__show_page_tables(struct kvm_cpu *vcpu);

#endif /* KVM__KVM_CPU_H */
