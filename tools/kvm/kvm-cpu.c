#include "kvm/kvm-cpu.h"

#include "kvm/symbol.h"
#include "kvm/util.h"
#include "kvm/kvm.h"

#include <asm/msr-index.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <kvm/libkvm-main.h>
#include "gdb_srv.h"
#include "gdb_srv_arch.h"

#define PAGE_SIZE (sysconf(_SC_PAGE_SIZE))
//#define DEBUG_MMIO

extern struct kvm_cpu *kvm_cpus[KVM_NR_CPUS];
extern __thread struct kvm_cpu *current_kvm_cpu;

//static int debug_fd;
static FILE * debug_fd;

#define dprintf(fd, fmt, args...)                               \
    do { fprintf(fd, fmt, ##args); } while (0)

void kvm_cpu__set_debug_fd(int fd)
{
	debug_fd = (FILE *) fd;
}

int kvm_cpu__get_debug_fd(void)
{
	return ((int) debug_fd);
}

static inline bool is_in_protected_mode(struct kvm_cpu *vcpu)
{
	return vcpu->sregs.cr0 & 0x01;
}

static inline u64 ip_to_flat(struct kvm_cpu *vcpu, u64 ip)
{
	u64 cs;

	/*
	 * NOTE! We should take code segment base address into account here.
	 * Luckily it's usually zero because Linux uses flat memory model.
	 */
	if (is_in_protected_mode(vcpu))
		return ip;

	cs = vcpu->sregs.cs.selector;

	return ip + (cs << 4);
}

static inline u32 selector_to_base(u16 selector)
{
	/*
	 * KVM on Intel requires 'base' to be 'selector * 16' in real mode.
	 */
	return (u32)selector * 16;
}

static struct kvm_cpu *kvm_cpu__new(struct kvm *kvm)
{
	struct kvm_cpu *vcpu;

	vcpu		= calloc(1, sizeof *vcpu);
	if (!vcpu)
		return NULL;

	vcpu->kvm	= kvm;

	return vcpu;
}

void kvm_cpu__delete(struct kvm_cpu *vcpu)
{
	if (vcpu->msrs)
		free(vcpu->msrs);

	free(vcpu);
}

struct kvm_cpu *kvm_cpu__init(struct kvm *kvm, unsigned long cpu_id)
{
	struct kvm_cpu *vcpu;
	int mmap_size;
	int coalesced_offset;

	vcpu		= kvm_cpu__new(kvm);
	if (!vcpu)
		return NULL;

	vcpu->cpu_id	= cpu_id;

	vcpu->vcpu_fd = ioctl(vcpu->kvm->vm_fd, KVM_CREATE_VCPU, cpu_id);
	if (vcpu->vcpu_fd < 0)
		die_perror("KVM_CREATE_VCPU ioctl");

	mmap_size = ioctl(vcpu->kvm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
		die_perror("KVM_GET_VCPU_MMAP_SIZE ioctl");

	vcpu->kvm_run = mmap(NULL, mmap_size, PROT_RW, MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED)
		die("unable to mmap vcpu fd");

	coalesced_offset = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_COALESCED_MMIO);
	if (coalesced_offset)
		vcpu->ring = (void *)vcpu->kvm_run + (coalesced_offset * PAGE_SIZE);

	vcpu->is_running = true;
    vcpu->queued_work_size = 0;

	return vcpu;
}

/*
static void kvm_cpu__enable_singlestep(struct kvm_cpu *vcpu)
{
	struct kvm_guest_debug debug = {
		.control	= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};

	if (ioctl(vcpu->vcpu_fd, KVM_SET_GUEST_DEBUG, &debug) < 0)
		pr_warning("KVM_SET_GUEST_DEBUG failed");
}
*/

static struct kvm_msrs *kvm_msrs__new(size_t nmsrs)
{
	struct kvm_msrs *vcpu = calloc(1, sizeof(*vcpu) + (sizeof(struct kvm_msr_entry) * nmsrs));

	if (!vcpu)
		die("out of memory");

	return vcpu;
}

#define KVM_MSR_ENTRY(_index, _data)	\
	(struct kvm_msr_entry) { .index = _index, .data = _data }

static void kvm_cpu__setup_msrs(struct kvm_cpu *vcpu)
{
	unsigned long ndx = 0;

	vcpu->msrs = kvm_msrs__new(100);

	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_CS,	0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_ESP,	0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_EIP,	0x0);
#ifdef CONFIG_X86_64
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_STAR,			0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_CSTAR,			0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_KERNEL_GS_BASE,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_SYSCALL_MASK,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_LSTAR,			0x0);
#endif
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_TSC,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_MISC_ENABLE,
						MSR_IA32_MISC_ENABLE_FAST_STRING);

	vcpu->msrs->nmsrs	= ndx;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_MSRS, vcpu->msrs) < 0)
		die_perror("KVM_SET_MSRS failed");
}

static void kvm_cpu__setup_fpu(struct kvm_cpu *vcpu)
{
	vcpu->fpu = (struct kvm_fpu) {
		.fcw		= 0x37f,
		.mxcsr		= 0x1f80,
	};

	if (ioctl(vcpu->vcpu_fd, KVM_SET_FPU, &vcpu->fpu) < 0)
		die_perror("KVM_SET_FPU failed");
}

static void kvm_cpu__setup_regs(struct kvm_cpu *vcpu)
{
	vcpu->regs = (struct kvm_regs) {
		/* We start the guest in 16-bit real mode  */
		.rflags		= 0x0000000000000002ULL,

		.rip		= vcpu->kvm->boot_ip,
		.rsp		= vcpu->kvm->boot_sp,
		.rbp		= vcpu->kvm->boot_sp,
	};

	if (vcpu->regs.rip > USHRT_MAX)
		die("ip 0x%llx is too high for real mode", (u64) vcpu->regs.rip);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs) < 0)
		die_perror("KVM_SET_REGS failed");
}

static void kvm_cpu__setup_sregs(struct kvm_cpu *vcpu)
{

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_GET_SREGS failed");

	vcpu->sregs.cs.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.cs.base	= selector_to_base(vcpu->kvm->boot_selector);

	vcpu->sregs.ss.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.ss.base	= selector_to_base(vcpu->kvm->boot_selector);

	vcpu->sregs.ds.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.ds.base	= selector_to_base(vcpu->kvm->boot_selector);

	vcpu->sregs.es.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.es.base	= selector_to_base(vcpu->kvm->boot_selector);

	vcpu->sregs.fs.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.fs.base	= selector_to_base(vcpu->kvm->boot_selector);

	vcpu->sregs.gs.selector	= vcpu->kvm->boot_selector;
	vcpu->sregs.gs.base	= selector_to_base(vcpu->kvm->boot_selector);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_SET_SREGS failed");
}

/**
 * kvm_cpu__reset_vcpu - reset virtual CPU to a known state
 */
void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu)
{
	kvm_cpu__setup_sregs(vcpu);
	kvm_cpu__setup_regs(vcpu);

	kvm_cpu__setup_fpu(vcpu);
	kvm_cpu__setup_msrs(vcpu);
}

static void print_dtable(const char *name, struct kvm_dtable *dtable, struct kvm_cpu *vcpu)
{
	dprintf(debug_fd, " %s                 %016llx  %08hx\n",
		name, (u64) dtable->base, (u16) dtable->limit);
}

static void print_segment(const char *name, struct kvm_segment *seg, struct kvm_cpu *vcpu)
{
	dprintf(debug_fd, " %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
		name, (u16) seg->selector, (u64) seg->base, (u32) seg->limit,
		(u8) seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_cpu__show_registers(struct kvm_cpu *vcpu)
{
	unsigned long cr0, cr2, cr3;
	unsigned long cr4, cr8;
	unsigned long rax, rbx, rcx;
	unsigned long rdx, rsi, rdi;
	unsigned long rbp,  r8,  r9;
	unsigned long r10, r11, r12;
	unsigned long r13, r14, r15;
	unsigned long rip, rsp;
	struct kvm_sregs sregs;
	unsigned long rflags;
	struct kvm_regs regs;
	int i;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &regs) < 0)
		die("KVM_GET_REGS failed");

	rflags = regs.rflags;

	rip = regs.rip; rsp = regs.rsp;
	rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
	rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
	rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
	r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
	r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

	debug_fd = stdout;
	dprintf(debug_fd, "\n");
	dprintf(debug_fd, " Registers:\n");
	dprintf(debug_fd,   " ----------\n");
	dprintf(debug_fd, " rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
	dprintf(debug_fd, " rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
	dprintf(debug_fd, " rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
	dprintf(debug_fd, " rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8,  r9);
	dprintf(debug_fd, " r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
	dprintf(debug_fd, " r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
		die("KVM_GET_REGS failed");

	cr0 = sregs.cr0; cr2 = sregs.cr2; cr3 = sregs.cr3;
	cr4 = sregs.cr4; cr8 = sregs.cr8;

	dprintf(debug_fd, " cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
	dprintf(debug_fd, " cr4: %016lx   cr8: %016lx\n", cr4, cr8);
        dprintf(debug_fd, "\n");
	dprintf(debug_fd, " Segment registers:\n");
	dprintf(debug_fd,   " ------------------\n");
	dprintf(debug_fd, " register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", &sregs.cs, vcpu);
	print_segment("ss ", &sregs.ss, vcpu);
	print_segment("ds ", &sregs.ds, vcpu);
	print_segment("es ", &sregs.es, vcpu);
	print_segment("fs ", &sregs.fs, vcpu);
	print_segment("gs ", &sregs.gs, vcpu);
	print_segment("tr ", &sregs.tr, vcpu);
	print_segment("ldt", &sregs.ldt, vcpu);
	print_dtable("gdt", &sregs.gdt, vcpu);
	print_dtable("idt", &sregs.idt, vcpu);

        dprintf(debug_fd, "\n");
	dprintf(debug_fd, " APIC:\n");
	dprintf(debug_fd, " -----\n");
	dprintf(debug_fd, " efer: %016llx  apic base: %016llx  nmi: %s\n",
		(u64) sregs.efer, (u64) sregs.apic_base,
		(vcpu->kvm->nmi_disabled ? "disabled" : "enabled"));

        dprintf(debug_fd, "\n");
	dprintf(debug_fd, " Interrupt bitmap:\n");
	dprintf(debug_fd,   " -----------------\n");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		dprintf(debug_fd, " %016llx", (u64) sregs.interrupt_bitmap[i]);
	dprintf(debug_fd, "\n");
}

#define MAX_SYM_LEN		128

void kvm_cpu__show_code(struct kvm_cpu *vcpu)
{
	unsigned int code_bytes = 64;
	unsigned int code_prologue = code_bytes * 43 / 64;
	unsigned int code_len = code_bytes;
	char sym[MAX_SYM_LEN];
	unsigned char c;
	unsigned int i;
	u8 *ip;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &vcpu->regs) < 0)
		die("KVM_GET_REGS failed");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die("KVM_GET_SREGS failed");

	ip = guest_flat_to_host(vcpu->kvm, ip_to_flat(vcpu, vcpu->regs.rip) - code_prologue);

        dprintf(debug_fd, "\n");
	dprintf(debug_fd, " Code:\n");
	dprintf(debug_fd, " -----\n");

	symbol__lookup(vcpu->kvm, vcpu->regs.rip, sym, MAX_SYM_LEN);

	dprintf(debug_fd, " rip: [<%016lx>] %s\n\n", (unsigned long) vcpu->regs.rip, sym);

	for (i = 0; i < code_len; i++, ip++) {
		if (!host_ptr_in_ram(vcpu->kvm, ip))
			break;

		c = *ip;

		if (ip == guest_flat_to_host(vcpu->kvm, ip_to_flat(vcpu, vcpu->regs.rip)))
			dprintf(debug_fd, " <%02x>", c);
		else
			dprintf(debug_fd, " %02x", c);
	}

	dprintf(debug_fd, "\n");

        dprintf(debug_fd, "\n");
	dprintf(debug_fd, " Stack:\n");
	dprintf(debug_fd, " ------\n");
	kvm__dump_mem(vcpu->kvm, (vcpu->regs.rsp)-32, 64);
}

void kvm_cpu__show_page_tables(struct kvm_cpu *vcpu)
{
	u64 *pte1;
	u64 *pte2;
	u64 *pte3;
	u64 *pte4;

	if (!is_in_protected_mode(vcpu))
		return;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die("KVM_GET_SREGS failed");

	pte4	= guest_flat_to_host(vcpu->kvm, vcpu->sregs.cr3);
	if (!host_ptr_in_ram(vcpu->kvm, pte4))
		return;

	pte3	= guest_flat_to_host(vcpu->kvm, (*pte4 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte3))
		return;

	pte2	= guest_flat_to_host(vcpu->kvm, (*pte3 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte2))
		return;

	pte1	= guest_flat_to_host(vcpu->kvm, (*pte2 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte1))
		return;

	dprintf(debug_fd, "Page Tables:\n");
	if (*pte2 & (1 << 7))
		dprintf(debug_fd, " pte4: %016llx   pte3: %016llx"
			"   pte2: %016llx\n",
			*pte4, *pte3, *pte2);
	else
		dprintf(debug_fd, " pte4: %016llx  pte3: %016llx   pte2: %016"
			"llx   pte1: %016llx\n",
			*pte4, *pte3, *pte2, *pte1);
}

extern void systemc_wait_until_runnable(void *_this);
extern void systemc_notify_runnable_event(void *_this);
extern void **p_sysc_cpu_wrapper;

/* Check if the current CPU has received an Init IPI */
int kvm_cpu_init_received(void * kvm_cpu_inst)
{
    struct kvm_cpu * vcpu = kvm_cpu_inst;
	struct kvm_mp_state state;

	ioctl(vcpu->vcpu_fd, KVM_GET_MP_STATE, &state);
	switch(state.mp_state)
	{
		case KVM_MP_STATE_UNINITIALIZED:
			//printf("VCPU-%d: KVM_MP_STATE_UNINITIALIZED\n", (u32) vcpu->cpu_id);
			break;

		case KVM_MP_STATE_INIT_RECEIVED: 
			printf("VCPU-%d: KVM_MP_STATE_INIT_RECEIVED\n", (u32) vcpu->cpu_id);
			return 1;
	}

	return 0;
}

/* Check if the current CPU has received an Startup IPI */
int kvm_cpu_sipi_received(void * kvm_cpu_inst)
{
    struct kvm_cpu * vcpu = kvm_cpu_inst;
	struct kvm_mp_state state;

	ioctl(vcpu->vcpu_fd, KVM_GET_MP_STATE, &state);
	switch(state.mp_state)
	{
		case KVM_MP_STATE_UNINITIALIZED:
			//printf("VCPU-%d: KVM_MP_STATE_UNINITIALIZED\n", (u32) vcpu->cpu_id);
			break;

		case KVM_MP_STATE_SIPI_RECEIVED: 
			printf("VCPU-%d: KVM_MP_STATE_SIPI_RECEIVED\n", (u32) vcpu->cpu_id);
			return 1;
	}

	return 0;
}

/* Check if the current CPU is in Runnable State */ 
int kvm_cpu_is_runnable(void * kvm_cpu_inst)
{
    struct kvm_cpu * vcpu = kvm_cpu_inst;
	struct kvm_mp_state state;
	int err;

	err = ioctl(vcpu->vcpu_fd, KVM_GET_MP_STATE, &state);
	if(err && (errno == EBADF))
	{
		printf("VCPU-%d: ERROR in KVM_GET_MP_STATE\n", (u32) vcpu->cpu_id);
		return 0;
	}
	
	if(state.mp_state == KVM_MP_STATE_RUNNABLE)
	{
		//printf("VCPU-%d: KVM_MP_STATE_RUNNABLE\n", (u32) vcpu->cpu_id);
		return 1;
	}

	return 0;
}

#if 0
void kvm_cpu_set_run_state(struct kvm_cpu *vcpu, int run_state)
{
	struct kvm_run_state rs;
	rs.run_state = run_state;

//	printf("Address of Runstate: %p\n", & rs);
    if (ioctl(vcpu->vcpu_fd, KVM_RUN_STATE, & rs) < 0)
        die_perror("KVM_RUN_STATE failed");
}
#endif

void * kvm_cpu__run(struct kvm_cpu *vcpu, int *retry_to_run)
{
	int err;
	int kick_vcpu_id;
	*retry_to_run = 0;	

	//printf("Calling KVM_RUN VCPU-%d ... \n", (u32)vcpu->cpu_id);

	err = ioctl(vcpu->vcpu_fd, KVM_RUN, 0);

	if(err && (errno == 99 || errno >= 100))
	{
		if(errno == 99){
			*retry_to_run = 1;
			return NULL;
		}
		else
		{
			kick_vcpu_id = errno - 100;
			if(kick_vcpu_id >= 0 && kick_vcpu_id < vcpu->kvm->nrcpus)
				return (p_sysc_cpu_wrapper[kick_vcpu_id]);
			else
				return NULL;		
		}
	}

	if(err && (errno != EAGAIN && errno != EINTR))
	{
		die_perror("KVM_RUN failed");
	}

	return NULL;
}

void kvm_cpu_kick(void * kick_cpu)
{
	systemc_notify_runnable_event(kick_cpu);
}

/*
static void kvm_cpu_signal_handler(int signum)
{
	if (signum == SIGKVMEXIT) {
		if (current_kvm_cpu && current_kvm_cpu->is_running) {
			current_kvm_cpu->is_running = false;
			pthread_kill(pthread_self(), SIGKVMEXIT);
		}
	} else if (signum == SIGKVMPAUSE) {
		printf("KVM Pause Signal Received\n");
		current_kvm_cpu->paused = 1;
	}
}
*/

static void kvm_cpu__handle_coalesced_mmio(struct kvm_cpu *cpu)
{
	if (cpu->ring) {
#ifdef DEBUG_MMIO
                if(cpu->ring->first != cpu->ring->last){
                        struct kvm_coalesced_mmio *m;
                        __u32 first = cpu->ring->first, last = cpu->ring->last;

                        while (first != last)
                        {
                            m = &cpu->ring->coalesced_mmio[first];

                            if(m->len == 1)
                            {
                                printf(">>>>COALESCED_MMIO (Write): Address = 0x%08X, Length = %d, Data = %c\n",
                                       (u32) m->phys_addr, (u32) m->len, m->data[0]);
                            }
                            else
                            {
                                printf(">>>>COALESCED_MMIO (Write): Address = 0x%08X, Length = %d, Data = 0x%08X\n",
                                       (u32) m->phys_addr, (u32) m->len, *((u32 * )m->data));
                            }

                            first = (first + 1) % KVM_COALESCED_MMIO_MAX;
                        }
                }
#endif
		while (cpu->ring->first != cpu->ring->last) {
			struct kvm_coalesced_mmio *m;
			m = &cpu->ring->coalesced_mmio[cpu->ring->first];

			kvm__emulate_mmio(cpu,
					m->phys_addr,
					m->data,
					m->len,
					1);
			cpu->ring->first = (cpu->ring->first + 1) % KVM_COALESCED_MMIO_MAX;
		}
	}
}

void kvm_cpu__reboot(void)
{
	int i;

	for (i = 0; i < KVM_NR_CPUS; i++)
		if (kvm_cpus[i])
			pthread_kill(kvm_cpus[i]->thread, SIGKVMEXIT);
}

/*
static int kvm_set_signal_mask(CPUState *env, const sigset_t *sigset)
{
    struct kvm_signal_mask *sigmask;
    int r;

    if (!sigset) {
        return ioctl(env->vcpu_fd, KVM_SET_SIGNAL_MASK, NULL);
    }

    sigmask = malloc(sizeof(*sigmask) + sizeof(*sigset));
    sigmask->len = 8;
    memcpy(sigmask->sigset, sigset, sizeof(*sigset));
    r = ioctl(env->vcpu_fd, KVM_SET_SIGNAL_MASK, sigmask);
    free(sigmask);

    return r;
}
*/

//static void dummy_signal(int sig){}

/*
static void kvm_init_cpu_signals(CPUState *env)
{
    int r;
    sigset_t set;
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = dummy_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    sigdelset(&set, SIGBUS);
    r = kvm_set_signal_mask(env, &set);
    if (r) {
        fprintf(stderr, "kvm_set_signal_mask: %s\n", strerror(-r));
        exit(1);
    }
}
*/

//extern pthread_mutex_t kvm_global_mutex;
//extern pthread_cond_t kvm_work_cond;

int kvm_cpu_reset(void *vcpu)
{
	struct kvm_cpu *cpu = (struct kvm_cpu *) vcpu;
	/*
	if(cpu->cpu_id == 0)
	{
		sigset_t sigset;

		sigemptyset(&sigset);
		sigaddset(&sigset, SIGALRM);

		pthread_sigmask(SIG_BLOCK, &sigset, NULL);

		signal(SIGKVMEXIT, kvm_cpu_signal_handler);
		signal(SIGKVMPAUSE, kvm_cpu_signal_handler);

        // TODO: Use mutex_lock defined in kvm/mutex.h
        // kvm_mutex_lock(&kvm_global_mutex);
	    kvm_init_cpu_signals(cpu);
	}*/

	kvm_cpu__setup_cpuid(cpu);
	kvm_cpu__reset_vcpu(cpu);

    if ((cpu->kvm->sw_single_step > 0))
    {
        kvm_update_guest_debug(cpu, 0);
    }

	return KVM_CPU_OK;
}

int kvm_cpu_execute(void *vcpu)
{
	struct kvm_cpu *cpu = (struct kvm_cpu *) vcpu;
	void * kick_cpu = NULL;
	int cpu_status = KVM_CPU_OK;
	int retry_to_run = 0;
		
	if (cpu->kvm_vcpu_dirty) {
		kvm_arch_put_registers(cpu);
		cpu->kvm_vcpu_dirty = 0;
	}

	// printf("Calling KVM_RUN VCPU-%d ... \n", (u32)cpu->cpu_id);
    kick_cpu = kvm_cpu__run(cpu, &retry_to_run);
	if(retry_to_run) 
		cpu_status = KVM_CPU_RETRY;

	switch (cpu->kvm_run->exit_reason)
    {
        case KVM_EXIT_UNKNOWN:
            //printf("KVM_EXIT_UNKNOWN [CPU # %d]: H/W Exit Reason = 0x%08X, cpu->kvm_run->fail_entry = 0x%X\n",
            //          (u32) cpu->cpu_id, (unsigned int)(cpu->kvm_run->hw.hardware_exit_reason), 
            //          (unsigned int)(cpu->kvm_run->fail_entry.hardware_entry_failure_reason));
            break;
		case KVM_EXIT_DEBUG:
            kvm_arch_handle_debug(cpu);
            //kvm_cpu__show_registers(cpu);
            //kvm_cpu__show_code(cpu);
            break;
		case KVM_EXIT_IO: {
			bool ret;

			ret = kvm__emulate_io(cpu,
					cpu->kvm_run->io.port,
					(u8 *)cpu->kvm_run +
					cpu->kvm_run->io.data_offset,
					cpu->kvm_run->io.direction,
					cpu->kvm_run->io.size,
					cpu->kvm_run->io.count);

			if (!ret)
				goto panic_kvm;
			break;
		}
		case KVM_EXIT_MMIO: {
			bool ret;
#ifdef DEBUG_MMIO
       		printf("MMIO@VCPU-%d: Address = 0x%08X, Length = %d, is_write = %d ... ",
				   (u32) cpu->cpu_id,
                   (u32) cpu->kvm_run->mmio.phys_addr,
				   (u32) cpu->kvm_run->mmio.len, 
				   (u32) cpu->kvm_run->mmio.is_write);
#endif
	        ret = kvm__emulate_mmio(cpu,
     				                cpu->kvm_run->mmio.phys_addr,
                                    cpu->kvm_run->mmio.data,
                                    cpu->kvm_run->mmio.len,
                                    cpu->kvm_run->mmio.is_write);
			if (!ret)
				goto panic_kvm;
       		
			break;
		}
		case KVM_EXIT_INTR:
			printf("KVM_EXIT_INTR: VCPU-%d\n", (u32) cpu->cpu_id);
			break;

		case KVM_EXIT_SHUTDOWN:
			printf("KVM_EXIT_SHUTDOWN: VCPU-%d\n", (u32) cpu->cpu_id);
			cpu_status = KVM_CPU_SHUTDOWN;
		}

		kvm_cpu__handle_coalesced_mmio(cpu);

		if(kick_cpu){
			kvm_cpu_kick(kick_cpu);
			cpu_status = KVM_CPU_BLOCK_AFTER_KICK; // We kicked someone else; So we should block for some time.
		}

	return cpu_status;

panic_kvm:
	return KVM_CPU_PANIC;
}
