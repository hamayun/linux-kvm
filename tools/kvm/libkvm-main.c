#include "kvm/parse-options.h"
#include "kvm/8250-serial.h"
#include "kvm/threadpool.h"
#include "kvm/ioeventfd.h"
#include "kvm/barrier.h"
#include "kvm/kvm-cpu.h"
#include "kvm/ioport.h"
#include "kvm/symbol.h"
#include "kvm/kvm.h"
#include "kvm/pci-shmem.h"
#include "kvm/kvm-ipc.h"

#include <linux/types.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>

#include "kvm/libkvm-main.h"
#include "gdb_srv.h"

#define DEFAULT_KVM_DEV	    "/dev/kvm"
#define DEFAULT_CONSOLE	    "serial"

#define MB_SHIFT	    (20)
#define KB_SHIFT	    (10)
#define GB_SHIFT	    (30)

#define MIN_RAM_SIZE_MB	    (64ULL)
#define MIN_RAM_SIZE_BYTE	(MIN_RAM_SIZE_MB << MB_SHIFT)

struct kvm *kvm;
struct kvm * kvm_instances[10];
int          no_kvm_instances = 0;

struct kvm_cpu *kvm_cpus[KVM_NR_CPUS];
__thread struct kvm_cpu *current_kvm_cpu;

static u64 ram_size;

static unsigned int nr_online_cpus;
static const char *kernel_cmdline;
static const char *kernel_filename;
static const char *initrd_filename;
static const char *console;
static const char *dev;
static const char *guest_name;
extern bool ioport_debug;
extern int active_console;
extern int debug_iodelay;
int      kvm_debug_port = 0;

bool do_debug_print = false;

static int nrcpus;

static const char * const run_usage[] = {
    "kvm run [<options>] [<kernel image>]",
	NULL
};

static int shmem_parser(const struct option *opt, const char *arg, int unset)
{
	const u64 default_size = SHMEM_DEFAULT_SIZE;
	const u64 default_phys_addr = SHMEM_DEFAULT_ADDR;
	const char *default_handle = SHMEM_DEFAULT_HANDLE;
	struct shmem_info *si = malloc(sizeof(struct shmem_info));
	u64 phys_addr;
	u64 size;
	char *handle = NULL;
	int create = 0;
	const char *p = arg;
	char *next;
	int base = 10;
	int verbose = 0;

	const int skip_pci = strlen("pci:");
	if (verbose)
    	pr_info("shmem_parser(%p,%s,%d)", opt, arg, unset);
    /* parse out optional addr family */
	if (strcasestr(p, "pci:")) {
    	p += skip_pci;
    } else if (strcasestr(p, "mem:")) {
    	die("I can't add to E820 map yet.\n");
    }
    /* parse out physical addr */
	base = 10;
	if (strcasestr(p, "0x"))
    	base = 16;
	phys_addr = strtoll(p, &next, base);
	if (next == p && phys_addr == 0) {
    	pr_info("shmem: no physical addr specified, using default.");
    	phys_addr = default_phys_addr;
    }
	if (*next != ':' && *next != '\0')
    	die("shmem: unexpected chars after phys addr.\n");
	if (*next == '\0')
    	p = next;
	else
    	p = next + 1;
    /* parse out size */
	base = 10;
	if (strcasestr(p, "0x"))
    	base = 16;
	size = strtoll(p, &next, base);
	if (next == p && size == 0) {
    	pr_info("shmem: no size specified, using default.");
    	size = default_size;
    }
    /* look for [KMGkmg][Bb]*  uses base 2. */
	int skip_B = 0;
	if (strspn(next, "KMGkmg")) {    /* might have a prefix */
    	if (*(next + 1) == 'B' || *(next + 1) == 'b')
        	skip_B = 1;
    	switch (*next) {
    	case 'K':
    	case 'k':
        	size = size << KB_SHIFT;
        	break;
    	case 'M':
    	case 'm':
        	size = size << MB_SHIFT;
        	break;
    	case 'G':
    	case 'g':
        	size = size << GB_SHIFT;
        	break;
    	default:
        	die("shmem: bug in detecting size prefix.");
        	break;
        }
    	next += 1 + skip_B;
    }
	if (*next != ':' && *next != '\0') {
    	die("shmem: unexpected chars after phys size. <%c><%c>\n",
            *next, *p);
    }
	if (*next == '\0')
    	p = next;
	else
    	p = next + 1;
    /* parse out optional shmem handle */
	const int skip_handle = strlen("handle=");
	next = strcasestr(p, "handle=");
	if (*p && next) {
    	if (p != next)
        	die("unexpected chars before handle\n");
    	p += skip_handle;
    	next = strchrnul(p, ':');
    	if (next - p) {
        	handle = malloc(next - p + 1);
        	strncpy(handle, p, next - p);
        	handle[next - p] = '\0';    /* just in case. */
        }
    	if (*next == '\0')
        	p = next;
    	else
        	p = next + 1;
    }
    /* parse optional create flag to see if we should create shm seg. */
	if (*p && strcasestr(p, "create")) {
    	create = 1;
    	p += strlen("create");
    }
	if (*p != '\0')
    	die("shmem: unexpected trailing chars\n");
	if (handle == NULL) {
    	handle = malloc(strlen(default_handle) + 1);
    	strcpy(handle, default_handle);
    }
	if (verbose) {
    	pr_info("shmem: phys_addr = %llx", phys_addr);
    	pr_info("shmem: size      = %llx", size);
    	pr_info("shmem: handle    = %s", handle);
    	pr_info("shmem: create    = %d", create);
    }

	si->phys_addr = phys_addr;
	si->size = size;
	si->handle = handle;
	si->create = create;
	pci_shmem__register_mem(si);    /* ownership of si, etc. passed on. */
	return 0;
}

static const struct option options[] = {
	OPT_GROUP("Basic options:"),
	OPT_INTEGER('c', "cpus", &nrcpus, "Number of CPUs"),
	OPT_U64('m', "mem", &ram_size, "Virtual machine memory size in MiB."),
	OPT_CALLBACK('\0', "shmem", NULL,
             "[pci:]<addr>:<size>[:handle=<handle>][:create]",
             "Share host shmem with guest via pci device",
             shmem_parser),
	OPT_STRING('\0', "dev", &dev, "device_file", "KVM device file"),

    OPT_GROUP("Kernel options:"),
	OPT_STRING('k', "kernel", &kernel_filename, "kernel",
            "Kernel to boot in virtual machine"),
	OPT_STRING('i', "initrd", &initrd_filename, "initrd",
            "Initial RAM disk image"),
	OPT_STRING('p', "params", &kernel_cmdline, "params",
            "Kernel command line arguments"),

	OPT_GROUP("Debug options:"),
	OPT_BOOLEAN('\0', "debug", &do_debug_print, "Enable debug messages"),
	OPT_INTEGER('\0', "debug-port", &kvm_debug_port, "The debug port to use for GDB Server"),
	OPT_BOOLEAN('\0', "debug-ioport", &ioport_debug, "Enable ioport debugging"),
	OPT_INTEGER('\0', "debug-iodelay", &debug_iodelay, "Delay IO by millisecond"),
	OPT_END()
};

/*
 * Serialize debug printout so that the output of multiple vcpus does not
 * get mixed up:
 */
static int printout_done;

static void handle_sigusr1(int sig)
{
	struct kvm_cpu *cpu = current_kvm_cpu;
	int fd = kvm_cpu__get_debug_fd();

	if (!cpu)
    	return;

	dprintf(fd, "\n #\n # vCPU #%ld's dump:\n #\n", cpu->cpu_id);
	kvm_cpu__show_registers(cpu);
	kvm_cpu__show_code(cpu);
	kvm_cpu__show_page_tables(cpu);
	fflush(stdout);
	printout_done = 1;
	mb();
}

/* Pause/resume the guest using SIGUSR2 */
static int is_paused;

static void handle_pause(int fd, u32 type, u32 len, u8 *msg)
{
	if (type == KVM_IPC_RESUME && is_paused)
    	kvm__continue();
	else if (type == KVM_IPC_PAUSE && !is_paused)
    	kvm__pause();
	else
    	return;

	is_paused = !is_paused;
	pr_info("Guest %s\n", is_paused ? "paused" : "resumed");
}

static void handle_sigalrm(int sig)
{
/*
	serial8250__inject_interrupt(kvm);
	virtio_console__inject_interrupt(kvm);
*/
}

static void handle_stop(int fd, u32 type, u32 len, u8 *msg)
{
	kvm_cpu__reboot();
}

static void *kvm_cpu_thread(void *arg)
{
	current_kvm_cpu	    = arg;

	if (kvm_cpu__start(current_kvm_cpu))
    	goto panic_kvm;

	kvm_cpu__delete(current_kvm_cpu);

	return (void *) (intptr_t) 0;

panic_kvm:
	fprintf(stderr, "KVM exit reason: %u (\"%s\")\n",
    	current_kvm_cpu->kvm_run->exit_reason,
    	kvm_exit_reasons[current_kvm_cpu->kvm_run->exit_reason]);
	if (current_kvm_cpu->kvm_run->exit_reason == KVM_EXIT_UNKNOWN)
    	fprintf(stderr, "KVM exit code: 0x%Lu\n",
        	current_kvm_cpu->kvm_run->hw.hardware_exit_reason);

	kvm_cpu__set_debug_fd(STDOUT_FILENO);
	kvm_cpu__show_registers(current_kvm_cpu);
	kvm_cpu__show_code(current_kvm_cpu);
	kvm_cpu__show_page_tables(current_kvm_cpu);

	kvm_cpu__delete(current_kvm_cpu);

	return (void *) (intptr_t) 1;
}

static char kernel[PATH_MAX];

static const char *host_kernels[] = {
    "/boot/vmlinuz",
    "/boot/bzImage",
	NULL
};

static const char *default_kernels[] = {
    "./bzImage",
    "../../arch/x86/boot/bzImage",
	NULL
};

/*
static const char *default_vmlinux[] = {
    "../../../vmlinux",
    "../../vmlinux",
	NULL
};
*/

static void kernel_usage_with_options(void)
{
	const char **k;
	struct utsname uts;

	fprintf(stderr, "Fatal: could not find default kernel image in:\n");
	k = &default_kernels[0];
	while (*k) {
    	fprintf(stderr, "\t%s\n", *k);
    	k++;
    }

	if (uname(&uts) < 0)
    	return;

	k = &host_kernels[0];
	while (*k) {
    	if (snprintf(kernel, PATH_MAX, "%s-%s", *k, uts.release) < 0)
        	return;
    	fprintf(stderr, "\t%s\n", kernel);
    	k++;
    }
	fprintf(stderr, "\nPlease see 'kvm run --help' for more options.\n\n");
}

static u64 host_ram_size(void)
{
	long page_size;
	long nr_pages;

	nr_pages	= sysconf(_SC_PHYS_PAGES);
	if (nr_pages < 0) {
    	pr_warning("sysconf(_SC_PHYS_PAGES) failed");
    	return 0;
    }

	page_size	= sysconf(_SC_PAGE_SIZE);
	if (page_size < 0) {
    	pr_warning("sysconf(_SC_PAGE_SIZE) failed");
    	return 0;
    }

	return (nr_pages * page_size) >> MB_SHIFT;
}

/*
 * If user didn't specify how much memory it wants to allocate for the guest,
 * avoid filling the whole host RAM.
 */
#define RAM_SIZE_RATIO		0.8

static u64 get_ram_size(int nr_cpus)
{
	u64 available;
	u64 ram_size;

    ram_size	= 64 * (nr_cpus + 3);

	available	= host_ram_size() * RAM_SIZE_RATIO;
	if (!available)
    	available = MIN_RAM_SIZE_MB;

	if (ram_size > available)
    	ram_size	= available;

	return ram_size;
}

#if 0
static const char *find_kernel(void)
{
	const char **k;
	struct stat st;
	struct utsname uts;

	k = &default_kernels[0];
	while (*k) {
    	if (stat(*k, &st) < 0 || !S_ISREG(st.st_mode)) {
        	k++;
        	continue;
        }
    	strncpy(kernel, *k, PATH_MAX);
    	return kernel;
    }

	if (uname(&uts) < 0)
    	return NULL;

	k = &host_kernels[0];
	while (*k) {
    	if (snprintf(kernel, PATH_MAX, "%s-%s", *k, uts.release) < 0)
        	return NULL;

    	if (stat(kernel, &st) < 0 || !S_ISREG(st.st_mode)) {
        	k++;
        	continue;
        }
    	return kernel;

    }
	return NULL;
}

static const char *find_vmlinux(void)
{
	const char **vmlinux;

	vmlinux = &default_vmlinux[0];
	while (*vmlinux) {
    	struct stat st;

    	if (stat(*vmlinux, &st) < 0 || !S_ISREG(st.st_mode)) {
        	vmlinux++;
        	continue;
        }
    	return *vmlinux;
    }
	return NULL;
}
#endif

void kvm_help(void)
{
	usage_with_options(run_usage, options);
}

void * p_kvm_wrapper = NULL;
extern uint64_t systemc_kvm_read_memory (void *_this, uint32_t cpu_id, uint64_t addr,
										 int nbytes, unsigned int *ns, int bIO);
extern void     systemc_kvm_write_memory (void *_this, uint32_t cpu_id, uint64_t addr,
										  unsigned char *data, int nbytes, unsigned int *ns, int bIO);

static void generic_systemc_mmio_handler(struct kvm_cpu * cpu, u64 addr, u8 *data, u32 len, u8 is_write, void *ptr)
{
    u64 value;
    u32 i;

# if 1		// Verify that each CPU is Actually Running 
	static u64 id_list[256] = {0};
	static u32 id_count = 0;
	u32	found = 0;

	for(i = 0; i < id_count; i++)
	{
		if(id_list[i] == cpu->cpu_id)
		{
			found = 1;
			break;
		}
	}

	if(!found)
	{
		id_list[id_count++] = cpu->cpu_id;
		printf("MMIO Request: KVM CPU ID = %ld\n", cpu->cpu_id);
	}
#endif

    if(is_write)
    {
        //printf("MMIO Write: addr = 0x%x, len = 0x%x\n", (u32) addr, len);
        systemc_kvm_write_memory(p_kvm_wrapper, (uint32_t) cpu->cpu_id, addr, data, len, NULL, 1);
    }
    else
    {
        //printf("MMIO Read: addr = 0x%x, len = 0x%x\n", (u32) addr, len);
        value = systemc_kvm_read_memory(p_kvm_wrapper, (uint32_t) cpu->cpu_id, addr, len, NULL, 1);
        for (i = 0; i < len; i++)
            data[i] = *((unsigned char *) &value + i);
    }

    return;
}

static int kvm_register_systemc_mmio_callbacks(struct kvm *kvm)
{
    //TODO: Move these registration steps to kvm_processor component and use node maps.
    // Also consider modifying the node maps for device type; Input/Output or Output only.
    // So as to decide which type of MMIO mapping be used. Normal or Coalesced.

    //kvm__register_coalesced_mmio(kvm, 0xC0000000, 0x40, generic_systemc_mmio_handler, NULL); // Causes some problems in Printing to TTY
    kvm__register_mmio(kvm, 0xC0000000, 0x40, generic_systemc_mmio_handler, NULL);
    kvm__register_mmio(kvm, 0xC1000000, 0x10, generic_systemc_mmio_handler, NULL);

    kvm__register_mmio(kvm, 0xC3000000, 0x1000, generic_systemc_mmio_handler, NULL);
    kvm__register_mmio(kvm, 0xC4000000, 0x100000, generic_systemc_mmio_handler, NULL);

    kvm__register_mmio(kvm, 0xC6000000, 0x100000, generic_systemc_mmio_handler, NULL);
    kvm__register_mmio(kvm, 0xC6500000, 0x100000, generic_systemc_mmio_handler, NULL);
    kvm__register_mmio(kvm, 0xC6A00000, 0x100000, generic_systemc_mmio_handler, NULL);
    return 0;
}

static bool semihosting_io_in(struct ioport *ioport, struct kvm *kvm, u16 port, void *data, int size)
{
    uint32_t * pdata = (uint32_t *) data;
    *pdata = 1;

    printf("semihosting_io_in: Port = %X, Size = %d, Data = 0x%X\n", port, size, *pdata);
    return true;
}

static bool semihosting_io_out(struct ioport *ioport, struct kvm *kvm, u16 port, void *data, int size)
{
    uint32_t * pdata = (uint32_t *) data;

    printf("semihosting_io_out: Port = %X, Size = %d, Data = 0x%X\n", port, size, *pdata);
    return true;
}

static struct ioport_operations semihosting_read_write_ioport_ops = {
    .io_in	    = semihosting_io_in,
    .io_out	    = semihosting_io_out,
};

static int kvm_register_io_callbacks(struct kvm *kvm)
{
    ioport__register(0x1000, &semihosting_read_write_ioport_ops, 0x10+1, NULL);
	return 0;
}

void * kvm_internal_init(struct kvm_import_export_t * kie, uint32_t num_cpus, uint64_t ram_size /* MBs */,
					     const char * kernel, const char * boot_loader, void * kvm_userspace_mem_addr)
{
	static char default_name[20];
	int max_cpus, recommended_cpus;

	// Get the KVM WRAPPER Reference
	p_kvm_wrapper = kie->imp_kvm_wrapper;

    // Fill in the function table for SystemC (Called by Platform or Components)
	kie->exp_gdb_srv_start_and_wait = (gdb_srv_start_and_wait_fc_t) gdb_srv_start_and_wait;

	signal(SIGALRM, handle_sigalrm);
	signal(SIGUSR1, handle_sigusr1);

	kvm_ipc__register_handler(KVM_IPC_PAUSE, handle_pause);
	kvm_ipc__register_handler(KVM_IPC_RESUME, handle_pause);
	kvm_ipc__register_handler(KVM_IPC_STOP, handle_stop);

	nr_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
#if 0
	while (argc != 0) {
    	argc = parse_options(argc, argv, options, run_usage,
            	PARSE_OPT_STOP_AT_NON_OPTION);
    	if (argc != 0) {
        	if (kernel_filename) {
            	fprintf(stderr, "Cannot handle parameter: "
                        "%s\n", argv[0]);
            	usage_with_options(run_usage, options);
            	return ((void *) EINVAL);
            }
            /* first unhandled parameter is treated as a kernel
               image
             */
        	kernel_filename = argv[0];
        	argv++;
        	argc--;
        }

    }

	if (!kernel_filename)
    	kernel_filename = find_kernel();
#endif

    nrcpus = num_cpus;
	kernel_filename = kernel;

	if (!kernel_filename) {
    	kernel_usage_with_options();
    	return ((void *) EINVAL);
    }

	if (nrcpus == 0)
    	nrcpus = nr_online_cpus;
	else if (nrcpus < 1 || nrcpus > KVM_NR_CPUS)
    	die("Number of CPUs %d is out of [1;%d] range", nrcpus, KVM_NR_CPUS);

	if (!ram_size)
    	ram_size	= get_ram_size(nrcpus);
    //printf("  # Allocating %lld MB of RAM for %d CPUs\n", ram_size, nrcpus);

	if (ram_size < MIN_RAM_SIZE_MB)
    	die("Not enough memory specified: %lluMB (min %lluMB)", ram_size, MIN_RAM_SIZE_MB);

	if (ram_size > host_ram_size())
    	pr_warning("Guest memory size %lluMB exceeds host physical RAM size %lluMB", ram_size, host_ram_size());

	ram_size <<= MB_SHIFT;

	if (!dev)
    	dev = DEFAULT_KVM_DEV;

	if (!console)
    	console = DEFAULT_CONSOLE;

	if (!guest_name) {
    	sprintf(default_name, "guest-%u", getpid());
    	guest_name = default_name;
    }

	kvm = kvm__init(dev, ram_size, guest_name);

    if(kvm_debug_port)
    {
        kvm->enable_debug_mode = true;
        // We force single stepping for first instruction only; afterwards we disable it.
        kvm->sw_single_step = 1;        // Single step for one instruction
        gdb_srv_init (kvm);
    }
    else
    {
        // single stepping mode without gdb support.
        kvm->sw_single_step = 0;
        kvm->enable_debug_mode = false;
    }

    kvm_userspace_mem_addr = kvm->ram_start;

    kvm_register_systemc_mmio_callbacks(kvm);
    kvm_register_io_callbacks(kvm);

	max_cpus = kvm__max_cpus(kvm);
	recommended_cpus = kvm__recommended_cpus(kvm);

	if (nrcpus > max_cpus) {
    	printf("  # Limit the number of CPUs to %d\n", max_cpus);
    	kvm->nrcpus	= max_cpus;
    } else if (nrcpus > recommended_cpus) {
    	printf("  # Warning: The maximum recommended amount of VCPUs"
            " is %d\n", recommended_cpus);
    }

	kvm->nrcpus = nrcpus;

	printf("<%s> Kernel File=%s, Boot Loader=%s, CPUs=%d, RAM Size=%Lu\n", 
			__func__, kernel_filename, boot_loader, nrcpus, ram_size / 1024 / 1024);

    if(!kvm__load_bootstrap_elf_kernel(kvm, kernel_filename, boot_loader))
        die("unable to load bootloader or elf kernel");

    printf("KVM Initialized\n");
    return (void *) kvm;             // Return KVM Instance Pointer to Caller
}

int kvm_run_cpus(void)
{
    int i;
    int exit_code = 0;
    void *ret;

	//ioport__setup_legacy();
	//serial8250__init(kvm);

	kvm__setup_bios(kvm);

    printf("Initializing KVM VCPUs ... ");

	for (i = 0; i < nrcpus; i++) {
        printf("%d  ", i);

        kvm_cpus[i] = kvm_cpu__init(kvm, i);
    	if (!kvm_cpus[i])
        	die("unable to initialize KVM VCPU");

        if(i == 0)
            kvm->first_cpu = kvm_cpus[i];
        else
            kvm_cpus[i-1]->next_cpu = kvm_cpus[i];

        kvm_cpus[i]->next_cpu = NULL;
    }
    printf("\n");

	kvm__init_ram(kvm);

	for (i = 0; i < nrcpus; i++) {
    	if (pthread_create(&kvm_cpus[i]->thread, NULL, kvm_cpu_thread, kvm_cpus[i]) != 0)
        	die("unable to create KVM VCPU thread");
    }

    /* Only VCPU #0 is going to exit by itself when shutting down */
	if (pthread_join(kvm_cpus[0]->thread, &ret) != 0)
    	exit_code = 1;

	for (i = 1; i < nrcpus; i++) {
    	if (kvm_cpus[i]->is_running) {
        	pthread_kill(kvm_cpus[i]->thread, SIGKVMEXIT);
        	if (pthread_join(kvm_cpus[i]->thread, &ret) != 0)
            	die("pthread_join");
        }
    	if (ret != NULL)
        	exit_code = 1;
    }

	kvm__delete(kvm);

	if (!exit_code)
    	printf("\n  # KVM session ended normally.\n");

	return exit_code;
}
