#include "kvm/kvm.h"

#include "kvm/boot-protocol.h"
#include "kvm/cpufeature.h"
#include "kvm/read-write.h"
#include "kvm/interrupt.h"
#include "kvm/mptable.h"
#include "kvm/util.h"
#include "kvm/mutex.h"
#include "kvm/kvm-cpu.h"
#include "kvm/kvm-ipc.h"

#include <linux/kvm.h>

#include <asm/bootparam.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <sys/eventfd.h>
#include <asm/unistd.h>
#include <dirent.h>

#include <libelf.h>
#include <gelf.h>

#include "gdb_srv_arch.h"

#define DEFINE_KVM_EXIT_REASON(reason) [reason] = #reason

const char *kvm_exit_reasons[] = {
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_UNKNOWN),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_EXCEPTION),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_IO),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_HYPERCALL),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_DEBUG),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_HLT),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_MMIO),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_IRQ_WINDOW_OPEN),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_SHUTDOWN),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_FAIL_ENTRY),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_INTR),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_SET_TPR),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_TPR_ACCESS),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_S390_SIEIC),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_S390_RESET),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_DCR),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_NMI),
	DEFINE_KVM_EXIT_REASON(KVM_EXIT_INTERNAL_ERROR),
};

#define DEFINE_KVM_EXT(ext)		\
	.name = #ext,			\
	.code = ext

struct {
	const char *name;
	int code;
} kvm_req_ext[] = {
	{ DEFINE_KVM_EXT(KVM_CAP_COALESCED_MMIO) },
	{ DEFINE_KVM_EXT(KVM_CAP_SET_TSS_ADDR) },
	{ DEFINE_KVM_EXT(KVM_CAP_PIT2) },
	{ DEFINE_KVM_EXT(KVM_CAP_USER_MEMORY) },
	{ DEFINE_KVM_EXT(KVM_CAP_IRQ_ROUTING) },
	{ DEFINE_KVM_EXT(KVM_CAP_IRQCHIP) },
	{ DEFINE_KVM_EXT(KVM_CAP_HLT) },
	{ DEFINE_KVM_EXT(KVM_CAP_IRQ_INJECT_STATUS) },
	{ DEFINE_KVM_EXT(KVM_CAP_EXT_CPUID) },
};

extern struct kvm *kvm;
extern struct kvm_cpu *kvm_cpus[KVM_NR_CPUS];
static int pause_event;
static DEFINE_MUTEX(pause_lock);

static char kvm_dir[PATH_MAX];

static void set_dir(const char *fmt, va_list args)
{
	char tmp[PATH_MAX];

	vsnprintf(tmp, sizeof(tmp), fmt, args);

	mkdir(tmp, 0777);

	if (!realpath(tmp, kvm_dir))
		die("Unable to set KVM tool directory");

	strcat(kvm_dir, "/");
}

void kvm__set_dir(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	set_dir(fmt, args);
	va_end(args);
}

const char *kvm__get_dir(void)
{
	return kvm_dir;
}

static bool kvm__supports_extension(struct kvm *kvm, unsigned int extension)
{
	int ret;

	ret = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, extension);
	if (ret < 0)
		return false;

	return ret;
}

static int kvm__check_extensions(struct kvm *kvm)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(kvm_req_ext); i++) {
		if (!kvm__supports_extension(kvm, kvm_req_ext[i].code)) {
			pr_error("Unsuppored KVM extension detected: %s",
				kvm_req_ext[i].name);
			return (int)-i;
		}
	}

	return 0;
}

static struct kvm *kvm__new(void)
{
	struct kvm *kvm = calloc(1, sizeof *kvm);

	if (!kvm)
		die("out of memory");

	return kvm;
}

#if 0
static int kvm__create_socket(struct kvm *kvm)
{
	char full_name[PATH_MAX];
	unsigned int s;
	struct sockaddr_un local;
	int len, r;

	if (!kvm->name)
		return -1;

	sprintf(full_name, "%s", kvm__get_dir());
	mkdir(full_name, 0777);
	sprintf(full_name, "%s/%s.sock", kvm__get_dir(), kvm->name);
	if (access(full_name, F_OK) == 0)
		die("Socket file %s already exist", full_name);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return s;
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, full_name);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	r = bind(s, (struct sockaddr *)&local, len);
	if (r < 0)
		goto fail;

	r = listen(s, 5);
	if (r < 0)
		goto fail;

	return s;

fail:
	close(s);
	return -1;
}
#endif

void kvm__remove_socket(const char *name)
{
	char full_name[PATH_MAX];

	sprintf(full_name, "%s/%s.sock", kvm__get_dir(), name);
	unlink(full_name);
}

int kvm__get_sock_by_instance(const char *name)
{
	int s, len, r;
	char sock_file[PATH_MAX];
	struct sockaddr_un local;

	sprintf(sock_file, "%s/%s.sock", kvm__get_dir(), name);
	s = socket(AF_UNIX, SOCK_STREAM, 0);

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, sock_file);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	r = connect(s, &local, len);
	if (r < 0 && errno == ECONNREFUSED) {
		/* Clean ghost socket file */
		unlink(sock_file);
		return -1;
	} else if (r < 0) {
		die("Failed connecting to instance");
	}

	return s;
}

int kvm__enumerate_instances(int (*callback)(const char *name, int fd))
{
	char full_name[PATH_MAX];
	int sock;
	DIR *dir;
	struct dirent entry, *result;
	int ret = 0;

	sprintf(full_name, "%s", kvm__get_dir());
	dir = opendir(full_name);

	while (dir != NULL) {
		readdir_r(dir, &entry, &result);
		if (result == NULL)
			break;
		if (entry.d_type == DT_SOCK) {
			entry.d_name[strlen(entry.d_name)-5] = 0;
			sock = kvm__get_sock_by_instance(entry.d_name);
			if (sock < 0)
				continue;
			ret = callback(entry.d_name, sock);
			close(sock);
			if (ret < 0)
				break;
		}
	}

	closedir(dir);

	return ret;
}

void kvm__delete(struct kvm *kvm)
{
	kvm__stop_timer(kvm);

	munmap(kvm->ram_start, kvm->ram_size);
	kvm_ipc__stop();
	kvm__remove_socket(kvm->name);
	free(kvm);
}

static bool kvm__cpu_supports_vm(void)
{
	struct cpuid_regs regs;
	u32 eax_base;
	int feature;

	regs	= (struct cpuid_regs) {
		.eax		= 0x00,
	};
	host_cpuid(&regs);

	switch (regs.ebx) {
	case CPUID_VENDOR_INTEL_1:
		eax_base	= 0x00;
		feature		= KVM__X86_FEATURE_VMX;
		break;

	case CPUID_VENDOR_AMD_1:
		eax_base	= 0x80000000;
		feature		= KVM__X86_FEATURE_SVM;
		break;

	default:
		return false;
	}

	regs	= (struct cpuid_regs) {
		.eax		= eax_base,
	};
	host_cpuid(&regs);

	if (regs.eax < eax_base + 0x01)
		return false;

	regs	= (struct cpuid_regs) {
		.eax		= eax_base + 0x01
	};
	host_cpuid(&regs);

	return regs.ecx & (1 << feature);
}

/*
 * Note: KVM_SET_USER_MEMORY_REGION assumes that we don't pass overlapping
 * memory regions to it. Therefore, be careful if you use this function for
 * registering memory regions for emulating hardware.
 */
void kvm__register_mem(struct kvm *kvm, u64 guest_phys, u64 size, void *userspace_addr)
{
	struct kvm_userspace_memory_region mem;
	int ret;

	mem = (struct kvm_userspace_memory_region) {
		.slot			= kvm->mem_slots++,
		.guest_phys_addr	= guest_phys,
		.memory_size		= size,
		.userspace_addr		= (unsigned long)userspace_addr,
	};

	ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
	if (ret < 0)
		die_perror("KVM_SET_USER_MEMORY_REGION ioctl");
}

/*
 * Allocating RAM size bigger than 4GB requires us to leave a gap
 * in the RAM which is used for PCI MMIO, hotplug, and unconfigured
 * devices (see documentation of e820_setup_gap() for details).
 *
 * If we're required to initialize RAM bigger than 4GB, we will create
 * a gap between 0xe0000000 and 0x100000000 in the guest virtual mem space.
 */

void kvm__init_ram(struct kvm *kvm)
{
	u64	phys_start, phys_size;
	void	*host_mem;

	if (kvm->ram_size < KVM_32BIT_GAP_START) {
		/* Use a single block of RAM for 32bit RAM */
                printf("Initializing RAM: Single Block of RAM; Size = %d MB\n", (int) kvm->ram_size/1024/1024);

		phys_start = 0;
		phys_size  = kvm->ram_size;
		host_mem   = kvm->ram_start;

		kvm__register_mem(kvm, phys_start, phys_size, host_mem);
	} else {
		/* First RAM range from zero to the PCI gap: */
                printf("Initializing RAM: Double Block of RAM; Size = %d MB\n", (int) kvm->ram_size/1024/1024);

		phys_start = 0;
		phys_size  = KVM_32BIT_GAP_START;
		host_mem   = kvm->ram_start;

		kvm__register_mem(kvm, phys_start, phys_size, host_mem);

		/* Second RAM range from 4GB to the end of RAM: */

		phys_start = 0x100000000ULL;
		phys_size  = kvm->ram_size - phys_size;
		host_mem   = kvm->ram_start + phys_start;

		kvm__register_mem(kvm, phys_start, phys_size, host_mem);
	}
}

int kvm__recommended_cpus(struct kvm *kvm)
{
	int ret;

	ret = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
	if (ret <= 0)
		die_perror("KVM_CAP_NR_VCPUS");

	return ret;
}

#if 0
static void kvm__pid(int fd, u32 type, u32 len, u8 *msg)
{
	pid_t pid = getpid();
	int r = 0;

	if (type == KVM_IPC_PID)
		r = write(fd, &pid, sizeof(pid));

	if (r < 0)
		pr_warning("Failed sending PID");
}
#endif

/*
 * The following hack should be removed once 'x86: Raise the hard
 * VCPU count limit' makes it's way into the mainline.
 */
#ifndef KVM_CAP_MAX_VCPUS
#define KVM_CAP_MAX_VCPUS 66
#endif

int kvm__max_cpus(struct kvm *kvm)
{
	int ret;

	ret = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS);
	if (ret <= 0)
		ret = kvm__recommended_cpus(kvm);

	return ret;
}

extern pthread_mutex_t kvm_global_mutex;
extern pthread_cond_t kvm_work_cond;

struct kvm *kvm__init(const char *kvm_dev, u64 ram_size, const char *name)
{
	struct kvm_pit_config pit_config = { .flags = KVM_PIT_SPEAKER_DUMMY, };
	struct kvm *kvm;
	int ret;

	if (!kvm__cpu_supports_vm())
		die("Your CPU does not support hardware virtualization");

	kvm = kvm__new();

    KTAILQ_INIT(&kvm->kvm_sw_breakpoints);

	kvm->sys_fd = open(kvm_dev, O_RDWR);
	if (kvm->sys_fd < 0) {
		if (errno == ENOENT)
			die("'%s' not found. Please make sure your kernel has CONFIG_KVM enabled and that the KVM modules are loaded.", kvm_dev);
		if (errno == ENODEV)
			die("'%s' KVM driver not available.\n  # (If the KVM module is loaded then 'dmesg' may offer further clues about the failure.)", kvm_dev);

		fprintf(stderr, "  Fatal, could not open %s: ", kvm_dev);
		perror(NULL);
		exit(1);
	}

	ret = ioctl(kvm->sys_fd, KVM_GET_API_VERSION, 0);
	if (ret != KVM_API_VERSION)
		die_perror("KVM_API_VERSION ioctl");

	kvm->vm_fd = ioctl(kvm->sys_fd, KVM_CREATE_VM, 0);
	if (kvm->vm_fd < 0)
		die_perror("KVM_CREATE_VM ioctl");

	if (kvm__check_extensions(kvm))
		die("A required KVM extention is not supported by OS");

	ret = ioctl(kvm->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);
	if (ret < 0)
		die_perror("KVM_SET_TSS_ADDR ioctl");

	ret = ioctl(kvm->vm_fd, KVM_CREATE_PIT2, &pit_config);
	if (ret < 0)
		die_perror("KVM_CREATE_PIT2 ioctl");

    kvm->vcpu_events = kvm__supports_extension(kvm, KVM_CAP_VCPU_EVENTS);
    if(!kvm->vcpu_events)
        pr_warning("KVM Does Not have VCPU Events");

    kvm->robust_singlestep = kvm__supports_extension(kvm, KVM_CAP_X86_ROBUST_SINGLESTEP);
    if(!kvm->robust_singlestep)
        pr_warning("KVM Does Not have Robust Single Step");

    kvm->debugregs         = kvm__supports_extension(kvm, KVM_CAP_DEBUGREGS);
    if(!kvm->debugregs)
        pr_warning("KVM Does Not support Debug Registers");

	kvm->ram_size		= ram_size;

	if (kvm->ram_size < KVM_32BIT_GAP_START) {
		kvm->ram_start = mmap(NULL, ram_size, PROT_RW, MAP_ANON_NORESERVE, -1, 0);
	} else {
		kvm->ram_start = mmap(NULL, ram_size + KVM_32BIT_GAP_SIZE, PROT_RW, MAP_ANON_NORESERVE, -1, 0);
		if (kvm->ram_start != MAP_FAILED) {
			/*
			 * We mprotect the gap (see kvm__init_ram() for details) PROT_NONE so that
			 * if we accidently write to it, we will know.
			 */
			mprotect(kvm->ram_start + KVM_32BIT_GAP_START, KVM_32BIT_GAP_SIZE, PROT_NONE);
		}
	}
	if (kvm->ram_start == MAP_FAILED)
		die("out of memory");

	madvise(kvm->ram_start, kvm->ram_size, MADV_MERGEABLE);

	ret = ioctl(kvm->vm_fd, KVM_CREATE_IRQCHIP);
	if (ret < 0)
		die_perror("KVM_CREATE_IRQCHIP ioctl");

    kvm->irqchip_in_kernel = true;
	kvm->name = name;

    kvm_cond_init(&kvm_work_cond);
    kvm_mutex_init(&kvm_global_mutex);

	//kvm_ipc__start(kvm__create_socket(kvm));
	//kvm_ipc__register_handler(KVM_IPC_PID, kvm__pid);
	return kvm;
}

#define BOOT_LOADER_SELECTOR	0x0000
#define BOOT_LOADER_IP		0x7C00

#define BOOT_LOADER_SP		0x8000
#define BOOT_CMDLINE_OFFSET	0x20000

#define BOOT_PROTOCOL_REQUIRED	0x206
#define LOAD_HIGH		0x01

static int load_flat_binary(struct kvm *kvm, int fd)
{
	void *p;
	void *q;
	int nr;

	if (lseek(fd, 0, SEEK_SET) < 0)
		die_perror("lseek");

	p = guest_real_to_host(kvm, BOOT_LOADER_SELECTOR, BOOT_LOADER_IP);

	while ((nr = read(fd, p, 65536)) > 0)
    {
        q = host_to_guest_flat(kvm, p);
        printf("%s : Loaded 0x%X bytes at 0x%X (Host 0x%x)\n", __func__, nr, (u32)q, (u32)p);
        p += nr;
    }

	kvm->boot_selector	= BOOT_LOADER_SELECTOR;
	kvm->boot_ip		= BOOT_LOADER_IP;
    //kvm->boot_ip		= BOOT_LOADER_IP + 0x200;
	kvm->boot_sp		= BOOT_LOADER_SP;

	return true;
}

static int load_elf_binary(struct kvm *kvm, int fd)
{
    char *section_copy[] = {(char *) ".reset", (char *) ".init", (char *) ".text", (char *) ".data", (char *) ".rodata",
                            (char *) ".bstext", (char *) ".bsdata", (char *) ".header", (char *) ".entrytext",
                            (char *) ".inittext", (char *) ".initdata", (char *) ".text32", (char *) ".signature",
                            (char *) ".rodata.str1.1", (char *) ".os_config", (char *) ".hal", (char *) ".note", (char *) ""};
    char *section_bss = {(char *) ".bss"};
    Elf32_Ehdr *elf_header = NULL;  /* ELF header */
    Elf *elf = NULL;                /* Our Elf pointer for libelf */
    Elf_Scn *scn = NULL;            /* Section Descriptor */
    GElf_Shdr shdr;                 /* Section Header */
    char *base_ptr;                 // ptr to our object in memory
    struct stat elf_stats;          // fstat struct
    int i;

    void *vm_addr = kvm->ram_start;

    // Move to the beginning of the file.
    if (lseek(fd, 0, SEEK_SET) < 0)
            die_perror("lseek");

    if((fstat(fd, &elf_stats)))
    {
        printf("Could Not fstat\n");
        return false;
    }

    if((u64)elf_stats.st_size > kvm->ram_size){
        printf("%s: ERROR ELF Binary Size Too Big; ram_size = %d, binary_size = %d\n",
               __func__, (int)kvm->ram_size, (int)elf_stats.st_size);
        return false;
    }

    if((base_ptr = (char *) malloc(elf_stats.st_size)) == NULL)
    {
        printf("Could Not malloc\n");
        return false;
    }

    if((i = read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size)
    {
        printf("could not read, bytes read = %d, elf_stats.st_size = %d\n", i, (uint32_t) elf_stats.st_size);

        i = read(fd, base_ptr+i, 4);
        printf("Read More %d bytes\n", i);

        free(base_ptr);
        return false;
    }

    /* Check libelf version first */
    if(elf_version(EV_CURRENT) == EV_NONE)
    {
        printf("WARNING Elf Library is out of date!\n");
    }

    elf_header = (Elf32_Ehdr *) base_ptr;    // point elf_header at our object in memory
    elf = elf_begin(fd, ELF_C_READ, NULL);    // Initialize 'elf' pointer to our file descriptor

    printf("%s  : Loading ELF Binary at vm_addr: 0x%x, Size = %d\n", __func__, (uint32_t)vm_addr, (int)elf_stats.st_size);
    printf("Section Type        Flags\tVirt Addr\tSize (bytes)\tOffset\t           Name\n");
    /* Iterate through section headers */
    while((scn = elf_nextscn(elf, scn)) != 0)
    {
        // point shdr at this section header entry
        gelf_getshdr(scn, &shdr);

        // print the Section Type
        switch(shdr.sh_type)
        {
            case SHT_NULL:              printf("SHT_NULL            ");break;
            case SHT_PROGBITS:          printf("SHT_PROGBITS        ");break;
            case SHT_SYMTAB:            printf("SHT_SYMTAB          ");break;
            case SHT_STRTAB:            printf("SHT_STRTAB          ");break;
            case SHT_RELA:              printf("SHT_RELA            ");break;
            case SHT_HASH:              printf("SHT_HASH            ");break;
            case SHT_DYNAMIC:           printf("SHT_DYNAMIC         ");break;
            case SHT_NOTE:              printf("SHT_NOTE            ");break;
            case SHT_NOBITS:            printf("SHT_NOBITS          ");break;
            case SHT_REL:               printf("SHT_REL             ");break;
            case SHT_SHLIB:             printf("SHT_SHLIB           ");break;
            case SHT_DYNSYM:            printf("SHT_DYNSYM          ");break;
            case SHT_INIT_ARRAY:        printf("SHT_INIT_ARRAY      ");break;
            case SHT_FINI_ARRAY:        printf("SHT_FINI_ARRAY      ");break;
            case SHT_PREINIT_ARRAY:     printf("SHT_PREINIT_ARRAY   ");break;
            case SHT_GROUP:             printf("SHT_GROUP           ");break;
            case SHT_SYMTAB_SHNDX:      printf("SHT_SYMTAB_SHNDX    ");break;
            case SHT_NUM:               printf("SHT_NUM             ");break;
            case SHT_LOOS:              printf("SHT_LOOS            ");break;
            case SHT_GNU_ATTRIBUTES:    printf("SHT_GNU_ATTRIBUTES  ");break;
            case SHT_GNU_HASH:          printf("SHT_GNU_HASH        ");break;
            case SHT_GNU_LIBLIST:       printf("SHT_GNU_LIBLIST     ");break;
            case SHT_CHECKSUM:          printf("SHT_CHECKSUM        ");break;
            case SHT_LOSUNW:            printf("SHT_LOSUNW          ");break;
            case SHT_SUNW_COMDAT:       printf("SHT_SUNW_COMDAT     ");break;
            case SHT_SUNW_syminfo:      printf("SHT_SUNW_syminfo    ");break;
            case SHT_GNU_verdef:        printf("SHT_GNU_verdef      ");break;
            case SHT_GNU_verneed:       printf("SHT_VERNEED         ");break;
            case SHT_GNU_versym:        printf("SHT_GNU_versym      ");break;
            case SHT_LOPROC:            printf("SHT_LOPROC          ");break;
            case SHT_HIPROC:            printf("SHT_HIPROC          ");break;
            case SHT_LOUSER:            printf("SHT_LOUSER          ");break;
            case SHT_HIUSER:            printf("SHT_HIUSER          ");break;
            default:                    printf("(none)              ");break;
        }

        // print the section header Flags
        if(shdr.sh_flags & SHF_WRITE) { printf("W"); }
        if(shdr.sh_flags & SHF_ALLOC) { printf("A"); }
        if(shdr.sh_flags & SHF_EXECINSTR) { printf("X"); }
        if(shdr.sh_flags & SHF_STRINGS) { printf("S"); }
        printf("\t\t");

        // Virt Addr
        printf("0x%08llx\t", (uint64_t)shdr.sh_addr);
        // Size (bytes)
        printf("%lld\t\t", (uint64_t)shdr.sh_size);
        // Offset
        printf("0x%llx\t", (uint64_t)shdr.sh_offset);

        // the shdr Name is in a string table, libelf uses elf_strptr() to find it
        // using the e_shstrndx value from the elf_header
        printf("%15s\t", elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name));

        // Load binary to memory address.
        for(i = 0; strcmp(section_copy[i], "") != 0; i++)
        {
            if(strcmp(section_copy[i], elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name)) == 0)
            {
                u64 n = 0;
                Elf_Data *edata = NULL;         /* Data Descriptor */
                while( (n < shdr.sh_size) && ((edata = elf_getdata(scn, edata)) != NULL))
                {
                    memcpy(vm_addr + shdr.sh_addr + n, edata->d_buf, edata->d_size);
                    n += edata->d_size;
                }
                printf("Loaded ...  %7d Bytes @ 0x%x (KVM: 0x%x)", (u32)n,
                       (uint32_t)(vm_addr + shdr.sh_addr), (uint32_t) shdr.sh_addr);
            }
        }

        if(strcmp(section_bss, elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name)) == 0)
        {
            memset(vm_addr + shdr.sh_addr, 0, shdr.sh_size);
            printf("Initialized %7d Bytes @ 0x%x (KVM: 0x%x)", (int)shdr.sh_size,
                   (uint32_t)(vm_addr + shdr.sh_addr), (uint32_t)(shdr.sh_addr));
        }

        printf("\n");
    }

    free(base_ptr);
    return true;
}

static const char *BZIMAGE_MAGIC	= "HdrS";

static bool load_bzimage(struct kvm *kvm, int fd_kernel,
			int fd_initrd, const char *kernel_cmdline, u16 vidmode)
{
	struct boot_params *kern_boot;
	unsigned long setup_sects;
	struct boot_params boot;
	size_t cmdline_size;
	ssize_t setup_size;
	void *p;
	int nr;

	/*
	 * See Documentation/x86/boot.txt for details no bzImage on-disk and
	 * memory layout.
	 */

	if (lseek(fd_kernel, 0, SEEK_SET) < 0)
		die_perror("lseek");

	if (read(fd_kernel, &boot, sizeof(boot)) != sizeof(boot))
		return false;

	if (memcmp(&boot.hdr.header, BZIMAGE_MAGIC, strlen(BZIMAGE_MAGIC)))
		return false;

	if (boot.hdr.version < BOOT_PROTOCOL_REQUIRED)
		die("Too old kernel");

	if (lseek(fd_kernel, 0, SEEK_SET) < 0)
		die_perror("lseek");

	if (!boot.hdr.setup_sects)
		boot.hdr.setup_sects = BZ_DEFAULT_SETUP_SECTS;
	setup_sects = boot.hdr.setup_sects + 1;

	setup_size = setup_sects << 9;
	p = guest_real_to_host(kvm, BOOT_LOADER_SELECTOR, BOOT_LOADER_IP);

	/* copy setup.bin to mem*/
	if (read(fd_kernel, p, setup_size) != setup_size)
		die_perror("read");

	/* copy vmlinux.bin to BZ_KERNEL_START*/
	p = guest_flat_to_host(kvm, BZ_KERNEL_START);

	while ((nr = read(fd_kernel, p, 65536)) > 0)
		p += nr;

	p = guest_flat_to_host(kvm, BOOT_CMDLINE_OFFSET);
	if (kernel_cmdline) {
		cmdline_size = strlen(kernel_cmdline) + 1;
		if (cmdline_size > boot.hdr.cmdline_size)
			cmdline_size = boot.hdr.cmdline_size;

		memset(p, 0, boot.hdr.cmdline_size);
		memcpy(p, kernel_cmdline, cmdline_size - 1);
	}

	kern_boot	= guest_real_to_host(kvm, BOOT_LOADER_SELECTOR, 0x00);

	kern_boot->hdr.cmd_line_ptr	= BOOT_CMDLINE_OFFSET;
	kern_boot->hdr.type_of_loader	= 0xff;
	kern_boot->hdr.heap_end_ptr	= 0xfe00;
	kern_boot->hdr.loadflags	|= CAN_USE_HEAP;
	kern_boot->hdr.vid_mode		= vidmode;

	/*
	 * Read initrd image into guest memory
	 */
	if (fd_initrd >= 0) {
		struct stat initrd_stat;
		unsigned long addr;

		if (fstat(fd_initrd, &initrd_stat))
			die_perror("fstat");

		addr = boot.hdr.initrd_addr_max & ~0xfffff;
		for (;;) {
			if (addr < BZ_KERNEL_START)
				die("Not enough memory for initrd");
			else if (addr < (kvm->ram_size - initrd_stat.st_size))
				break;
			addr -= 0x100000;
		}

		p = guest_flat_to_host(kvm, addr);
		nr = read(fd_initrd, p, initrd_stat.st_size);
		if (nr != initrd_stat.st_size)
			die("Failed to read initrd");

		kern_boot->hdr.ramdisk_image	= addr;
		kern_boot->hdr.ramdisk_size	= initrd_stat.st_size;
	}

	kvm->boot_selector	= BOOT_LOADER_SELECTOR;
	/*
	 * The real-mode setup code starts at offset 0x200 of a bzImage. See
	 * Documentation/x86/boot.txt for details.
	 */
	kvm->boot_ip		= BOOT_LOADER_IP + 0x200;
	kvm->boot_sp		= BOOT_LOADER_SP;

	return true;
}

/* RFC 1952 */
#define GZIP_ID1		0x1f
#define GZIP_ID2		0x8b

static bool initrd_check(int fd)
{
	unsigned char id[2];

	if (read_in_full(fd, id, ARRAY_SIZE(id)) < 0)
		return false;

	if (lseek(fd, 0, SEEK_SET) < 0)
		die_perror("lseek");

	return id[0] == GZIP_ID1 && id[1] == GZIP_ID2;
}

bool kvm__load_kernel(struct kvm *kvm, const char *kernel_filename,
		const char *initrd_filename, const char *kernel_cmdline, u16 vidmode)
{
	bool ret;
	int fd_kernel = -1, fd_initrd = -1;

	fd_kernel = open(kernel_filename, O_RDONLY);
	if (fd_kernel < 0)
		die("Unable to open kernel %s", kernel_filename);

	if (initrd_filename) {
		fd_initrd = open(initrd_filename, O_RDONLY);
		if (fd_initrd < 0)
			die("Unable to open initrd %s", initrd_filename);

		if (!initrd_check(fd_initrd))
			die("%s is not an initrd", initrd_filename);
	}

	ret = load_bzimage(kvm, fd_kernel, fd_initrd, kernel_cmdline, vidmode);

	if (initrd_filename)
		close(fd_initrd);

	if (ret)
		goto found_kernel;

	pr_warning("%s is not a bzImage. Trying to load it as a flat binary...", kernel_filename);
	ret = load_flat_binary(kvm, fd_kernel);
	if (ret)
        goto found_kernel;

	close(fd_kernel);

	die("%s is not a valid bzImage or flat binary", kernel_filename);

found_kernel:
	close(fd_kernel);

	return ret;
}

bool kvm__load_bootstrap_elf_kernel(struct kvm *kvm,
        const char *kernel_filename, const char *boot_loader)
{
	bool ret;
	int fd_bootstrap = -1, fd_kernel = -1;

    fd_bootstrap = open(boot_loader, O_RDONLY);
	if (fd_bootstrap < 0)
		die("Unable to open bootstrap");

	printf("Loading Bootstrap as a flat binary ... %s\n", boot_loader);
    ret = load_flat_binary(kvm, fd_bootstrap);
    if (!ret){
        close(fd_bootstrap);
        die("Failed in loading bootstrap");
    }

	fd_kernel = open(kernel_filename, O_RDONLY);
	if (fd_kernel < 0)
		die("Unable to open ELF kernel %s", kernel_filename);

	//printf("Loading Kernel as an ELF binary ... %s\n", kernel_filename);
    ret = load_elf_binary(kvm, fd_kernel);

    close(fd_bootstrap);
    close(fd_kernel);
    return ret;
}


/**
 * kvm__setup_bios - inject BIOS into guest system memory
 * @kvm - guest system descriptor
 *
 * This function is a main routine where we poke guest memory
 * and install BIOS there.
 */
void kvm__setup_bios(struct kvm *kvm)
{
	/* standard minimal configuration */
	setup_bios(kvm);

	/* FIXME: SMP, ACPI and friends here */

	/* MP table */
	mptable_setup(kvm, kvm->nrcpus);
}

#define TIMER_INTERVAL_NS 1000000	/* 1 msec */

/*
 * This function sets up a timer that's used to inject interrupts from the
 * userspace hypervisor into the guest at periodical intervals. Please note
 * that clock interrupt, for example, is not handled here.
 */
void kvm__start_timer(struct kvm *kvm)
{
	struct itimerspec its;
	struct sigevent sev;

	memset(&sev, 0, sizeof(struct sigevent));
	sev.sigev_value.sival_int	= 0;
	sev.sigev_notify		= SIGEV_THREAD_ID;
	sev.sigev_signo			= SIGALRM;
	sev._sigev_un._tid		= syscall(__NR_gettid);

	if (timer_create(CLOCK_REALTIME, &sev, &kvm->timerid) < 0)
		die("timer_create()");

	its.it_value.tv_sec		= TIMER_INTERVAL_NS / 1000000000;
	its.it_value.tv_nsec		= TIMER_INTERVAL_NS % 1000000000;
	its.it_interval.tv_sec		= its.it_value.tv_sec;
	its.it_interval.tv_nsec		= its.it_value.tv_nsec;

	if (timer_settime(kvm->timerid, 0, &its, NULL) < 0)
		die("timer_settime()");
}

void kvm__stop_timer(struct kvm *kvm)
{
	if (kvm->timerid)
		if (timer_delete(kvm->timerid) < 0)
			die("timer_delete()");

	kvm->timerid = 0;
}

void kvm__irq_line(struct kvm *kvm, int irq, int level)
{
	struct kvm_irq_level irq_level;

	irq_level	= (struct kvm_irq_level) {
		{
			.irq		= irq,
		},
		.level		= level,
	};

	if (ioctl(kvm->vm_fd, KVM_IRQ_LINE, &irq_level) < 0)
		die_perror("KVM_IRQ_LINE failed");
}

void kvm__irq_trigger(struct kvm *kvm, int irq)
{
	kvm__irq_line(kvm, irq, 1);
	kvm__irq_line(kvm, irq, 0);
}

void kvm__dump_mem(struct kvm *kvm, unsigned long addr, unsigned long size)
{
	unsigned char *p;
	unsigned long n;

	size &= ~7; /* mod 8 */
	if (!size)
		return;

	p = guest_flat_to_host(kvm, addr);

	for (n = 0; n < size; n += 8) {
		if (!host_ptr_in_ram(kvm, p + n))
			break;

		printf("  0x%08lx: %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			addr + n, p[n + 0], p[n + 1], p[n + 2], p[n + 3],
				  p[n + 4], p[n + 5], p[n + 6], p[n + 7]);
	}
}

void kvm__pause(void)
{
	int i, paused_vcpus = 0;

	/* Check if the guest is running */
	if (!kvm_cpus[0] || kvm_cpus[0]->thread == 0)
		return;

	mutex_lock(&pause_lock);

	pause_event = eventfd(0, 0);
	if (pause_event < 0)
		die("Failed creating pause notification event");
	for (i = 0; i < kvm->nrcpus; i++)
		pthread_kill(kvm_cpus[i]->thread, SIGKVMPAUSE);

	while (paused_vcpus < kvm->nrcpus) {
		u64 cur_read;

		if (read(pause_event, &cur_read, sizeof(cur_read)) < 0)
			die("Failed reading pause event");
		paused_vcpus += cur_read;
	}
	close(pause_event);
}

void kvm__continue(void)
{
	/* Check if the guest is running */
	if (!kvm_cpus[0] || kvm_cpus[0]->thread == 0)
		return;

	mutex_unlock(&pause_lock);
}

void kvm__notify_paused(void)
{
	u64 p = 1;

	printf("Inside %s\n", __func__);

	if (write(pause_event, &p, sizeof(p)) < 0)
		die("Failed notifying of paused VCPU.");

	mutex_lock(&pause_lock);
	mutex_unlock(&pause_lock);
}
