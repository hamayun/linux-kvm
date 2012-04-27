#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/*
#include "rabbits/cfg.h"
#include "qemu-common.h"
#include "cpu.h"
#include "rabbits/qemu_encap.h"
*/
#include "include/kvm/kvm.h"
#include "include/kvm/kvm-cpu.h"
#include "gdb_srv.h"

//#define DEBUG_GDB_SRV

typedef struct kvm_cpu CPUState;
#define TARGET_ARCH "x86"
extern __thread struct kvm_cpu *current_kvm_cpu;

enum
{
    GDB_SIGNAL_0 = 0,
    GDB_SIGNAL_INT = 2,
    GDB_SIGNAL_TRAP = 5,
    GDB_SIGNAL_UNKNOWN = 143
};

enum
{
    TARGET_SIGINT = 2,
    TARGET_SIGTRAP = 5
};

enum RSState
{
    RS_IDLE,
    RS_GETLINE,
    RS_CHKSUM1,
    RS_CHKSUM2
};

static int              one_cpu = 0;
static int              saved_c_cpu_index = 0;
static int              write_watchpoint = 0;
static unsigned long    watchpoint_new_value = 0;
static unsigned long    watchpoint_address = 0;

extern struct kvm     * crt_kvm_instance;
extern struct kvm     * kvm_instances[10];
extern int              no_kvm_instances;
//extern unsigned long    get_phys_addr_gdb (unsigned long addr);

/* The GDB remote protocol transfers values in target byte order.  This means
we can use the raw memory access routines to access the value buffer.
Conveniently, these also handle the case where the buffer is mis-aligned.
*/
#define GET_REG8(val) do { \
    stb_p(mem_buf, val); \
    return 1; \
    } while(0)
#define GET_REG16(val) do { \
    stw_p(mem_buf, val); \
    return 2; \
    } while(0)
#define GET_REG32(val) do { \
    stl_p(mem_buf, val); \
    return 4; \
    } while(0)
#define GET_REG64(val) do { \
    stq_p(mem_buf, val); \
    return 8; \
    } while(0)

#if TARGET_LONG_BITS == 64
#define GET_REGL(val) GET_REG64(val)
#define ldtul_p(addr) ldq_p(addr)
#else
#define GET_REGL(val) GET_REG32(val)
#define ldtul_p(addr) ldl_p(addr)
#endif

/*
static int cpu_gdb_read_register(CPUState *env, uint8_t *mem_buf, int n)
{
    return -1;
}
*/

/*
struct kvm_regs {
	// out (KVM_GET_REGS) / in (KVM_SET_REGS)
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};
*/

// TODO: Take the read routines defined in gdbstub.c for x86 registers.
static int cpu_gdb_read_register(CPUState *env, uint8_t *mem_buf, int n)
{
    //memcpy(mem_buf, env->regs->rax, 8);
    return -1;
}

static int cpu_gdb_write_register(CPUState *env, uint8_t *mem_buf, int n)
{
    return -1;
}

static int num_g_regs = NUM_CORE_REGS;

/*
static int gdb_read_register (CPUState *env, uint8_t *mem_buf, int reg)
{
    if (reg < NUM_CORE_REGS)
        return cpu_gdb_read_register (env, mem_buf, reg);

    return 0;
}
*/

static int gdb_read_register (CPUState * current_kvm_cpu, uint8_t * mem_buf, int reg)
{
    if (reg < NUM_CORE_REGS)
        return cpu_gdb_read_register (current_kvm_cpu, mem_buf, reg);

    return 0;
}

static int gdb_write_register (CPUState *env, uint8_t *mem_buf, int reg)
{
    if (reg < NUM_CORE_REGS)
        return cpu_gdb_write_register (env, mem_buf, reg);

    return 0;
}

static inline int fromhex(int v)
{
    if (v >= '0' && v <= '9')
        return v - '0';
    else if (v >= 'A' && v <= 'F')
        return v - 'A' + 10;
    else if (v >= 'a' && v <= 'f')
        return v - 'a' + 10;
    else
        return 0;
}

static inline int tohex(int v)
{
    if (v < 10)
        return v + '0';
    else
        return v - 10 + 'a';
}


static void memtohex (char *buf, const uint8_t *mem, int len)
{
    int                 i, c;
    char                *q;

    q = buf;
    for (i = 0; i < len; i++)
    {
        c = mem[i];
        *q++ = tohex (c >> 4);
        *q++ = tohex (c & 0xf);
    }
    *q = '\0';
}

static void hextomem (uint8_t *mem, const char *buf, int len)
{
    int                 i;

    for (i = 0; i < len; i++)
    {
        mem[i] = (fromhex (buf[0]) << 4) | fromhex (buf[1]);
        buf += 2;
    }
}

static int get_char (struct GDBState *s)
{
    uint8_t             ch;
    int                 ret;

    for(;;)
    {
        ret = recv (s->fd, &ch, 1, 0);
        if (ret < 0)
        {
            if (errno == ECONNRESET)
                s->fd = -1;
            if (errno != EINTR && errno != EAGAIN)
                return -1;
        }
        else
        {
            if (ret == 0)
            {
                close  (s->fd);
                s->fd = -1;
                return -1;
            }

            break;
        }
    }

    return ch;
}

static void put_buffer (struct GDBState *s, const uint8_t *buf, int len)
{
    int         ret;

    while (len > 0)
    {
        ret = send (s->fd, buf, len, 0);
        if (ret < 0)
        {
            if (errno != EINTR && errno != EAGAIN)
            {
                s->running_state = GDB_STATE_DETACH;
                return;
            }
        }
        else
        {
            buf += ret;
            len -= ret;
        }
    }
}

static int put_packet_binary (struct GDBState *s, const char *buf, int len)
{
    int             csum, i;
    uint8_t         *p;

    for (;;)
    {
        p = s->last_packet;
        *(p++) = '$';
        memcpy (p, buf, len);
        p += len;
        csum = 0;
        for(i = 0; i < len; i++)
        {
            csum += buf[i];
        }
        *(p++) = '#';
        *(p++) = tohex ((csum >> 4) & 0xf);
        *(p++) = tohex((csum) & 0xf);

        s->last_packet_len = p - s->last_packet;
        put_buffer (s, (uint8_t *) s->last_packet, s->last_packet_len);

        i = get_char (s);
        if (i < 0)
            return -1;
        if (i == '+')
            break;
    }

    return 0;
}

static int put_packet (struct GDBState *s, const char *buf)
{
    #ifdef DEBUG_GDB_SRV
    printf ("response:%s\n", buf);
    #endif

    return put_packet_binary (s, buf, strlen(buf));
}

static void gdb_srv_accept (struct GDBState *s)
{
    struct sockaddr_in          sa;
    socklen_t                   len;
    int                         fd;

    len = sizeof (sa);
    fd = accept (s->srv_sock_fd, (struct sockaddr *) &sa, &len);
    if (fd < 0 && errno != EINTR)
    {
        perror ("accept");
        return;
    }
    printf ("GDB connected.\n");

    s->fd = fd;
}

static int gdb_srv_open (int port)
{
    struct sockaddr_in      sa;
    int                     fd, ret;

    fd = socket (PF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror ("socket");
        return -1;
    }

    /* allow fast reuse */
    int                   val = 1;
    setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof (val));

    sa.sin_family = AF_INET;
    sa.sin_port = htons (port);
    sa.sin_addr.s_addr = 0;
    ret = bind (fd, (struct sockaddr *) &sa, sizeof (sa));
    if (ret < 0)
    {
        perror("bind");
        return -1;
    }

    ret = listen (fd, 0);
    if (ret < 0)
    {
        perror("listen");
        return -1;
    }

    return fd;
}

static int gdb_breakpoint_insert (unsigned long addr, unsigned long len, int type)
{
    switch (type)
    {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
    {
        int             nb;
        unsigned long   *paddr;

        nb = crt_kvm_instance->m_gdb->breakpoints.nb;
        paddr = crt_kvm_instance->m_gdb->breakpoints.addr;
        paddr[nb] = addr;
        crt_kvm_instance->m_gdb->breakpoints.nb++;

        return 0;
    }

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
    {
        int                     nb;
        struct watch_el_t       *pwatch;

        nb = crt_kvm_instance->m_gdb->watchpoints.nb;
        pwatch = crt_kvm_instance->m_gdb->watchpoints.watch;
        pwatch[nb].begin_address = addr;
        pwatch[nb].end_address = addr + len;
        pwatch[nb].type = type;
        crt_kvm_instance->m_gdb->watchpoints.nb++;
        return 0;
    }

    default:
        return -ENOSYS;
    }
}

static int gdb_breakpoint_remove (unsigned long addr, unsigned long len, int type)
{
    switch (type)
    {
    case GDB_BREAKPOINT_SW:
    case GDB_BREAKPOINT_HW:
    {
        int                 i, nb;
        unsigned long       *paddr;

        nb = crt_kvm_instance->m_gdb->breakpoints.nb;
        paddr = crt_kvm_instance->m_gdb->breakpoints.addr;
        for (i = 0; i < nb; i++)
            if (addr == paddr[i])
                break;
        if (i < nb)
        {
            for ( ;i < nb - 1; i++)
                paddr[i] = paddr[i + 1];
            crt_kvm_instance->m_gdb->breakpoints.nb--;
        }

        return 0;
    }

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
    {
        int                     i, nb;
        struct watch_el_t       *pwatch;

        nb = crt_kvm_instance->m_gdb->watchpoints.nb;
        pwatch = crt_kvm_instance->m_gdb->watchpoints.watch;
        for (i = 0; i < nb; i++)
            if (addr == pwatch[i].begin_address &&
                (addr + len) == pwatch[i].end_address &&
                type == pwatch[i].type)
                break;

        if (i < nb)
        {
            for ( ;i < nb - 1; i++)
                pwatch[i] = pwatch[i + 1];
            crt_kvm_instance->m_gdb->watchpoints.nb--;
        }

        return 0;
    }
    default:
        return -ENOSYS;
    }
}

static void gdb_breakpoint_remove_all (void)
{
    crt_kvm_instance->m_gdb->breakpoints.nb = 0;
    crt_kvm_instance->m_gdb->watchpoints.nb = 0;
}

static void gdb_continue (struct GDBState *s, int running_state)
{
    s->running_state = running_state;
}

static int gdb_handle_packet (struct GDBState *s, const char *line_buf)
{
    const char              *p;
    int                     ch, type, thread, reg_size, len, res;
    char                    buf[GDB_MAX_PACKET_LENGTH];
    uint8_t                 mem_buf[GDB_MAX_PACKET_LENGTH];
    uint8_t                 *registers;
    unsigned long           addr;
    void                    *hw_addr;           // MMH: This is in the SystemC Address-Space

    #ifdef DEBUG_GDB_SRV
    printf ("command='%s'\n", line_buf);
    #endif

    p = line_buf;
    ch = *p++;
    switch(ch)
    {
    case '?': //reason the target halted
        snprintf (buf, sizeof (buf), "T%02xthread:%x;",
            GDB_SIGNAL_TRAP, current_kvm_cpu->cpu_id + 1);
        put_packet (s, buf);
        /* Remove all the breakpoints when this query is issued,
         * because gdb is doing and initial connect and the state
         * should be cleaned up.
         */
        gdb_breakpoint_remove_all ();
        break;

    case 'c': //caddr - continue
        if (*p != '\0')
        {
            addr = strtoull (p, (char **) &p, 16);
        }
        gdb_continue (s, GDB_STATE_CONTINUE);
        break;

    case 'C': // Csig;addr - continue with signal
        gdb_continue (s, GDB_STATE_CONTINUE);
        break;

    case 'D': //D - detach
        gdb_breakpoint_remove_all ();
        gdb_continue (s, GDB_STATE_DETACH);
        put_packet (s, "OK");
        break;

    case 'g': //read registers
        len = 0;
        for (addr = 0; addr < num_g_regs; addr++)
        {
            //reg_size = gdb_read_register (((CPUState **) crt_kvm_instance->m_envs)[s->g_cpu_index],
            //    mem_buf + len, addr);
            reg_size = gdb_read_register (current_kvm_cpu, mem_buf + len, addr);
            len += reg_size;
        }
        memtohex (buf, mem_buf, len);
        put_packet (s, buf);
        break;

    case 'G': //GXX... - write regs
        registers = mem_buf;
        len = strlen(p) / 2;
        hextomem ((uint8_t *) registers, p, len);

        for (addr = 0; addr < num_g_regs && len > 0; addr++)
        {
            //reg_size = gdb_write_register (((CPUState **) crt_kvm_instance->m_envs)[s->g_cpu_index],
            //    registers, addr);
            reg_size = gdb_write_register (current_kvm_cpu, registers, addr);
            len -= reg_size;
            registers += reg_size;
        }
        put_packet(s, "OK");
        break;

    case 'H': //set thread
        type = *p++;
        thread = strtoull (p, (char **) &p, 16);
        if (thread == -1 || thread == 0)
        {
            if (type == 'c')
                s->c_cpu_index = -1;
            put_packet (s, "OK");
            break;
        }

        switch (type)
        {
        case 'c':
            s->c_cpu_index = thread - 1;
            put_packet (s, "OK");
            break;

        case 'g':
            s->g_cpu_index = thread - 1;
            put_packet (s, "OK");
            break;

        default:
             put_packet (s, "E22");
             break;
        }
        break;

    case 'k': //k - kill request
        fprintf (stderr, "\nTerminated via GDB!\n");
        exit (0);

    case 'm': //read memory
        addr = strtoull (p, (char **) &p, 16);

        //addr = get_phys_addr_gdb (addr);   // MMH: We don't need this as the 
                                             //target addresses are already in
                                             // target address-space

        if (*p == ',')
            p++;
        len = strtoull (p, NULL, 16);

        if (write_watchpoint && addr == watchpoint_address)
            hw_addr = &watchpoint_new_value;
        else
            //hw_addr = crt_kvm_instance->m_systemc.systemc_get_mem_addr (current_kvm_cpu->rabbits.sc_obj, addr);
            hw_addr = crt_kvm_instance->ram_start + addr;

        if (hw_addr == NULL)
        {
            put_packet (s, "E14");
            break;
        }

        memcpy (mem_buf, hw_addr, len);

        memtohex (buf, mem_buf, len);
        put_packet (s, buf);

        break;

    case 'M': //write memory
        addr = strtoull (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        len = strtoull (p, (char **) &p, 16);
        if (*p == ':')
            p++;
        hextomem (mem_buf, p, len);

        //hw_addr = crt_kvm_instance->m_systemc.systemc_get_mem_addr (current_kvm_cpu->rabbits.sc_obj, addr);
        hw_addr = crt_kvm_instance->ram_start + addr;

        if (hw_addr == NULL)
        {
            put_packet (s, "E14");
            break;
        }
        memcpy (hw_addr, mem_buf, len);

        put_packet (s, "OK");
        break;

    case 'p': //pn - read reg
        /* Older gdb are really dumb, and don't use 'g' if 'p' is avaialable.
           This works, but can be very slow.  Anything new enough to
           understand XML also knows how to use this properly.  */
        addr = strtoull (p, (char **) &p, 16);

        reg_size = gdb_read_register (current_kvm_cpu, mem_buf, addr);
        if (reg_size)
        {
            memtohex (buf, mem_buf, reg_size);
            put_packet (s, buf);
        }
        else
        {
            put_packet(s, "E14");
        }
        break;

    case 'P': //Pn...=r... - write reg
        addr = strtoull (p, (char **) &p, 16);
        if (*p == '=')
            p++;
        reg_size = strlen(p) / 2;
        hextomem (mem_buf, p, reg_size);
        gdb_write_register (current_kvm_cpu, mem_buf, addr);
        put_packet(s, "OK");
        break;

    case 'q': //general query
    case 'Q':
        if (strcmp(p, "C") == 0)
        {
            sprintf (buf, "QC%x", current_kvm_cpu->cpu_id + 1);
            put_packet (s, buf);
            break;
        }
        else
        if (strncmp(p, "Offsets", 7) == 0)
        {
            snprintf (buf, sizeof(buf), "Text=%x;Data=%x;Bss=%x",
                0x00000000, 0x00000000, 0x00000000);
            put_packet (s, buf);
            break;
        }
        else
        if (strncmp(p, "Supported", 9) == 0)
        {
            snprintf (buf, sizeof (buf), "PacketSize=%x", GDB_MAX_PACKET_LENGTH);
            put_packet (s, buf);
            break;
        }
        else
        if (strcmp (p,"fThreadInfo") == 0)
        {
            s->query_cpu_index = 0;
            goto report_cpuinfo;
        }
        else
        if (strcmp (p,"sThreadInfo") == 0)
        {
            report_cpuinfo:
            if (s->query_cpu_index < crt_kvm_instance->nrcpus)
            {
                snprintf (buf, sizeof (buf), "m%x", s->query_cpu_index + 1);
                put_packet (s, buf);
                s->query_cpu_index++;
            }
            else
                put_packet (s, "l");

            break;
        }
        else
        if (strncmp(p,"ThreadExtraInfo,", 16) == 0)
        {
            thread = strtoull (p + 16, (char **) &p, 16);
            if (thread > crt_kvm_instance->nrcpus)
                put_packet(s, "E14");
            else
            {
                len = snprintf ((char *) mem_buf, sizeof (mem_buf),
                    "CPU %d [%s]", thread,
                    //((CPUState **)crt_kvm_instance->m_envs)[thread - 1]->halted ? "halted " : "running");
                    current_kvm_cpu->paused ? "halted " : "running");
                memtohex (buf, mem_buf, len);
                put_packet (s, buf);
            }
            
            break;
        }
        goto unknown_command;

    case 's': //saddr - step
        
        if (*p != '\0') 
        {
            addr = strtoull (p, (char **) &p, 16);
        }        
        gdb_continue (s, GDB_STATE_STEP);
        break;

    case 'T': //TXX - thread alive
        thread = strtoull (p, (char **) &p, 16);
        if (thread > 0 && thread <= crt_kvm_instance->nrcpus)
             put_packet(s, "OK");
        else
            put_packet(s, "E22");
        break;

    case 'v':
        if (!strncmp (p, "Cont", 4))
        {
            p += 4;
            if (!strcmp (p, "?"))
                put_packet (s, "vCont;c;C;s;S");
            else
            if (*p == ';')
            {
                p++;
                if (*p == 'c')
                {
                    p++;
                    if (*p == ':')
                    {
                        one_cpu = 1;
                        saved_c_cpu_index = s->c_cpu_index;
                        thread = strtoull (p + 1, (char **) &p, 16) - 1;
                        s->c_cpu_index = thread;
                    }

                    gdb_continue (s, GDB_STATE_CONTINUE);
                }
                else
                if (*p == 's')
                {
                    p++;
                    if (*p == ':')
                    {
                        if (write_watchpoint == 1)
                        {
                            put_packet (s, "S05");
                            break;
                        }
                        else
                        {
                            one_cpu = 1;
                            saved_c_cpu_index = s->c_cpu_index;
                            thread = strtoull (p + 1, (char **) &p, 16) - 1;
                            s->c_cpu_index = thread;
                        }
                    }

                    gdb_continue (s, GDB_STATE_STEP);
                }
                else
                goto unknown_command;
            }
        }
        break;

    case 'Z': //zt,addr,length - add break or watchpoint 
    case 'z': //zt,addr,length - remove break or watchpoint 
        type = strtoul (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        addr = strtoull (p, (char **) &p, 16);
        if (*p == ',')
            p++;
        len = strtoull (p, (char **) &p, 16);
        res = 0;
        //if (addr > 0x10020)
        {
            if (ch == 'Z')
                res = gdb_breakpoint_insert (addr, len, type);
            else
                res = gdb_breakpoint_remove (addr, len, type);
        }

        if (res >= 0)
             put_packet(s, "OK");
        else
            if (res == -ENOSYS)
                put_packet(s, "");
            else
                put_packet(s, "E22");
        break;

    default:
    unknown_command:
        /* put empty packet */
        buf[0] = '\0';
        put_packet (s, buf);
        break;
    }

    return RS_IDLE;
}

static void gdb_read_byte (struct GDBState *s, int ch)
{
    int                 i, csum;
    uint8_t             reply;

    switch (s->state)
    {
    case RS_IDLE:
        if (ch == '$')
        {
            s->line_buf_index = 0;
            s->state = RS_GETLINE;
        }
        break;
    case RS_GETLINE:
        if (ch == '#')
        {
            s->state = RS_CHKSUM1;
        }
        else
        {
            if (s->line_buf_index >= sizeof(s->line_buf) - 1)
            {
                s->state = RS_IDLE;
            }
            else
            {
                s->line_buf[s->line_buf_index++] = ch;
            }
        }
        break;
    case RS_CHKSUM1:
        s->line_buf[s->line_buf_index] = '\0';
        s->line_csum = fromhex(ch) << 4;
        s->state = RS_CHKSUM2;
        break;
    case RS_CHKSUM2:
        s->line_csum |= fromhex(ch);
        csum = 0;
        for(i = 0; i < s->line_buf_index; i++)
        {
            csum += s->line_buf[i];
        }
        if (s->line_csum != (csum & 0xff))
        {
            reply = '-';
            put_buffer (s, &reply, 1);
            s->state = RS_IDLE;
        }
        else
        {
            reply = '+';
            put_buffer (s, &reply, 1);
            s->state = gdb_handle_packet (s, s->line_buf);
        }
        break;
    } //switch
}

void gdb_loop (int idx_watch, int bwrite, unsigned long new_val)
{
    char              buf[256], buf1[256];
    int               i, nb;
    struct GDBState   *s = crt_kvm_instance->m_gdb;
    //unsigned char     save_b_use_backdoor = current_kvm_cpu->rabbits.b_use_backdoor;

    //current_kvm_cpu->rabbits.b_use_backdoor = 1;
    write_watchpoint = 0;

    if (s->running_state != GDB_STATE_INIT)
    {
        sprintf (buf, "T%02x", TARGET_SIGTRAP);

        if (idx_watch != -1)
        {
            struct watch_el_t   *pwatch;
            static const char   *watch_names[] = {"watch", "rwatch", "awatch"};

            pwatch = &s->watchpoints.watch[idx_watch];
            sprintf (buf1, "%s:%lx;",
                watch_names[pwatch->type - GDB_WATCHPOINT_WRITE],
                pwatch->begin_address);
            strcat (buf, buf1);

            if (bwrite)
            {
                write_watchpoint = 1;
                watchpoint_new_value = new_val;
                watchpoint_address = pwatch->begin_address;
            }
        }

        sprintf (buf1, "thread:%x;", current_kvm_cpu->cpu_id + 1);
        strcat (buf, buf1);

        put_packet (s, buf);
    }

    if (s->running_state == GDB_STATE_DETACH)
    {
        //current_kvm_cpu->rabbits.b_use_backdoor = save_b_use_backdoor;
        return;
    }

    if (one_cpu)
    {
        one_cpu = 0;
        s->c_cpu_index = saved_c_cpu_index;
    }

    s->g_cpu_index = current_kvm_cpu->cpu_id;
    s->state = RS_IDLE;
    s->running_state = 0;
    while (s->running_state == GDB_STATE_CONTROL)
    {
        nb = read (s->fd, buf, 256);
        if (nb > 0)
        {
            for (i = 0; i < nb; i++)
                gdb_read_byte (s, buf[i]);
        }
        else
        if (nb == 0 || errno != EAGAIN)
        {
            printf ("GDB disconnected!\n");
            s->running_state = GDB_STATE_DETACH;
            break;
        }
    }

    //current_kvm_cpu->rabbits.b_use_backdoor = save_b_use_backdoor;
}

static void close_gdb_sockets (void)
{
    int                 idx;
    for (idx = 0; idx < no_kvm_instances; idx++)
    {
        if (kvm_instances[idx]->m_gdb->fd)
        {
            close (kvm_instances[idx]->m_gdb->fd);
            kvm_instances[idx]->m_gdb->fd = 0;
        }

        if (kvm_instances[idx]->m_gdb->srv_sock_fd)
        {
            close (kvm_instances[idx]->m_gdb->srv_sock_fd);
            kvm_instances[idx]->m_gdb->srv_sock_fd = 0;
        }
    }
}

int gdb_srv_start_and_wait (struct kvm *pinstance, int port)
{
    //printf("Inside gdb_srv_start_and_wait: KVM Instance = 0x%08X, Port = %d\n", pinstance, port);

    pinstance->m_gdb->running_state = GDB_STATE_DETACH;

    pinstance->m_gdb->srv_sock_fd = gdb_srv_open (port);
    if (pinstance->m_gdb->srv_sock_fd < 0)
    {
        printf ("Error: Cannot open port %d in %s\n", port, __FUNCTION__);
        return -1;
    }

    printf ("Waiting for a GDB connection on port %d (arch=%s) ...\n", port, TARGET_ARCH);
    gdb_srv_accept (pinstance->m_gdb);

    pinstance->m_gdb->running_state = GDB_STATE_INIT;
    pinstance->m_gdb->c_cpu_index = -1;
    atexit (close_gdb_sockets);

    return 0;
}

int gdb_start_debug (void)
{
    int                 idx, bstart = 0;
    for (idx = 0; idx < no_kvm_instances; idx++)
    {
        if (kvm_instances[idx]->m_gdb->running_state != GDB_STATE_DETACH)
        {
            kvm_instances[idx]->m_gdb->running_state = GDB_STATE_STEP;
            bstart = 1;
        }
    }
    return bstart;
}

int gdb_condition (target_ulong addr)
{
    int                 gdbrs = crt_kvm_instance->m_gdb->running_state;
    int                 gdbcpu = crt_kvm_instance->m_gdb->c_cpu_index;
    int                 i, nb;
    unsigned long       *paddr;
    
    if (gdbrs == GDB_STATE_DETACH)
        return 0;

    if (current_kvm_cpu->cpu_id != gdbcpu && gdbcpu != - 1)
        return 0;

    if (gdbrs == GDB_STATE_STEP || gdbrs == GDB_STATE_INIT)
        return 1;

    nb = crt_kvm_instance->m_gdb->breakpoints.nb;
    paddr = crt_kvm_instance->m_gdb->breakpoints.addr;
    for (i = 0; i < nb; i++)
        if (addr == paddr[i])
            return 1;

    return 0;
}

void gdb_server_init (struct kvm * pinstance)
{
    pinstance->m_gdb = malloc(sizeof (struct GDBState));
    memset (pinstance->m_gdb, 0, sizeof (struct GDBState));
    pinstance->m_gdb->running_state = GDB_STATE_DETACH;

    printf("GDB Server Initialized; KVM Instance = 0x%08X\n", pinstance);
}
