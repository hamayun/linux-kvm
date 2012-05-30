/*
 * gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "include/kvm/kvm.h"
#include "include/kvm/kvm-cpu.h"
#include "include/kvm/util.h"

#include "gdb_srv.h"
#include "gdb_srv_arch.h"

#define DEBUG_GDB_SRV

#define TARGET_ARCH "x86"
extern __thread struct kvm_cpu *current_kvm_cpu;

static inline int target_memory_rw_debug(CPUState *env, target_ulong addr,
                                         uint8_t *buf, int len, int is_write)
{
    return kvm_arch_memory_rw_debug(env, addr, buf, len, is_write);
}

enum {
    GDB_SIGNAL_0 = 0,
    GDB_SIGNAL_INT = 2,
    GDB_SIGNAL_TRAP = 5,
    GDB_SIGNAL_UNKNOWN = 143
};

enum {
    TARGET_SIGINT = 2,
    TARGET_SIGTRAP = 5
};

static int gdb_signal_table[] = {
    -1,
    -1,
    TARGET_SIGINT,
    -1,
    -1,
    TARGET_SIGTRAP
};

static int gdb_signal_to_target (int sig)
{
    if (sig < (int) ARRAY_SIZE (gdb_signal_table))
        return gdb_signal_table[sig];
    else
        return -1;
}

enum RSState {
    RS_IDLE,
    RS_GETLINE,
    RS_CHKSUM1,
    RS_CHKSUM2
};

/* By default use no IRQs and no timers while single stepping so as to
 * make single stepping like an ICE HW step.
 */
static int sstep_flags = SSTEP_ENABLE|SSTEP_NOIRQ|SSTEP_NOTIMER;

//static int              one_cpu = 0;
//static int              saved_c_cpu_index = 0;
//static int              write_watchpoint = 0;
//static unsigned long    watchpoint_new_value = 0;
//static unsigned long    watchpoint_address = 0;

extern struct kvm     * kvm_instances[10];
extern int              no_kvm_instances;

/* Number of registers.  */
#define NUMREGS        16

/* Number of bytes of registers.  */
#define NUMREGBYTES (NUMREGS * 4)

enum regnames {EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
               PC /* also known as eip */,
               PS /* also known as eflags */,
               CS, SS, DS, ES, FS, GS};

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
    for(i = 0; i < len; i++){
        c = mem[i];
        *q++ = tohex (c >> 4);
        *q++ = tohex (c & 0xf);
    }
    *q = '\0';
}

static void hextomem (uint8_t *mem, const char *buf, int len)
{
    int                 i;

    for(i = 0; i < len; i++){
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

/* return -1 if error, 0 if OK */
static int put_packet_binary(GDBState *s, const char *buf, int len)
{
    int             csum, i;
    uint8_t         *p;

    for(;;){
        p = s->last_packet;
        *(p++) = '$';
        memcpy (p, buf, len);
        p += len;
        csum = 0;
        for(i = 0; i < len; i++){
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

/* return -1 if error, 0 if OK */
static int put_packet(GDBState *s, const char *buf)
{
    #ifdef DEBUG_GDB_SRV
    printf("reply='%s'\n", buf);
    #endif

    return put_packet_binary (s, buf, strlen(buf));
}

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


#ifdef TARGET_X86_64
static const int gpr_map[16] = {
    R_EAX, R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP, R_ESP,
    8, 9, 10, 11, 12, 13, 14, 15
};
#else
#define gpr_map gpr_map32
#endif
static const int gpr_map32[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

#define IDX_IP_REG      CPU_NB_REGS
#define IDX_FLAGS_REG   (IDX_IP_REG + 1)
#define IDX_SEG_REGS    (IDX_FLAGS_REG + 1)
#define IDX_FP_REGS     (IDX_SEG_REGS + 6)
#define IDX_XMM_REGS    (IDX_FP_REGS + 16)
#define IDX_MXCSR_REG   (IDX_XMM_REGS + CPU_NB_REGS)

#if 1

static int num_g_regs = NUM_CORE_REGS;

static int cpu_gdb_read_register(CPUState *env, uint8_t *mem_buf, int n)
{
    struct kvm_regs  *regs = &env->regs;
    struct kvm_sregs *sregs = &env->sregs;
    uint32_t reg_val = 0;

    switch(n)
    {
        case EAX: reg_val = (uint32_t) regs->rax;           break;
        case ECX: reg_val = (uint32_t) regs->rcx;           break;
        case EDX: reg_val = (uint32_t) regs->rdx;           break;
        case EBX: reg_val = (uint32_t) regs->rbx;           break;
        case ESP: reg_val = (uint32_t) regs->rsp;           break;
        case EBP: reg_val = (uint32_t) regs->rbp;           break;
        case ESI: reg_val = (uint32_t) regs->rsi;           break;
        case EDI: reg_val = (uint32_t) regs->rdi;           break;
        case  PC: reg_val = (uint32_t) regs->rip;           break;
        case  PS: reg_val = (uint32_t) regs->rflags;        break;
        case  CS: reg_val = (uint32_t) sregs->cs.selector;  break;
        case  SS: reg_val = (uint32_t) sregs->ss.selector;  break;
        case  DS: reg_val = (uint32_t) sregs->ds.selector;  break;
        case  ES: reg_val = (uint32_t) sregs->es.selector;  break;
        case  FS: reg_val = (uint32_t) sregs->fs.selector;  break;
        case  GS: reg_val = (uint32_t) sregs->gs.selector;  break;
        default:
            printf("Error: Unknown Registers\n");
            return (-1);
    }

    GET_REG32(reg_val);     /* This returns size as well; uses mem_buf internally */

    return 0;  /* Zero means no register was read */
}

static int cpu_gdb_write_register(CPUState *env, uint8_t *mem_buf, int n)
{
    // TODO:
    return 0;
}

static int gdb_read_register (CPUState *env, uint8_t * mem_buf, int reg)
{
    //if (reg < NUMREGS)
        return cpu_gdb_read_register (env, mem_buf, reg);

    return 0;
}

static int gdb_write_register (CPUState *env, uint8_t *mem_buf, int reg)
{
    //if (reg < NUMREGS)
        return cpu_gdb_write_register (env, mem_buf, reg);

    return 0;
}
#else
static int cpu_gdb_read_register(CPUState *env, uint8_t *mem_buf, int n)
{
    if (n < CPU_NB_REGS) {
        if (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK) {
            GET_REG64(env->regs[gpr_map[n]]);
        } else if (n < CPU_NB_REGS32) {
            GET_REG32(env->regs[gpr_map32[n]]);
        }
    } else if (n >= IDX_FP_REGS && n < IDX_FP_REGS + 8) {
#ifdef USE_X86LDOUBLE
        /* FIXME: byteswap float values - after fixing fpregs layout. */
        memcpy(mem_buf, &env->fpregs[n - IDX_FP_REGS], 10);
#else
        memset(mem_buf, 0, 10);
#endif
        return 10;
    } else if (n >= IDX_XMM_REGS && n < IDX_XMM_REGS + CPU_NB_REGS) {
        n -= IDX_XMM_REGS;
        if (n < CPU_NB_REGS32 ||
            (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK)) {
            stq_p(mem_buf, env->xmm_regs[n].XMM_Q(0));
            stq_p(mem_buf + 8, env->xmm_regs[n].XMM_Q(1));
            return 16;
        }
    } else {
        switch (n) {
        case IDX_IP_REG:
            if (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK) {
                GET_REG64(env->eip);
            } else {
                GET_REG32(env->eip);
            }
        case IDX_FLAGS_REG: GET_REG32(env->eflags);

        case IDX_SEG_REGS:     GET_REG32(env->segs[R_CS].selector);
        case IDX_SEG_REGS + 1: GET_REG32(env->segs[R_SS].selector);
        case IDX_SEG_REGS + 2: GET_REG32(env->segs[R_DS].selector);
        case IDX_SEG_REGS + 3: GET_REG32(env->segs[R_ES].selector);
        case IDX_SEG_REGS + 4: GET_REG32(env->segs[R_FS].selector);
        case IDX_SEG_REGS + 5: GET_REG32(env->segs[R_GS].selector);

        case IDX_FP_REGS + 8:  GET_REG32(env->fpuc);
        case IDX_FP_REGS + 9:  GET_REG32((env->fpus & ~0x3800) |
                                         (env->fpstt & 0x7) << 11);
        case IDX_FP_REGS + 10: GET_REG32(0); /* ftag */
        case IDX_FP_REGS + 11: GET_REG32(0); /* fiseg */
        case IDX_FP_REGS + 12: GET_REG32(0); /* fioff */
        case IDX_FP_REGS + 13: GET_REG32(0); /* foseg */
        case IDX_FP_REGS + 14: GET_REG32(0); /* fooff */
        case IDX_FP_REGS + 15: GET_REG32(0); /* fop */

        case IDX_MXCSR_REG: GET_REG32(env->mxcsr);
        }
    }
    return 0;
}

static int cpu_x86_gdb_load_seg(CPUState *env, int sreg, uint8_t *mem_buf)
{
    uint16_t selector = ldl_p(mem_buf);

    if (selector != env->segs[sreg].selector) {
        unsigned int limit, flags;
        target_ulong base;

        if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)) {
            base = selector << 4;
            limit = 0xffff;
            flags = 0;
        } else {
            if (!cpu_x86_get_descr_debug(env, selector, &base, &limit, &flags))
                return 4;
        }
        cpu_x86_load_seg_cache(env, sreg, selector, base, limit, flags);
    }
    return 4;
}

static int cpu_gdb_write_register(CPUState *env, uint8_t *mem_buf, int n)
{
    uint32_t tmp;

    if (n < CPU_NB_REGS) {
        if (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK) {
            env->regs[gpr_map[n]] = ldtul_p(mem_buf);
            return sizeof(target_ulong);
        } else if (n < CPU_NB_REGS32) {
            n = gpr_map32[n];
            env->regs[n] &= ~0xffffffffUL;
            env->regs[n] |= (uint32_t)ldl_p(mem_buf);
            return 4;
        }
    } else if (n >= IDX_FP_REGS && n < IDX_FP_REGS + 8) {
#ifdef USE_X86LDOUBLE
        /* FIXME: byteswap float values - after fixing fpregs layout. */
        memcpy(&env->fpregs[n - IDX_FP_REGS], mem_buf, 10);
#endif
        return 10;
    } else if (n >= IDX_XMM_REGS && n < IDX_XMM_REGS + CPU_NB_REGS) {
        n -= IDX_XMM_REGS;
        if (n < CPU_NB_REGS32 ||
            (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK)) {
            env->xmm_regs[n].XMM_Q(0) = ldq_p(mem_buf);
            env->xmm_regs[n].XMM_Q(1) = ldq_p(mem_buf + 8);
            return 16;
        }
    } else {
        switch (n) {
        case IDX_IP_REG:
            if (TARGET_LONG_BITS == 64 && env->hflags & HF_CS64_MASK) {
                env->eip = ldq_p(mem_buf);
                return 8;
            } else {
                env->eip &= ~0xffffffffUL;
                env->eip |= (uint32_t)ldl_p(mem_buf);
                return 4;
            }
        case IDX_FLAGS_REG:
            env->eflags = ldl_p(mem_buf);
            return 4;

        case IDX_SEG_REGS:     return cpu_x86_gdb_load_seg(env, R_CS, mem_buf);
        case IDX_SEG_REGS + 1: return cpu_x86_gdb_load_seg(env, R_SS, mem_buf);
        case IDX_SEG_REGS + 2: return cpu_x86_gdb_load_seg(env, R_DS, mem_buf);
        case IDX_SEG_REGS + 3: return cpu_x86_gdb_load_seg(env, R_ES, mem_buf);
        case IDX_SEG_REGS + 4: return cpu_x86_gdb_load_seg(env, R_FS, mem_buf);
        case IDX_SEG_REGS + 5: return cpu_x86_gdb_load_seg(env, R_GS, mem_buf);

        case IDX_FP_REGS + 8:
            env->fpuc = ldl_p(mem_buf);
            return 4;
        case IDX_FP_REGS + 9:
            tmp = ldl_p(mem_buf);
            env->fpstt = (tmp >> 11) & 7;
            env->fpus = tmp & ~0x3800;
            return 4;
        case IDX_FP_REGS + 10: /* ftag */  return 4;
        case IDX_FP_REGS + 11: /* fiseg */ return 4;
        case IDX_FP_REGS + 12: /* fioff */ return 4;
        case IDX_FP_REGS + 13: /* foseg */ return 4;
        case IDX_FP_REGS + 14: /* fooff */ return 4;
        case IDX_FP_REGS + 15: /* fop */   return 4;

        case IDX_MXCSR_REG:
            env->mxcsr = ldl_p(mem_buf);
            return 4;
        }
    }
    /* Unrecognised register.  */
    return 0;
}

static int num_g_regs = NUM_CORE_REGS;

static int gdb_read_register(CPUState *env, uint8_t *mem_buf, int reg)
{
    GDBRegisterState *r;

    if (reg < NUM_CORE_REGS)
        return cpu_gdb_read_register(env, mem_buf, reg);

    for (r = env->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->get_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}

static int gdb_write_register(CPUState *env, uint8_t *mem_buf, int reg)
{
    GDBRegisterState *r;

    if (reg < NUM_CORE_REGS)
        return cpu_gdb_write_register(env, mem_buf, reg);

    for (r = env->gdb_regs; r; r = r->next) {
        if (r->base_reg <= reg && reg < r->base_reg + r->num_regs) {
            return r->set_reg(env, mem_buf, reg - r->base_reg);
        }
    }
    return 0;
}
#endif

static int gdb_breakpoint_insert(target_ulong addr, target_ulong len, int type, CPUState *env)
{
    return kvm_insert_breakpoint(env, addr, len, type);
}

static int gdb_breakpoint_remove(target_ulong addr, target_ulong len, int type, CPUState *env)
{
    return kvm_remove_breakpoint(env, addr, len, type);
}

static void gdb_breakpoint_remove_all (CPUState *env)
{
    kvm_remove_all_breakpoints(env);
}

static void gdb_set_cpu_pc(GDBState *s, target_ulong pc)
{
    cpu_synchronize_state(s->c_cpu);
    s->c_cpu->regs.rip = pc;
}

static inline int gdb_id(CPUState *env)
{
    return env->cpu_id + 1;
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

    printf ("GDB connected. (%d --> %d)\n", s->fd, fd);

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

/*
static int cpu_is_stopped(CPUState *env)
{
    return (!env->is_running);
}
*/

struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(CPUState *env, target_ulong pc)
{
    struct kvm_sw_breakpoint *bp;

    QTAILQ_FOREACH(bp, &env->kvm->kvm_sw_breakpoints, entry) {
        if (bp->pc == pc) {
            return bp;
        }
    }
    return NULL;
}

int kvm_sw_breakpoints_active(CPUState *env)
{
    return !QTAILQ_EMPTY(&env->kvm->kvm_sw_breakpoints);
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    CPUState *env;
    int err;
};

/*
static void kvm_invoke_set_guest_debug(void *data)
{
    struct kvm_set_guest_debug_data *dbg_data = data;
    CPUState *env = dbg_data->env;

    dbg_data->err = ioctl(env->vcpu_fd, KVM_SET_GUEST_DEBUG, &dbg_data->dbg);
}*/

int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap)
{
    struct kvm_set_guest_debug_data data;

    data.dbg.control = reinject_trap;

    if (env->kvm->enable_singlestep) {
        data.dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
    }

    kvm_arch_update_guest_debug(env, &data.dbg);
    data.env = env;

    //run_on_cpu(env, kvm_invoke_set_guest_debug, &data);

    data.err = ioctl(env->vcpu_fd, KVM_SET_GUEST_DEBUG, &data.dbg);

    return data.err;
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
static void cpu_single_step(CPUState *env, int enabled)
{
    if (env->kvm->enable_singlestep != enabled)
    {
        env->kvm->enable_singlestep = enabled;
        kvm_update_guest_debug(env, 0);
    }
}

static void gdb_continue (struct GDBState *s, int running_state)
{
    s->running_state = running_state;
}

static CPUState *find_cpu(struct GDBState *s, int thread_id)
{
    CPUState *env;

    for (env = s->p_kvm->first_cpu; env != NULL; env = env->next_cpu) {
        if (gdb_id(env) == thread_id) {
            return env;
        }
    }

    return NULL;
}

static int gdb_handle_packet (struct GDBState *s, const char *line_buf)
{
    CPUState               *env;
    const char             *p;
    int                     ch, type, thread, reg_size, len, res;
    char                    buf[GDB_MAX_PACKET_LENGTH];
    uint8_t                 mem_buf[GDB_MAX_PACKET_LENGTH];
    uint8_t                 *registers;
    int                     addr;

    #ifdef DEBUG_GDB_SRV
    printf("command='%s'\n", line_buf);
    #endif

    p = line_buf;
    ch = *p++;
    switch(ch)
    {
    //reason the target halted
    case '?':
        /* TODO: Make this return the correct value for user-mode.  */
        snprintf(buf, sizeof(buf), "T%02xthread:%02x;", GDB_SIGNAL_TRAP,
                 gdb_id(s->c_cpu));
        put_packet(s, buf);
        /* Remove all the breakpoints when this query is issued,
         * because gdb is doing and initial connect and the state
         * should be cleaned up.
         */
        gdb_breakpoint_remove_all (s->c_cpu);
        break;

    //caddr - continue
    case 'c':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            gdb_set_cpu_pc(s, addr);
        }
        s->signal = 0;
        gdb_continue (s, GDB_STATE_CONTINUE);
	    return RS_IDLE;

    // Csig;addr - continue with signal
    case 'C':
        s->signal = gdb_signal_to_target (strtoul(p, (char **)&p, 16));
        if (s->signal == -1)
            s->signal = 0;
        gdb_continue (s, GDB_STATE_CONTINUE);
        return RS_IDLE;

    case 'v':
       if (strncmp(p, "Cont", 4) == 0) {
            int res_signal, res_thread;

            p += 4;
            if (*p == '?') {
                put_packet(s, "vCont;c;C;s;S");
                break;
            }
            res = 0;
            res_signal = 0;
            res_thread = 0;
            while (*p) {
                int action, signal;

                if (*p++ != ';') {
                    res = 0;
                    break;
                }
                action = *p++;
                signal = 0;
                if (action == 'C' || action == 'S') {
                    signal = strtoul(p, (char **)&p, 16);
                } else if (action != 'c' && action != 's') {
                    res = 0;
                    break;
                }
                thread = 0;
                if (*p == ':') {
                    thread = strtoull(p+1, (char **)&p, 16);
                }
                action = tolower(action);
                if (res == 0 || (res == 'c' && action == 's')) {
                    res = action;
                    res_signal = signal;
                    res_thread = thread;
                }
            }
            if (res) {
                if (res_thread != -1 && res_thread != 0) {
                    env = find_cpu(s, res_thread);
                    if (env == NULL) {
                        put_packet(s, "E22");
                        break;
                    }
                    s->c_cpu = env;
                }
                if (res == 's') {
                    cpu_single_step(s->c_cpu, sstep_flags);
                }
                s->signal = res_signal;
                gdb_continue(s, GDB_STATE_STEP);
                return RS_IDLE;
            }
            break;
        } else {
            goto unknown_command;
        }

/*
        if (strncmp(p, "Cont", 4) == 0) {
            p += 4;
            if (!strcmp (p, "?"))
                put_packet (s, "vCont;c;C;s;S");
            else
            if (*p == ';'){
                p++;
                if (*p == 'c'){
                    p++;
                    if (*p == ':'){
                        one_cpu = 1;
                        saved_c_cpu_index = s->c_cpu_index;
                        thread = strtoull (p + 1, (char **) &p, 16) - 1;
                        s->c_cpu_index = thread;
                    }

                    gdb_continue (s, GDB_STATE_CONTINUE);
                } else if (*p == 's') {
                    p++;
                    if (*p == ':') {
                        if (write_watchpoint == 1)
                        {
                            put_packet (s, "S05");
                            break;
                        } else {
                            one_cpu = 1;
                            saved_c_cpu_index = s->c_cpu_index;
                            thread = strtoull (p + 1, (char **) &p, 16) - 1;
                            s->c_cpu_index = thread;
                        }
                    }

                    gdb_continue (s, GDB_STATE_STEP);
                } else {
                    goto unknown_command;
                }
            }
        }
        break;
*/
    case 'k':
        /* Kill the target */
        fprintf(stderr, "\nKVM: Terminated via GDBstub\n");
        exit(0);

    //D - detach
    case 'D':
        /* Detach packet */
        gdb_breakpoint_remove_all (s->c_cpu);
        gdb_continue (s, GDB_STATE_DETACH);
        put_packet(s, "OK");
        break;

    //saddr - step
    case 's':
        if (*p != '\0') {
            addr = strtoull(p, (char **)&p, 16);
            gdb_set_cpu_pc(s, addr);
        }
        cpu_single_step(s->c_cpu, sstep_flags);
        gdb_continue (s, GDB_STATE_STEP);
	return RS_IDLE;

    //read registers
    case 'g':
        cpu_synchronize_state(s->g_cpu);
        env = s->g_cpu;
        len = 0;
        for (addr = 0; addr < num_g_regs; addr++) {
            reg_size = gdb_read_register(s->g_cpu, mem_buf + len, addr);
            len += reg_size;
        }
        memtohex(buf, mem_buf, len);
        put_packet(s, buf);
        break;

    //GXX... - write regs
    case 'G':
        cpu_synchronize_state(s->g_cpu);
        env = s->g_cpu;
        registers = mem_buf;
        len = strlen(p) / 2;
        hextomem((uint8_t *)registers, p, len);
        for (addr = 0; addr < num_g_regs && len > 0; addr++) {
            reg_size = gdb_write_register(s->g_cpu, registers, addr);
            len -= reg_size;
            registers += reg_size;
        }
        put_packet(s, "OK");
        break;

    //read memory
    case 'm':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, NULL, 16);
        if (target_memory_rw_debug(s->g_cpu, addr, mem_buf, len, 0) != 0) {
            put_packet (s, "E14");
        } else {
            memtohex(buf, mem_buf, len);
            put_packet(s, buf);
        }
        break;

    //write memory
    case 'M':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (*p == ':')
            p++;
        hextomem(mem_buf, p, len);
        if (target_memory_rw_debug(s->g_cpu, addr, mem_buf, len, 1) != 0) {
            put_packet(s, "E14");
        } else {
            put_packet(s, "OK");
        }
        break;

    //pn - read reg
    case 'p':
        /* Older gdb are really dumb, and don't use 'g' if 'p' is avaialable.
           This works, but can be very slow.  Anything new enough to
           understand XML also knows how to use this properly.  */
        addr = strtoull (p, (char **) &p, 16);
        reg_size = gdb_read_register (s->g_cpu, mem_buf, addr);

        if (reg_size){
            memtohex (buf, mem_buf, reg_size);
            put_packet (s, buf);
        }else{
            put_packet(s, "E14");
        }
        break;

    //Pn...=r... - write reg
   case 'P':
        addr = strtoull(p, (char **)&p, 16);
        if (*p == '=')
            p++;
        reg_size = strlen(p) / 2;

        hextomem(mem_buf, p, reg_size);
        gdb_write_register(s->g_cpu, mem_buf, addr);
        put_packet(s, "OK");
        break;

    //zt,addr,length - add break or watchpoint
    //zt,addr,length - remove break or watchpoint
    case 'Z':
    case 'z':
        type = strtoul(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        addr = strtoull(p, (char **)&p, 16);
        if (*p == ',')
            p++;
        len = strtoull(p, (char **)&p, 16);
        if (ch == 'Z')
            res = gdb_breakpoint_insert(addr, len, type, s->g_cpu);
        else
            res = gdb_breakpoint_remove(addr, len, type, s->g_cpu);
        if (res >= 0)
             put_packet(s, "OK");
        else if (res == -ENOSYS)
            put_packet(s, "");
        else
            put_packet(s, "E22");
        break;

    // set thread
    case 'H':
        type = *p++;
        thread = strtoull(p, (char **)&p, 16);
        printf("GDB Set Thread ... %d\n", thread);
        if (thread == -1 || thread == 0) {
            put_packet(s, "OK");
            break;
        }
        env = find_cpu(s, thread);
        if (env == NULL) {
            put_packet(s, "E22");
            break;
        }
        switch (type) {
        case 'c':
            s->c_cpu = env;
            put_packet(s, "OK");
            break;
        case 'g':
            s->g_cpu = env;
            put_packet(s, "OK");
            break;
        default:
             put_packet(s, "E22");
             break;
        }
        break;

    //TXX - thread alive
    case 'T':
        thread = strtoull (p, (char **) &p, 16);
        env = find_cpu(s, thread);
        if (env != NULL) {
            put_packet(s, "OK");
        } else {
            put_packet(s, "E22");
        }
        break;

    //general query
    case 'q':
    case 'Q':
        if (strcmp(p,"C") == 0) {
            /* "Current thread" remains vague in the spec, so always return
             *  the first CPU (gdb returns the first thread). */
            put_packet(s, "QC1");
            break;
        } else if (strcmp(p,"fThreadInfo") == 0) {
            s->query_cpu = s->p_kvm->first_cpu;
            goto report_cpuinfo;
        } else if (strcmp(p,"sThreadInfo") == 0) {
            report_cpuinfo:
            if (s->query_cpu) {
                snprintf(buf, sizeof(buf), "m%x", gdb_id(s->query_cpu));
                put_packet(s, buf);
                s->query_cpu = s->query_cpu->next_cpu;
            } else
                put_packet(s, "l");
            break;
        } else if (strncmp(p,"ThreadExtraInfo,", 16) == 0) {
            thread = strtoull(p+16, (char **)&p, 16);
            env = find_cpu(s, thread);
            if (env != NULL) {
                cpu_synchronize_state(env);
                len = snprintf((char *)mem_buf, sizeof(mem_buf),
                               "CPU#%ld [%s]", env->cpu_id,
                               env->paused ? "halted " : "running");
                memtohex(buf, mem_buf, len);
                put_packet(s, buf);
            }
            break;
        }
        else if (strncmp(p, "Offsets", 7) == 0) {
            // TODO: Send the Actual Addresses
            snprintf (buf, sizeof(buf), "Text=%x;Data=%x;Bss=%x", 0x00000000, 0x00000000, 0x00000000);
            put_packet(s, buf);
            break;
        }
        else if (strncmp(p, "Supported", 9) == 0) {
            snprintf(buf, sizeof(buf), "PacketSize=%x", GDB_MAX_PACKET_LENGTH);
            put_packet(s, buf);
            break;
        }
        /* Unrecognised 'q' command.  */
        goto unknown_command;

    default:
    unknown_command:
        /* put empty packet */
        buf[0] = '\0';
        put_packet (s, buf);
        break;
    }

    return RS_IDLE;
}

static void gdb_read_byte(GDBState *s, int ch)
{
    int                 i, csum;
    uint8_t             reply;

    switch (s->state){
    case RS_IDLE:
        if (ch == '$'){
            s->line_buf_index = 0;
            s->state = RS_GETLINE;
        }
        break;
    case RS_GETLINE:
        if (ch == '#'){
            s->state = RS_CHKSUM1;
        } else if (s->line_buf_index >= (int)(sizeof(s->line_buf) - 1)) {
            s->state = RS_IDLE;
        } else {
            s->line_buf[s->line_buf_index++] = ch;
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
        for(i = 0; i < s->line_buf_index; i++) {
            csum += s->line_buf[i];
        }
        if (s->line_csum != (csum & 0xff)) {
            reply = '-';
            put_buffer (s, &reply, 1);
            s->state = RS_IDLE;
        } else {
            reply = '+';
            put_buffer (s, &reply, 1);
            s->state = gdb_handle_packet (s, s->line_buf);
        }
        break;
    }
}

#if 1
//static void gdb_loop(int idx_watch, int bwrite, unsigned long new_val)
void gdb_handle_debug(CPUState * env)
{
    char              buf[256], buf1[256];
    int               i, nb;
    struct GDBState   *s = env->kvm->m_gdb;

    if (s->running_state != GDB_STATE_INIT)
    {
        sprintf (buf, "T%02x", TARGET_SIGTRAP);
        sprintf (buf1, "thread:%x;", ((uint32_t) env->cpu_id) + 1);
        strcat (buf, buf1);
        put_packet (s, buf);
    }

    if (s->running_state == GDB_STATE_DETACH)
    {
        return;
    }

    s->g_cpu = env;
    s->c_cpu = env;
    s->state = RS_IDLE;
    s->running_state = GDB_STATE_CONTROL;

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
}
#endif

/*
void gdb_srv_handle_debug(struct kvm_cpu * p_kvm_cpu)
{
    if (!gdb_condition (p_kvm_cpu))
        return;

//    gdb_loop (-1, 0, 0, p_kvm_cpu);
    return;
}
*/

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

int gdb_srv_start_and_wait (struct kvm *p_kvm, int port)
{
    struct GDBState *s = p_kvm->m_gdb;

    s->running_state = GDB_STATE_DETACH;
    s->srv_sock_fd = gdb_srv_open (port);
    if (s->srv_sock_fd < 0)
    {
        printf ("Error: Cannot open port %d in %s\n", port, __FUNCTION__);
        return -1;
    }

    printf ("Waiting for a GDB connection on port %d (arch=%s) ...\n", port, TARGET_ARCH);
    gdb_srv_accept (s);

    s->running_state = GDB_STATE_INIT;

    s->g_cpu = p_kvm->first_cpu;
    s->c_cpu = p_kvm->first_cpu;

    atexit (close_gdb_sockets);

    return 0;
}

/* TODO: Register this handler and interrupt KVM Guest */
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

int gdb_server_init (struct kvm * p_kvm)
{
    struct GDBState *s = malloc(sizeof (struct GDBState));
    if(!s)
    {
        printf("Unable to Allocate Memory for GDB Server\n");
        return(-1);
    }

    memset(s, 0x0, sizeof (struct GDBState));
    s->running_state = GDB_STATE_DETACH;

    p_kvm->m_gdb = s;
    s->p_kvm = p_kvm;

    printf("GDB Server Initialized; KVM Instance = 0x%08X\n", (uint32_t) p_kvm);
    return 0;
}
