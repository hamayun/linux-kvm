#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "include/kvm/kvm.h"
#include "include/kvm/kvm-cpu.h"
#include "include/kvm/util.h"

#include "gdb_srv.h"
#include "gdb_srv_arch.h"

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    CPUState *env;
    int err;
};

static struct {
    target_ulong addr;
    int len;
    int type;
} hw_breakpoint[4];

static int nb_hw_breakpoint;
static CPUWatchpoint hw_watchpoint;

static int kvm_cpu__get_regs(struct kvm_cpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &vcpu->regs) < 0)
		die_perror("KVM_GET_REGS failed");
    return 0;
}

static int kvm_cpu__get_sregs(struct kvm_cpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_GET_SREGS failed");
    return 0;
}

static int kvm_cpu__put_regs(struct kvm_cpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs) < 0)
		die_perror("KVM_SET_REGS failed");
    return 0;
}

static int kvm_cpu__put_sregs(struct kvm_cpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_SET_SREGS failed");
    return 0;
}

static int kvm_cpu__get_debugregs(struct kvm_cpu *vcpu)
{
    struct kvm_debugregs dbgregs;
    int i, ret;

    /* Check if KVM has debug registers */
    if (!vcpu->kvm->debugregs) {
        return 0;
    }

    ret = ioctl(vcpu->vcpu_fd, KVM_GET_DEBUGREGS, &dbgregs);
    if (ret < 0) {
        return ret;
    }

    for (i = 0; i < 4; i++) {
        vcpu->dr[i] = dbgregs.db[i];
    }
    vcpu->dr[4] = vcpu->dr[6] = dbgregs.dr6;
    vcpu->dr[5] = vcpu->dr[7] = dbgregs.dr7;

    return 0;
}

static int kvm_cpu__put_debugregs(struct kvm_cpu *vcpu)
{
    struct kvm_debugregs dbgregs;
    int i;

    /* Check if KVM has debug registers */
    if (!vcpu->kvm->debugregs) {
        return 0;
    }

    for (i = 0; i < 4; i++) {
        dbgregs.db[i] = vcpu->dr[i];
    }

    dbgregs.dr6 = vcpu->dr[6];
    dbgregs.dr7 = vcpu->dr[7];
    dbgregs.flags = 0;

    return ioctl(vcpu->vcpu_fd, KVM_SET_DEBUGREGS, &dbgregs);
}

static int kvm_arch_insert_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp)
{
    static const uint8_t int3 = 0xcc;

    DPRINTF("Insert S/W breakpoint (CPU # %d, addr = 0x%08X)\n",
            (uint32_t) env->cpu_id, (uint32_t) bp->pc);

    if (kvm_arch_memory_rw_debug(env, bp->pc, (uint8_t *)&bp->saved_insn, 1, 0) ||
        kvm_arch_memory_rw_debug(env, bp->pc, (uint8_t *)&int3, 1, 1)) {
        return -EINVAL;
    }
    return 0;
}

static int kvm_arch_remove_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp)
{
    uint8_t int3;

    DPRINTF("Remove S/W breakpoint (CPU # %d, addr = 0x%08X)\n",
            (uint32_t) env->cpu_id, (uint32_t) bp->pc);

    if (kvm_arch_memory_rw_debug(env, bp->pc, &int3, 1, 0) || int3 != 0xcc ||
        kvm_arch_memory_rw_debug(env, bp->pc, (uint8_t *)&bp->saved_insn, 1, 1)) {
        return -EINVAL;
    }
    return 0;
}

static struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(CPUState *env, target_ulong pc)
{
    struct kvm_sw_breakpoint *bp;

    QTAILQ_FOREACH(bp, &env->kvm->kvm_sw_breakpoints, entry) {
        if (bp->pc == pc) {
            return bp;
        }
    }
    return NULL;
}

static int kvm_sw_breakpoints_active(CPUState *env)
{
    return !QTAILQ_EMPTY(&env->kvm->kvm_sw_breakpoints);
}

static int find_hw_breakpoint(target_ulong addr, int len, int type)
{
    int n;

    DPRINTF("Find H/W breakpoint (addr = 0x%08X, Total = %d)\n",
            (uint32_t) addr, (uint32_t) nb_hw_breakpoint);

    for (n = 0; n < nb_hw_breakpoint; n++) {
        if (hw_breakpoint[n].addr == addr && hw_breakpoint[n].type == type &&
            (hw_breakpoint[n].len == len || len == -1)) {
            return n;
        }
    }
    return -1;
}

static int kvm_arch_insert_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    DPRINTF("Insert H/W breakpoint (addr = 0x%08X, len = %d, type = %d)\n",
            (uint32_t) addr, (uint32_t) len, type);

    switch (type) {
    case GDB_BREAKPOINT_HW:
        len = 1;
        break;
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_ACCESS:
        switch (len) {
        case 1:
            break;
        case 2:
        case 4:
        case 8:
            if (addr & (len - 1)) {
                return -EINVAL;
            }
            break;
        default:
            return -EINVAL;
        }
        break;
    default:
        return -ENOSYS;
    }

    if (nb_hw_breakpoint == 4) {
        return -ENOBUFS;
    }
    if (find_hw_breakpoint(addr, len, type) >= 0) {
        return -EEXIST;
    }
    hw_breakpoint[nb_hw_breakpoint].addr = addr;
    hw_breakpoint[nb_hw_breakpoint].len = len;
    hw_breakpoint[nb_hw_breakpoint].type = type;
    nb_hw_breakpoint++;

    return 0;
}

static int kvm_arch_remove_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    int n;

    DPRINTF("Remove H/W breakpoint (addr = 0x%08X, len = %d, type = %d)\n",
            (uint32_t) addr, (uint32_t) len, type);

    n = find_hw_breakpoint(addr, (type == GDB_BREAKPOINT_HW) ? 1 : len, type);
    if (n < 0) {
        return -ENOENT;
    }
    nb_hw_breakpoint--;
    hw_breakpoint[n] = hw_breakpoint[nb_hw_breakpoint];

    return 0;
}

static void kvm_arch_remove_all_hw_breakpoints(void)
{
    DPRINTF("Remove All H/W breakpoints\n");
    nb_hw_breakpoint = 0;
}

static int kvm_has_vcpu_events(CPUState *env)
{
    return env->kvm->vcpu_events;
}

static int kvm_has_robust_singlestep(CPUState *env)
{
    return env->kvm->robust_singlestep;
}

static int kvm_guest_debug_workarounds(CPUState *env)
{
    int ret = 0;
    unsigned long reinject_trap = 0;

    if (!kvm_has_vcpu_events(env)) {
        if (env->exception_injected == 1) {
            reinject_trap = KVM_GUESTDBG_INJECT_DB;
        } else if (env->exception_injected == 3) {
            reinject_trap = KVM_GUESTDBG_INJECT_BP;
        }
        env->exception_injected = -1;
    }

    /*
     * Kernels before KVM_CAP_X86_ROBUST_SINGLESTEP overwrote flags.TF
     * injected via SET_GUEST_DEBUG while updating GP regs. Work around this
     * by updating the debug state once again if single-stepping is on.
     * Another reason to call kvm_update_guest_debug here is a pending debug
     * trap raise by the guest. On kernels without SET_VCPU_EVENTS we have to
     * reinject them via SET_GUEST_DEBUG.
     */
    if (reinject_trap ||
        (!kvm_has_robust_singlestep(env) && (env->kvm->sw_single_step > 0))) {
        ret = kvm_update_guest_debug(env, reinject_trap);
    }
    return ret;
}

int kvm_arch_get_registers(CPUState *env)
{
    int ret;
    DPRINTF("kvm_arch_get_registers\n");
    //if(!(cpu_is_stopped(env)))
    //    die_perror("CPU Must be Stopped\n");

    ret = kvm_cpu__get_regs(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_cpu__get_sregs(env);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_cpu__get_debugregs(env);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

int kvm_arch_put_registers(CPUState *env)
{
    int ret;

    //if(!(cpu_is_stopped(env)))
    //    die_perror("CPU Must be Stopped\n");

    DPRINTF("kvm_arch_put_registers");

    ret = kvm_cpu__put_regs(env);
    if (ret < 0) {
        DPRINTF2(" ... ERROR (put regs)\n");
        return ret;
    }

    ret = kvm_cpu__put_sregs(env);
    if (ret < 0) {
        DPRINTF2(" ... ERROR (put sregs)\n");
        return ret;
    }

    ret = kvm_cpu__put_debugregs(env);
    if (ret < 0) {
        DPRINTF2(" ... ERROR (put debugregs)\n");
        return ret;
    }

    /* must be last */
    ret = kvm_guest_debug_workarounds(env);
    if (ret < 0) {
        return ret;
    }

    DPRINTF2(" ... OK\n");
    return 0;
}

int kvm_cpu_synchronize_state(CPUState *env)
{
    DPRINTF("CPU Synchronize State [CPU # %ld]\n", env->cpu_id);

    if (!env->kvm_vcpu_dirty) {
        kvm_arch_get_registers(env);
        env->kvm_vcpu_dirty = 1;
    }

    return 0;
}

int kvm_arch_memory_rw_debug(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write)
{
    uint8_t * phys_addr = env->kvm->ram_start + addr;

    while (len > 0)
    {
        if (is_write){
            *phys_addr = *buf;
        } else {
            *buf = *phys_addr;
        }

        len -= 1;
        buf += 1;
        phys_addr += 1;
    }

    return 0;
}

int kvm_arch_handle_debug(CPUState * env)
{
    struct kvm_debug_exit_arch *arch_info = &env->kvm_run->debug.arch;
    struct kvm_sw_breakpoint *bp = NULL;
    int ret = 0;
    int n;

    DPRINTF("%s: [CPU # %d]\n", __func__, (uint32_t) env->cpu_id);

    if (arch_info->exception == 1) {
        if (arch_info->dr6 & (1 << 14)) {
            if (env->kvm->sw_single_step > 0) {
                DPRINTF("Single Step\n");
                ret = EXCP_DEBUG;

                env->kvm->sw_single_step--;
                if(env->kvm->sw_single_step == 0)
                {
                    kvm_update_guest_debug(env, 0);
                }
            }
        } else {
            for (n = 0; n < 4; n++) {
                if (arch_info->dr6 & (1 << n)) {
                    switch ((arch_info->dr7 >> (16 + n*4)) & 0x3) {
                    case 0x0:
                        DPRINTF("Generic Debug Exception\n");
                        ret = EXCP_DEBUG;
                        break;
                    case 0x1:
                        DPRINTF("BP_MEM_WRITE\n");
                        ret = EXCP_DEBUG;
                        env->watchpoint_hit = &hw_watchpoint;
                        hw_watchpoint.vaddr = hw_breakpoint[n].addr;
                        hw_watchpoint.flags = BP_MEM_WRITE;
                        break;
                    case 0x3:
                        DPRINTF("BP_MEM_ACCESS\n");
                        ret = EXCP_DEBUG;
                        env->watchpoint_hit = &hw_watchpoint;
                        hw_watchpoint.vaddr = hw_breakpoint[n].addr;
                        hw_watchpoint.flags = BP_MEM_ACCESS;
                        break;
                    }
                }
            }
        }
    } else if ((bp = kvm_find_sw_breakpoint(env, arch_info->pc))) {
        DPRINTF("%s: SW Breakpoint Found, PC = 0x%08x\n",
                __func__, (uint32_t) arch_info->pc);
        ret = EXCP_DEBUG;
    }

    if (ret){
        /* We got something to handle; call the gdb server */
        gdb_srv_handle_debug(env);
    }

    return ret;
}

static int kvm_arch_update_guest_debug(CPUState *env, struct kvm_guest_debug *dbg)
{
    const uint8_t type_code[] = {
        [GDB_BREAKPOINT_HW] = 0x0,
        [GDB_WATCHPOINT_WRITE] = 0x1,
        [GDB_WATCHPOINT_ACCESS] = 0x3
    };

    const uint8_t len_code[] = {
        [1] = 0x0, [2] = 0x1, [4] = 0x3, [8] = 0x2
    };

    int n;

    DPRINTF("kvm_arch_update_guest_debug [CPU # %d]\n", (uint32_t) env->cpu_id);

    if (kvm_sw_breakpoints_active(env)) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }
    if (nb_hw_breakpoint > 0) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        dbg->arch.debugreg[7] = 0x0600;
        for (n = 0; n < nb_hw_breakpoint; n++) {
            dbg->arch.debugreg[n] = hw_breakpoint[n].addr;
            dbg->arch.debugreg[7] |= (2 << (n * 2)) |
                (type_code[hw_breakpoint[n].type] << (16 + n*4)) |
                ((uint32_t)len_code[hw_breakpoint[n].len] << (18 + n*4));
        }
    }

    return 0;
}

static void kvm_invoke_set_guest_debug(void *data)
{
    struct kvm_set_guest_debug_data *dbg_data = data;
    CPUState *env = dbg_data->env;

    dbg_data->err = ioctl(env->vcpu_fd, KVM_SET_GUEST_DEBUG, &dbg_data->dbg);
    printf("%s: IOCTL for CPU#%d ... Done\n", __func__, (uint32_t) env->cpu_id);
}

static int qemu_thread_is_self(pthread_t thread)
{
   return pthread_equal(pthread_self(), thread);
}

static int qemu_cpu_is_self(void *_env)
{
    CPUState *env = _env;

    return qemu_thread_is_self(env->thread);
}

static void qemu_cpu_kick_thread(CPUState *env)
{
    int err;

    err = pthread_kill(env->thread, SIG_IPI);
    if (err) {
        fprintf(stderr, "Error in %s: %s", __func__, strerror(err));
        exit(1);
    }
}

static void qemu_cond_broadcast(pthread_cond_t *cond)
{
    int err;

    err = pthread_cond_broadcast(cond);
    if (err)
    {
        printf("Error: In pthread_cond_broadcast()");
        return;
    }
}

pthread_mutex_t qemu_global_mutex;
pthread_cond_t qemu_work_cond;

static void qemu_cpu_kick(void *_env)
{
    CPUState *env = _env;

    printf("%s: Calling qemu_cond_broadcast (halt_cond) ... (CPU#%d)\n", __func__, env->cpu_id);
    qemu_cond_broadcast(&env->halt_cond);
    if (!env->thread_kicked) {
        qemu_cpu_kick_thread(env);
        env->thread_kicked = true;
    }
}

void qemu_cond_init(pthread_cond_t *cond)
{
    int err;

    err = pthread_cond_init(cond, NULL);
    if (err)
    {
        fprintf(stderr, "%s: Error in pthread_cond_init\n", __func__);
        exit(1);
    }
}

void qemu_mutex_init(pthread_mutex_t *mutex)
{
    int err;
    pthread_mutexattr_t mutexattr;

    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
    err = pthread_mutex_init(mutex, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);
    if (err)
    {
        fprintf(stderr, "%s: Error in pthread_mutex_init\n", __func__);
        exit(1);
    }
}

void qemu_mutex_lock(pthread_mutex_t *mutex)
{
    int err;

    err = pthread_mutex_lock(mutex);
    if (err)
    {
        fprintf(stderr, "%s: Error in pthread_mutex_lock\n", __func__);
        exit(1);
    }
}

void qemu_mutex_unlock(pthread_mutex_t *mutex)
{
    int err;

    err = pthread_mutex_unlock(mutex);
    if (err)
    {
        fprintf(stderr, "%s: Error in pthread_mutex_unlock\n", __func__);
        exit(1);
    }
}

static void qemu_cond_wait(pthread_cond_t *cond, pthread_mutex_t *lock)
{
    int err;

    err = pthread_cond_wait(cond, lock);
    if (err) {
        if(err == EPERM)
        {
            fprintf(stderr, "%s: err == EPERM\n", __func__);
        }

        fprintf(stderr, "%s: Error in pthread_cond_wait (err code = %d)\n", __func__, err);
        exit(1);
    }

}

static bool cpu_thread_is_idle(CPUState *env)
{
    if (env->queued_work_first) {
    //if (env->queued_work_size > 0) {
        return false;
    }
    if (env->paused) {
        return true;
    }
    if (!env->paused || env->kvm->irqchip_in_kernel) {
        return false;
    }
    return true;
}

#if 0
static void qemu_kvm_eat_signals(CPUState *env)
{
    struct timespec ts = { 0, 0 };
    siginfo_t siginfo;
    sigset_t waitset;
    sigset_t chkset;
    int r;

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);
    sigaddset(&waitset, SIGBUS);

    do {
        r = sigtimedwait(&waitset, &siginfo, &ts);
        if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
            perror("sigtimedwait");
            exit(1);
        }

        switch (r) {
        case SIGBUS:
            if (kvm_on_sigbus_vcpu(env, siginfo.si_code, siginfo.si_addr)) {
                sigbus_reraise();
            }
            break;
        default:
            break;
        }

        r = sigpending(&chkset);
        if (r == -1) {
            perror("sigpending");
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI) || sigismember(&chkset, SIGBUS));
}
#endif

#if 0 // Dynamic allocations
static void flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->queued_work_first) {
        return;
    }

    while ((wi = env->queued_work_first)) {
        env->queued_work_first = wi->next;
        wi->func(wi->data);
        wi->done = true;

        env->queued_work_size--;
        free(wi->data);
        free(wi);
    }

    env->queued_work_last = NULL;
    qemu_cond_broadcast(&qemu_work_cond);
}

static void run_on_cpu(CPUState *env, void (*func)(void *data), void *data)
{
    struct qemu_work_item * wi = NULL;

    if (qemu_cpu_is_self(env)) {
        DPRINTF("%s: CPU is Self\n", __func__);
        func(data);
        return;
    }
    else
    {
        DPRINTF("%s: CPU is NOT Self\n", __func__);
    }

    wi = (struct qemu_work_item *) malloc(sizeof(struct qemu_work_item));
    if(!wi)
    {
        printf("Error: Allocating Work Item\n");
        return;
    }

    wi->data = (struct kvm_set_guest_debug_data *) malloc(sizeof(struct kvm_set_guest_debug_data));
    if(!wi->data)
    {
        printf("Error: Allocating Work Item Data\n");
        return;
    }

    wi->func = func;
    //wi->data = data;
    memcpy(wi->data, data, sizeof(struct kvm_set_guest_debug_data));

    if (!env->queued_work_first) {
        env->queued_work_first = wi;
    } else {
        env->queued_work_last->next = wi;
    }

    env->queued_work_last = wi;

    wi->next = NULL;
    wi->done = false;

    env->queued_work_size++;
    printf("###### %s: CPU#%d, queued_work_size = %d\n", __func__, env->cpu_id, env->queued_work_size);

    qemu_cpu_kick(env);
    printf("%s: Kicked CPU#%d\n", __func__, env->cpu_id);

    while (!wi->done) {
        //CPUState *self_env = cpu_single_env;

        qemu_cond_wait(&qemu_work_cond, &qemu_global_mutex);
        //cpu_single_env = self_env;
    }
}
#else
static void flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->queued_work_first) {
        return;
    }

    while ((wi = env->queued_work_first)) {
        env->queued_work_first = wi->next;
        wi->func(wi->data);
        wi->done = true;

        env->queued_work_size--;
    }

    env->queued_work_last = NULL;
    printf("%s: qemu_cond_broadcast @qemu_work_cond\n", __func__);
    qemu_cond_broadcast(&qemu_work_cond);
}

static void run_on_cpu(CPUState *env, void (*func)(void *data), void *data)
{
    struct qemu_work_item wi;

    if (qemu_cpu_is_self(env)) {
        printf("%s: CPU is Self\n", __func__);
        func(data);
        return;
    }
    else
    {
        printf("%s: CPU is NOT Self\n", __func__);
    }

    wi.func = func;
    wi.data = data;

    if (!env->queued_work_first) {
        env->queued_work_first = &wi;
    } else {
        env->queued_work_last->next = &wi;
    }

    env->queued_work_last = &wi;

    wi.next = NULL;
    wi.done = false;

    env->queued_work_size++;
    printf("###### %s: CPU#%d, queued_work_size = %d\n", __func__, env->cpu_id, env->queued_work_size);
    qemu_cpu_kick(env);

    while (!wi.done) {
        //CPUState *self_env = cpu_single_env;

        printf("%s: Kicked CPU#%d ... Waiting on qemu_work_cond\n", __func__, env->cpu_id);
        qemu_cond_wait(&qemu_work_cond, &qemu_global_mutex);
        //cpu_single_env = self_env;
    }
    printf("%s: Finished waiting on qemu_work_cond\n", __func__);
}
#endif

static void qemu_wait_io_event_common(CPUState *env)
{
    /*
    if (env->stop) {
        env->stop = 0;
        env->stopped = 1;
        qemu_cond_signal(&qemu_pause_cond);
    }*/

    flush_queued_work(env);
    env->thread_kicked = false;
}

static void qemu_kvm_eat_signals(CPUState *env)
{
    struct timespec ts = { 0, 0 };
    siginfo_t siginfo;
    sigset_t waitset;
    sigset_t chkset;
    int r;

    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);
    sigaddset(&waitset, SIGBUS);

    do {
        r = sigtimedwait(&waitset, &siginfo, &ts);
        if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
            perror("sigtimedwait");
            exit(1);
        }

        switch (r) {
        case SIGBUS:
            //if (kvm_on_sigbus_vcpu(env, siginfo.si_code, siginfo.si_addr)) {
            //    sigbus_reraise();
            //}
            break;
        default:
            break;
        }

        r = sigpending(&chkset);
        if (r == -1) {
            perror("sigpending");
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI) || sigismember(&chkset, SIGBUS));
}

void qemu_kvm_wait_io_event(CPUState *env)
{
    while (cpu_thread_is_idle(env)) {
        printf("%s: Calling qemu_cond_wait (halt_cond) ... (CPU#%d)\n", __func__, env->cpu_id);
        qemu_cond_wait(&env->halt_cond, &qemu_global_mutex);
    }

    //qemu_kvm_eat_signals(env);
    qemu_wait_io_event_common(env);
}

int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap)
{
    struct kvm_set_guest_debug_data data;

    data.dbg.control = reinject_trap;

    if (env->kvm->sw_single_step > 0) {
        data.dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
    }

    kvm_arch_update_guest_debug(env, &data.dbg);
    data.env = env;

    run_on_cpu(env, kvm_invoke_set_guest_debug, &data);
    //data.err = ioctl(env->vcpu_fd, KVM_SET_GUEST_DEBUG, &data.dbg);
    return data.err;
}

int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    CPUState *env;
    struct kvm_sw_breakpoint *bp;
    int err;

    DPRINTF("Insert breakpoint (addr = 0x%08X, len = %d, type = %d)\n",
            (uint32_t) addr, (uint32_t) len, type);

    if (type == GDB_BREAKPOINT_SW) {
        bp = kvm_find_sw_breakpoint(current_env, addr);
        if (bp) {
            bp->use_count++;
            return 0;
        }

        bp = malloc(sizeof(struct kvm_sw_breakpoint));
        if (!bp) {
            return -ENOMEM;
        }

        bp->pc = addr;
        bp->use_count = 1;
        err = kvm_arch_insert_sw_breakpoint(current_env, bp);
        if (err) {
            free(bp);
            return err;
        }

        QTAILQ_INSERT_HEAD(&current_env->kvm->kvm_sw_breakpoints,
                          bp, entry);
    } else {
        err = kvm_arch_insert_hw_breakpoint(addr, len, type);
        if (err) {
            return err;
        }
    }

    for (env = current_env->kvm->first_cpu; env != NULL; env = env->next_cpu) {
        err = kvm_update_guest_debug(env, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    struct kvm_sw_breakpoint *bp;
    CPUState *env;
    int err;

    DPRINTF("Remove breakpoint (addr = 0x%08X, len = %d, type = %d)\n",
            (uint32_t) addr, (uint32_t) len, type);

    if (type == GDB_BREAKPOINT_SW) {
        bp = kvm_find_sw_breakpoint(current_env, addr);
        if (!bp) {
            return -ENOENT;
        }

        if (bp->use_count > 1) {
            bp->use_count--;
            return 0;
        }

        err = kvm_arch_remove_sw_breakpoint(current_env, bp);
        if (err) {
            return err;
        }

        QTAILQ_REMOVE(&current_env->kvm->kvm_sw_breakpoints, bp, entry);
        free(bp);
    } else {
        err = kvm_arch_remove_hw_breakpoint(addr, len, type);
        if (err) {
            return err;
        }
    }

    for (env = current_env->kvm->first_cpu; env != NULL; env = env->next_cpu) {
        err = kvm_update_guest_debug(env, 0);
        if (err) {
            return err;
        }
    }
    return 0;
}

int kvm_remove_all_breakpoints(CPUState *current_env)
{
    struct kvm_sw_breakpoint *bp, *next;
    struct kvm *kvm = current_env->kvm;
    CPUState *env;

    DPRINTF("Remove All S/W Breakpoints\n");

    QTAILQ_FOREACH_SAFE(bp, &kvm->kvm_sw_breakpoints, entry, next) {
        if (kvm_arch_remove_sw_breakpoint(current_env, bp) != 0) {
            /* Try harder to find a CPU that currently sees the breakpoint. */
            for (env = kvm->first_cpu; env != NULL; env = env->next_cpu) {
                if (kvm_arch_remove_sw_breakpoint(env, bp) == 0) {
                    break;
                }
            }
        }
    }

    kvm_arch_remove_all_hw_breakpoints();

    for (env = kvm->first_cpu; env != NULL; env = env->next_cpu) {
        kvm_update_guest_debug(env, 0);
    }

    DPRINTF("Removed All Breakpoints ... Done\n");
    return 0;
}
