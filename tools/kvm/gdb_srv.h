#ifndef _GDB_SRV_H_
#define _GDB_SRV_H_

#include <inttypes.h>
#include "include/defs_imported.h"

#define GDB_MAX_PACKET_LENGTH (4096 * 4)

enum
{
    GDB_STATE_CONTROL,
    GDB_STATE_STEP,
    GDB_STATE_CONTINUE,
    GDB_STATE_DETACH,
    GDB_STATE_INIT,
};

enum
{
    GDB_BREAKPOINT_SW,
    GDB_BREAKPOINT_HW,
    GDB_WATCHPOINT_WRITE,
    GDB_WATCHPOINT_READ,
    GDB_WATCHPOINT_ACCESS
};

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

#define EXCP_INTERRUPT  0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */

#if 0
struct GDBState
{
    int                 fd;
    int                 srv_sock_fd;
    int                 c_cpu_index;
    int                 g_cpu_index;
    int                 query_cpu_index;
    int                 state;  /* parsing state */
    int                 running_state;
    char                line_buf[GDB_MAX_PACKET_LENGTH];
    int                 line_buf_index;
    int                 line_csum;
    uint8_t             last_packet[GDB_MAX_PACKET_LENGTH + 4];
    int                 last_packet_len;
};
#else
typedef struct GDBState {
    int                 fd;
    int                 srv_sock_fd;
    CPUState           *c_cpu;        /* current CPU for step/continue ops */
    CPUState           *g_cpu;        /* current CPU for other ops */
    CPUState           *query_cpu;    /* for q{f|s}ThreadInfo */
    int                 state;        /* parsing state */
    int                 running_state;
    char                line_buf[GDB_MAX_PACKET_LENGTH];
    int                 line_buf_index;
    int                 line_csum;
    uint8_t             last_packet[GDB_MAX_PACKET_LENGTH + 4];
    int                 last_packet_len;
    int                 signal;
    struct kvm         *p_kvm;
} GDBState;
#endif

int gdb_server_init (struct kvm * p_kvm);
int gdb_srv_start_and_wait (struct kvm *pinstance, int port);
void gdb_srv_handle_debug(struct kvm_cpu * p_kvm_cpu);
int gdb_condition (struct kvm_cpu * p_kvm_cpu);
int gdb_start_debug (void);

struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(CPUState *env, target_ulong pc);
int kvm_sw_breakpoints_active(CPUState *env);
int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap);

#endif
