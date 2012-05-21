#ifndef _GDB_SRV_H_
#define _GDB_SRV_H_

#include <inttypes.h>
#include "defs_imported.h"

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

    struct breakpoint_t
    {
        unsigned long   addr[100];
        int             nb;
    } breakpoints;
    
    struct watchpoint_t
    {
        struct watch_el_t
        {
            unsigned long   begin_address;
            unsigned long   end_address;
            int             type;
        } watch [100];
        int             nb;
    } watchpoints;
};

void gdb_server_init (struct kvm *pinstance);
int gdb_srv_start_and_wait (struct kvm *pinstance, int port);
void gdb_verify (target_ulong addr);
void gdb_loop (int idx_watch, int bwrite, unsigned long new_val);
int gdb_start_debug (void);
int gdb_condition (target_ulong addr);

#endif
