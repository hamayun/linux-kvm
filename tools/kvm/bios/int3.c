#include "kvm/bios.h"

/* We just want to quit the guest mode on breakpoints;
 * GDB Server Handles the rest in Host Mode */
bioscall void int3_handler(struct biosregs *regs)
{
    /* decrement eip; so we re-execute the original instruction */
    /* regs->eip -= 1; */
    /* pass control to user-space gdb server; for further processsing */
    //__asm__ volatile ("movl %0,%%eax" : : "m" (regs->eip));
    __asm__ volatile ("movl $0x0,%eax");   /* We send EIP = 0x0 in Real Mode; Temporary Hack */
    __asm__ volatile ("outl %%eax,%0" : : "dN" (IOPORT_BREAKPOINT));
}
