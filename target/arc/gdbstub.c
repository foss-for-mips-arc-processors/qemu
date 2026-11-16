#include "qemu/osdep.h"
#include "cpu.h"
#include "gdbstub.h"

uint32_t arc_gdb_read_status32(CPUARCState *env)
{
    arc_aux_status_t status = env->aux_status32;

    /* Report a CPU as halted while debugging (copy nSIM's behavior) */
    status.halt = 1;

    return arc_pack_status32(&status);
}

void arc_gdb_write_status32(CPUARCState *env, uint32_t value)
{
    arc_aux_status_t status;
    uint32_t new_bank;

    arc_unpack_status32(&status, value);

    /* Halt flag cannot be changed by a debugger */
    /* TODO: nSIM allows clearing H. Does it make sense in QEMU? */
    status.halt = env->aux_status32.halt;

    /* Switch registers banks if needed */
    new_bank = status.register_bank;
    status.register_bank = env->aux_status32.register_bank;
    env->aux_status32 = status;

    arc_cpu_switch_gpr_bank(env, new_bank);
}
