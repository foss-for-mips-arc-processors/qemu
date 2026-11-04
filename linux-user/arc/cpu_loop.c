/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU user cpu loop for ARC
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/cpu_loop.h"
#include "signal-common.h"
#include "syscall_nr.h"

/* TRAP_S parameters used by the Linux kernel */
#define ARC_TRAP_SYSCALL    0
#define ARC_TRAP_BREAKPOINT 1

/* TRAP_S is a 16-bit instruction */
#define ARC_TRAP_S_SIZE     2

static void arc_set_pc(CPUARCState *env, target_ulong pc)
{
    env->pc = pc;
    env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(pc);
}

/*
 * arch/arc/kernel/sys.c: sys_arc_usr_cmpxchg(uaddr, expected, new).
 * Returns the old value and stores @new only if the old value matched.
 */
static abi_long arc_usr_cmpxchg(CPUARCState *env, abi_ulong addr,
                                uint32_t expected, uint32_t new)
{
    uint32_t old;

    start_exclusive();
    if (get_user_u32(old, addr)) {
        end_exclusive();
        return -TARGET_EFAULT;
    }
    if (old == expected && put_user_u32(new, addr)) {
        end_exclusive();
        return -TARGET_EFAULT;
    }
    end_exclusive();

    return old;
}

static abi_long arc_do_syscall(CPUARCState *env)
{
    abi_ulong *r = env->gpr;

    switch (r[ARC_REGNUM_R8]) {
    case TARGET_NR_arc_settls:
        /* It does not change the thread pointer register of the caller */
        env->thr_ptr = r[ARC_REGNUM_R0];
        return 0;
    case TARGET_NR_arc_gettls:
        return env->thr_ptr;
    case TARGET_NR_cacheflush:
        /* Caches are coherent in user mode emulation */
        return 0;
    case TARGET_NR_arc_usr_cmpxchg:
        return arc_usr_cmpxchg(env, r[ARC_REGNUM_R0], r[ARC_REGNUM_R1],
                               r[ARC_REGNUM_R2]);
    default:
        return do_syscall(env, r[ARC_REGNUM_R8],
                          r[ARC_REGNUM_R0], r[ARC_REGNUM_R1],
                          r[ARC_REGNUM_R2], r[ARC_REGNUM_R3],
                          r[ARC_REGNUM_R4], r[ARC_REGNUM_R5],
                          -1, -1);
    }
}

static void arc_handle_trap(CPUARCState *env)
{
    abi_long ret;

    switch (env->excp_parameter) {
    case ARC_TRAP_SYSCALL:
        arc_set_pc(env, env->pc + ARC_TRAP_S_SIZE);
        ret = arc_do_syscall(env);
        if (ret == -QEMU_ERESTARTSYS) {
            arc_set_pc(env, env->pc - ARC_TRAP_S_SIZE);
        } else if (ret != -QEMU_ESIGRETURN) {
            env->gpr[ARC_REGNUM_R0] = ret;
        }
        break;
    case ARC_TRAP_BREAKPOINT:
        force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
        break;
    default:
        force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLTRP, env->pc);
        break;
    }
}

void cpu_loop(CPUARCState *env)
{
    CPUState *cs = env_cpu(env);
    int trapnr;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        qemu_process_cpu_events(cs);

        switch (trapnr) {
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        case EXCP_DEBUG:
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
            break;
        case ARC_EXCP_TRAP:
            arc_handle_trap(env);
            break;
        case ARC_EXCP_ILLEGAL_INSTRUCTION:
        case ARC_EXCP_ILLEGAL_INSTRUCTION_SEQUENCE:
        case ARC_EXCP_SWI:
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLOPC, env->pc);
            break;
        case ARC_EXCP_PRIVILEGE_VIOLATION:
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_PRVOPC, env->pc);
            break;
        case ARC_EXCP_DIVZERO:
            force_sig_fault(TARGET_SIGFPE, TARGET_FPE_INTDIV, env->pc);
            break;
        case ARC_EXCP_MISALIGNED_DATA:
            force_sig_fault(TARGET_SIGBUS, TARGET_BUS_ADRALN,
                            env->excp_mem_addr);
            break;
        case ARC_EXCP_TLB_MISS_I:
        case ARC_EXCP_TLB_MISS_D_LD:
        case ARC_EXCP_TLB_MISS_D_ST:
            force_sig_fault(TARGET_SIGSEGV, TARGET_SEGV_MAPERR,
                            env->excp_mem_addr);
            break;
        case ARC_EXCP_PROTV_EX:
        case ARC_EXCP_PROTV_LD:
        case ARC_EXCP_PROTV_ST:
            force_sig_fault(TARGET_SIGSEGV, TARGET_SEGV_ACCERR,
                            env->excp_mem_addr);
            break;
        default:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n",
                      trapnr);
            exit(EXIT_FAILURE);
        }

        process_pending_signals(env);
    }
}

void init_main_thread(CPUState *cs, struct image_info *info)
{
    CPUARCState *env = cpu_env(cs);

    arc_set_pc(env, info->entry);
    env->gpr[ARC_REGNUM_SP] = info->start_stack;
}
