/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef ARC_TARGET_CPU_H
#define ARC_TARGET_CPU_H

/*
 * The thread pointer register of the ARC Linux ABI: r25 for ARCv2 and the
 * GP register (r30) for ARCv3, see arch/arc/kernel/process.c.
 */
#ifdef TARGET_ARCV2
#define ARC_REGNUM_TP ARC_REGNUM_R25
#else
#define ARC_REGNUM_TP ARC_REGNUM_GP
#endif

/*
 * Like the kernel, a new thread starts with the thread pointer (@thr_ptr) of
 * its parent unless CLONE_SETTLS is used, see cpu_set_tls().
 */
static inline void cpu_clone_regs_child(CPUARCState *env, target_ulong newsp,
                                        unsigned flags)
{
    if (newsp) {
        env->gpr[ARC_REGNUM_SP] = newsp;
    }

    env->gpr[ARC_REGNUM_R0] = 0;
    env->gpr[ARC_REGNUM_TP] = env->thr_ptr;
}

static inline void cpu_clone_regs_parent(CPUARCState *env, unsigned flags)
{
}

static inline void cpu_set_tls(CPUARCState *env, target_ulong newtls)
{
    env->thr_ptr = newtls;
    env->gpr[ARC_REGNUM_TP] = newtls;
}

static inline abi_ulong get_sp_from_cpustate(CPUARCState *state)
{
    return state->gpr[ARC_REGNUM_SP];
}

#endif
