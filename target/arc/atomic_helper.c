#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/probe.h"
#include "exec/translation-block.h"
#ifndef CONFIG_USER_ONLY
#include "mmu.h"
#endif

static void arc_check_atomic_align(CPUARCState *env, target_ulong addr,
                                   uint32_t align, uintptr_t ra)
{
    if (addr & (align - 1)) {
        env->excp_mem_addr = addr;
        arc_raise_exception(env, ARC_EXCP_MISALIGNED_DATA, 0, ra);
    }
}

static hwaddr arc_atomic_paddr(CPUARCState *env, target_ulong addr,
                               MMUAccessType type, int size, uintptr_t ra)
{
    int mmu_idx = env->aux_status32.user_mode;
#ifndef CONFIG_USER_ONLY
    hwaddr paddr;
    bool ok;
#endif

    probe_access(env, addr, size, type, mmu_idx, ra);

#ifdef CONFIG_USER_ONLY
    return addr;
#else
    ok = arc_mmu_get_paddr(env, addr, type, &paddr);
    assert(ok);

    return paddr;
#endif
}

/*
 * LLOCK and SCOND remember the locked address and the loaded value. SCOND
 * succeeds only if the lock flag is set, the address matches and the memory
 * still holds the value read by LLOCK.
 *
 * TODO: This is only an approximation of the hardware, where any store to
 * the locked word clears the lock (nSIM does this even for a store of the
 * same value). Replace the value comparison with a proper lock monitor,
 * both for system mode and user mode.
 */
static void arc_atomic_lock(CPUARCState *env, hwaddr paddr, uint64_t value)
{
    env->atomic_lpa = paddr;
    env->atomic_lval = value;
    env->atomic_lf = 1;
}

static bool arc_atomic_try_store(CPUARCState *env, target_ulong addr,
                                 hwaddr paddr, uint64_t value,
                                 uint32_t size, uintptr_t ra)
{
    bool success = env->atomic_lf && env->atomic_lpa == paddr;

#ifdef CONFIG_USER_ONLY
    CPUState *cs = env_cpu(env);

    /* Claim exclusive thread access for an atomic write */
    if (tcg_cflags_has(cs, CF_PARALLEL) &&
        !cpu_in_exclusive_context(cs)) {
        cpu_loop_exit_atomic(cs, ra);
    }
#endif

    if (success) {
        uint64_t current = (size == 4) ? cpu_ldl_data_ra(env, addr, ra)
                                       : cpu_ldq_data_ra(env, addr, ra);
        success = current == (size == 4 ? (uint32_t)env->atomic_lval
                                        : env->atomic_lval);
    }

    if (success) {
        if (size == 4) {
            cpu_stl_data_ra(env, addr, value, ra);
        } else {
            cpu_stq_data_ra(env, addr, value, ra);
        }
    }

    env->aux_status32.zero_flag = success;
    env->atomic_lf = 0;

    return success;
}

uint32_t HELPER(llock)(CPUARCState *env, target_ulong addr)
{
    hwaddr paddr;
    uint32_t value;

    arc_check_atomic_align(env, addr, 4, GETPC());
    paddr = arc_atomic_paddr(env, addr, MMU_DATA_LOAD, 4, GETPC());

    value = cpu_ldl_data_ra(env, addr, GETPC());
    arc_atomic_lock(env, paddr, value);

    return value;
}

/*
 * SCOND and SCONDD will write successfully only if LF == 1 and
 * paddr == LPA. This behavior is *undocumented* and may verified
 * in nSIM.
 */

void HELPER(scond)(CPUARCState *env, target_ulong addr, uint32_t value)
{
    hwaddr paddr;

    arc_check_atomic_align(env, addr, 4, GETPC());
    paddr = arc_atomic_paddr(env, addr, MMU_DATA_STORE, 4, GETPC());

    arc_atomic_try_store(env, addr, paddr, value, 4, GETPC());
}

uint64_t HELPER(llockd)(CPUARCState *env, target_ulong addr)
{
    hwaddr paddr;
    uint64_t value;

    arc_check_atomic_align(env, addr, 8, GETPC());
    paddr = arc_atomic_paddr(env, addr, MMU_DATA_LOAD, 8, GETPC());

    value = cpu_ldq_data_ra(env, addr, GETPC());
    arc_atomic_lock(env, paddr, value);

    return value;
}

void HELPER(scondd)(CPUARCState *env, target_ulong addr, uint64_t value)
{
    hwaddr paddr;

    arc_check_atomic_align(env, addr, 8, GETPC());
    paddr = arc_atomic_paddr(env, addr, MMU_DATA_STORE, 8, GETPC());

    arc_atomic_try_store(env, addr, paddr, value, 8, GETPC());
}
