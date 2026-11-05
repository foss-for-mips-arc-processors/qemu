#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qapi/error.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "tcg/debug-assert.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/cpu-ldst.h"
#include "hw/qdev-properties.h"
#include "gdbstub.h"
#ifndef CONFIG_USER_ONLY
#include "timer.h"
#include "mmu.h"
#include "irq.h"
#endif

/* TODO: Remove static and reuse everywhere? */
static void arc_cpu_set_pc(CPUState *cs, vaddr value)
{
    CPUARCState *env = cpu_env(cs);

    env->pc = value;
    env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(value);
}

static vaddr arc_cpu_get_pc(CPUState *cs)
{
    CPUARCState *env = cpu_env(cs);

    return env->pc;
}

uint32_t arc_cpu_effective_gpr_bank(CPUARCState *env, uint32_t n)
{
    uint32_t extra = FIELD_EX32(env_archcpu(env)->aux_rf_build, AUX_RF_BUILD, BANKS);
    uint32_t nr_of_banks = extra + 1;

    /*
     * RGF_NUM_BANKS is extra+1. A power-of-two total implements
     * only log2(N) bits of STATUS32.RB; otherwise RB saturates.
     */
    if (nr_of_banks == 1) {
        n = 0;
    } else if (is_power_of_2(nr_of_banks)) {
        n &= nr_of_banks - 1;
    } else if (n >= nr_of_banks) {
        n = nr_of_banks - 1;
    }

    return n;
}

void arc_cpu_switch_gpr_bank(CPUARCState *env, uint32_t n)
{
    uint32_t old = env->aux_status32.register_bank;

    n = arc_cpu_effective_gpr_bank(env, n);

    if (n == old) {
        return;
    }

    /* ILINK is never replicated. RF_BUILD.D=32 duplicates r0–r31. */
    for (int i = 0; i < 32; i++) {
        if (i == ARC_REGNUM_ILINK) {
            continue;
        }
        env->gpr_banks[old][i] = env->gpr[i];
        env->gpr[i] = env->gpr_banks[n][i];
    }

    env->aux_status32.register_bank = n;
}

static TCGTBCPUState arc_get_tb_cpu_state(CPUState *cs)
{
    CPUARCState *env = cpu_env(cs);
    uint32_t flags = 0;

    if (env->aux_status32.user_mode) {
        flags |= ARC_TBFLAG_USER_MODE;
    }

    if (env->aux_status32.disable_alignment_checking) {
        flags |= ARC_TBFLAG_UNALIGNED_LDST;
    }

    /*
     * TB which starts with a delay slot will have a different
     * execution path.
     */
    if (env->aux_status32.delay_slot_pending) {
        flags |= ARC_TBFLAG_DELAY_SLOT;
    }

#ifdef TARGET_ARCV2
    if (!env->aux_status32.disable_zol) {
        flags |= ARC_TBFLAG_ZOL_ENABLED;
    }
#endif

    return (TCGTBCPUState){ .pc = env->pc, .flags = flags };
}

static void arc_cpu_synchronize_from_tb(CPUState *cs,
                                        const TranslationBlock *tb)
{
    CPUARCState *env = cpu_env(cs);

    env->pc = tb->pc;
    env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(env->pc);
}

static void arc_restore_state_to_opc(CPUState *cs,
                                     const TranslationBlock *tb,
                                     const uint64_t *data)
{
    CPUARCState *env = cpu_env(cs);

    env->pc = data[0];
    env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(env->pc);
}

#ifndef CONFIG_USER_ONLY
static bool arc_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}
#endif

static int arc_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    CPUARCState *env = cpu_env(cs);

    return env->aux_status32.user_mode;
}

#ifndef CONFIG_USER_ONLY
/*
 * TCG calls it for an access which crosses a page boundary. The
 * target must adjust it for the case when the address wraps around
 * the end of the address space. Addresses of 32-bit cores
 * are 32-bit wide, so the result wraps at 4 GiB. HS6x has 64-bit
 * addresses and the 64-bit result is correct as it is.
 */
static vaddr arc_cpu_pointer_wrap(CPUState *cs, int mmu_idx,
                                  vaddr result, vaddr base)
{
#ifdef TARGET_ARCV3_64
    return result;
#else
    return (uint32_t)result;
#endif
}
#endif

static void arc_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    ARCCPUClass *acc = ARC_CPU_GET_CLASS(obj);
    CPUARCState *env = cpu_env(cs);
    ARCCPU *cpu = env_archcpu(env);

    if (acc->parent_phases.hold) {
        acc->parent_phases.hold(obj, type);
    }

    memset(env, 0, offsetof(CPUARCState, end_reset_fields));

    env->pc = 0;
    env->aux_status32.register_bank = 0;
    env->gpr[ARC_REGNUM_PCL] = 0;

    env->aux_int_vector_base = FIELD_EX32(cpu->aux_vecbase_ac_build, AUX_VECBASE_AC_BUILD, ADDR);
    env->aux_int_vector_base <<= ARC_INT_VECTOR_BASE_ALIGNMENT_BITS;

#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    env->aux_hw_pf_ctrl = 0xAA;
#endif

    for (int i = ARC_FIRST_INTERRUPT_NR; i <= ARC_LAST_INTERRUPT_NR; i++) {
        env->aux_irq_bank[i].enable = 1;
    }

#ifdef CONFIG_USER_ONLY
    /*
     * User mode emulation runs the guest in the user privilege level.
     * Like the Linux kernel, start with ZOL inhibited (cleared by LP) and
     * with unaligned memory accesses enabled.
     */
    env->aux_status32.user_mode = 1;
    env->aux_status32.disable_zol = 1;
    env->aux_status32.disable_alignment_checking = 1;
#else
    arc_timers_reset(cpu);
#endif
}

static ObjectClass *arc_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    oc = object_class_by_name(cpu_model);
    if (oc != NULL && object_class_dynamic_cast(oc, TYPE_ARC_CPU) != NULL) {
        return oc;
    }
    typename = g_strdup_printf(ARC_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    return oc;
}

static void arc_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    ARCCPU *cpu = ARC_CPU(dev);
    ARCCPUClass *acc = ARC_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    arc_cpu_register_gdb_regs_for_features(cs);

    qemu_init_vcpu(cs);

    /* Initial number for all cores is 0x0. It must be adjusted in hw/arc. */
    cpu->aux_identity = FIELD_DP32(cpu->aux_identity, AUX_IDENTITY, ARCNUM, 0x0);

    if (arc_cpu_is_hs(cpu)) {
        cpu->aux_identity = FIELD_DP32(cpu->aux_identity, AUX_IDENTITY, ARCVER, ARC_AUX_IDENTITY_VERSION_HS);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MINOR_REV, 0x2);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MAJOR_REV, 0x3);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, FAMILY, ARC_AUX_MICRO_ARCH_BUILD_FAMILY_HS);
    } else if (arc_cpu_is_em(cpu)) {
        cpu->aux_identity = FIELD_DP32(cpu->aux_identity, AUX_IDENTITY, ARCVER, ARC_AUX_IDENTITY_VERSION_EM);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MINOR_REV, 0x0);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MAJOR_REV, 0x5);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, FAMILY, ARC_AUX_MICRO_ARCH_BUILD_FAMILY_EM);
    } else if (arc_cpu_is_hs5x(cpu)) {
        cpu->aux_identity = FIELD_DP32(cpu->aux_identity, AUX_IDENTITY, ARCVER, ARC_AUX_IDENTITY_VERSION_HS5X);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MINOR_REV, 0x0);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MAJOR_REV, 0x0);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, FAMILY, ARC_AUX_MICRO_ARCH_BUILD_FAMILY_HS5X);
    } else if (arc_cpu_is_hs6x(cpu)) {
        cpu->aux_identity = FIELD_DP32(cpu->aux_identity, AUX_IDENTITY, ARCVER, ARC_AUX_IDENTITY_VERSION_HS6X);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MINOR_REV, 0x0);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, MAJOR_REV, 0x0);
        cpu->aux_micro_arch_build = FIELD_DP32(cpu->aux_micro_arch_build, AUX_MICRO_ARCH_BUILD, FAMILY, ARC_AUX_MICRO_ARCH_BUILD_FAMILY_HS6X);
    } else {
        g_assert_not_reached();
    }

    cpu->aux_bcr_ver = 0x3;
    cpu->aux_bta_link_build = 0x0;

    /* TODO: Add an option for a default intc base */
    cpu->aux_vecbase_ac_build = FIELD_DP32(cpu->aux_vecbase_ac_build, AUX_VECBASE_AC_BUILD, CONFIG, 0x0);
    cpu->aux_vecbase_ac_build = FIELD_DP32(cpu->aux_vecbase_ac_build, AUX_VECBASE_AC_BUILD, VERSION, AUX_VECBASE_AC_BUILD_VERSION);
    cpu->aux_vecbase_ac_build = FIELD_DP32(cpu->aux_vecbase_ac_build, AUX_VECBASE_AC_BUILD, ADDR, 0x0);

    cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, VERSION, 0x2);
    cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, PORTS, 0x0); /* 3-ports register file*/
    cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, ENTRIES, 0x0); /* 32-entry register file */
    cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, CLEARED_ON_RESET, true);

    /* BANKS is extra banks (0–7); array holds extra+1 including the primary. */
    if (cpu->cfg.rf_banks > ARC_MAX_NR_OF_RF_BANKS - 1) {
        cpu->cfg.rf_banks = ARC_MAX_NR_OF_RF_BANKS - 1;
    }

    if (cpu->cfg.rf_banks == 0) {
        cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, BANKS, 0x0); /* No additional register banks */
        cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, DUPLICATED, 0x0); /* No duplicated registers */
    } else {
        cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, BANKS, cpu->cfg.rf_banks);
        cpu->aux_rf_build = FIELD_DP32(cpu->aux_rf_build, AUX_RF_BUILD, DUPLICATED, 0x3); /* All registers are duplicated */
    }

    cpu->aux_swap_build = 0x3; /* ARCv2/ARCv3*/
    cpu->aux_norm_build = 0x3; /* ARCv2/ARCv3*/
    cpu->aux_minmax_build = 0x2; /* ARCv2/ARCv3*/
    cpu->aux_barrel_build = 0x303; /* ARCv2/ARCv3 and all shift instructions */

    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, VERSION, 0x1); /* ARCv2 */
    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, IRQS, ARC_MAX_NR_OF_INTERRUPTS);
    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, EXTS, 128);
    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, PRIORITIES, ARC_MAX_NR_OF_PRIORITIES - 1);
    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, FIRQ, cpu->cfg.firq);
    cpu->aux_irq_build = FIELD_DP32(cpu->aux_irq_build, AUX_IRQ_BUILD, NMI, false);

#if defined(TARGET_ARCV2)
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, VERSION, 0x4); /* ARCv2 */
#elif defined(TARGET_ARCV3_32)
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, VERSION, 0x6); /* ARCv3 32-bit */
#elif defined(TARGET_ARCV3_64)
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, VERSION, 0x7); /* ARCv3 64-bit */
#endif
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, TIMER0, cpu->cfg.has_timer0);
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, TIMER1, cpu->cfg.has_timer1);
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, RTC, false);
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, PRIORITY0, 0);
    cpu->aux_timer_build = FIELD_DP32(cpu->aux_timer_build, AUX_TIMER_BUILD, PRIORITY1, 0);

#if defined(TARGET_ARCV2)
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, VERSION, 0x2); /* ARCv2 */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, PC_SIZE, 0x4); /* 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, LPC_SIZE, 0x7); /* 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, ADDR_SIZE, 0x4); /* 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, BIG_ENDIAN, false);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, ATOMIC, true);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, NON_ALIGNED, arc_cpu_is_hs(cpu));
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, LL64, true);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, CODE_DENSITY, 0x2);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, DIV_REM, 0x2);
#elif defined(TARGET_ARCV3_32)
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, VERSION, 0x3); /* ARCv3 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, PC_SIZE, 0x4); /* 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, LPC_SIZE, 0x0); /* ZOL is not supported */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, ADDR_SIZE, 0x4); /* 32-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, BIG_ENDIAN, false);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, ATOMIC, 0x1); /* LLOCK and SCOND*/
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, NON_ALIGNED, true);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, LL64, true);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, CODE_DENSITY, 0x2);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, DIV_REM, 0x2);
#elif defined(TARGET_ARCV3_64)
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, VERSION, 0x4); /* ARCv3 64-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, VA_SIZE, 0x3); /* 64-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, PA_SIZE, 0x1); /* 48-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, BIG_ENDIAN, false);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, ATOMIC, 0x1); /* LLOCK and SCOND*/
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, NON_ALIGNED, true);
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, M128, 0x2); /* -m128 is supported*/
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, CODE_DENSITY, 0x3); /* ARCv3 64-bit */
    cpu->aux_isa_config = FIELD_DP32(cpu->aux_isa_config, AUX_ISA_CONFIG, DIV_REM, 0x3); /* ARCv3 64-bit */
#else
#error "Unsupported target"
#endif

    cpu->aux_multiply_build = FIELD_DP32(cpu->aux_multiply_build, AUX_MULTIPLY_BUILD, VERSION32X32, 0x6); /* ARCv2 */
    cpu->aux_multiply_build = FIELD_DP32(cpu->aux_multiply_build, AUX_MULTIPLY_BUILD, TYPE, 0x0); /* Serial multiplier */
    cpu->aux_multiply_build = FIELD_DP32(cpu->aux_multiply_build, AUX_MULTIPLY_BUILD, CYC, 0x0); /* 1 cycle */
    cpu->aux_multiply_build = FIELD_DP32(cpu->aux_multiply_build, AUX_MULTIPLY_BUILD, DSP, 0x3); /* Full MPY: MPY_OPTION=9 */
    cpu->aux_multiply_build = FIELD_DP32(cpu->aux_multiply_build, AUX_MULTIPLY_BUILD, VERSION16X16, 0x2); /* ARCv2 */

#ifdef TARGET_ARCV2
    /* Super pages and shared pages (SASID) are not supported */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, DTLB, ARC_MMU_BUILD_DTLB_ENTRIES_8);
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, ITLB, ARC_MMU_BUILD_ITLB_ENTRIES_4);
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, JES, 0); /* 0 entries, no super pages */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, JE, 0x2); /* 1024 entries (4-way) */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, JA, 0x2); /* 4-way set associative */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, PAE, false); /* No PAE */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, CT, false); /* No CCM translation */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, DL, false); /* No dynamic loading */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, PSZ0, ARC_MMU_BUILD_PAGE_SIZE_8K);
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, PSZ1, ARC_MMU_BUILD_PAGE_SIZE_NONE);
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, SL, false); /* No SASID */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, VERSION, ARC_MMU_BUILD_VERSION_V4);
#endif

#if defined(TARGET_ARCV3_32) || defined(TARGET_ARCV3_64)
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, DTLB, 0x3); /* 16 entries */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, ITLB, 0x3); /* 16 entries */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, L2TLB, 0x3); /* 2048 entries */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, TC, 0x0); /* MMU translation cached is not available */
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, VERSION, 0x10); /* ARCv3 */
#endif

#ifdef TARGET_ARCV3_32
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, TYPE, 0x0); /* MMUv32 */
#endif

#ifdef TARGET_ARCV3_64
    if (cpu->cfg.mmu_type < 1 || cpu->cfg.mmu_type > 3) {
        error_setg(errp, "mmu-type must be 1 (V48-4K), 2 (V48-16K) "
                   "or 3 (V48-64K)");
        return;
    }
    cpu->aux_mmu_build = FIELD_DP32(cpu->aux_mmu_build, AUX_MMU_BUILD, TYPE,
                                    cpu->cfg.mmu_type);
#endif

    /*
     * Instruction cache build register
     *
     *     VERSION = 0x4       - ARCv2
     *     WAYS = 0x2          - 4-way set associative
     *     SIZE = 0x7          - 64KB
     *     BLOCK_SIZE = 0x3    - 64B
     *     FEATURE_LEVEL = 0x2 - Common for EM and HS
     *     DISABLED = 0        - Enabled on reset, valid for EM and HS
     */
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, VERSION, 0x4);
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, WAYS, 0x1);
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, SIZE, 0x7);
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, BLOCK_SIZE, 0x3);
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, FEATURE_LEVEL, 0x2);
    cpu->aux_i_cache_build = FIELD_DP32(cpu->aux_i_cache_build, AUX_I_CACHE_BUILD, DISABLED_ON_RESET, 0);

    /*
     * Data cache build register
     *
     *     VERSION = 0x4       - ARCv2 with fixed number of cycles
     *     WAYS = 0x2          - 4-way set associative
     *     SIZE = 0x7          - 64KB
     *     BLOCK_SIZE = 0x2    - 64B
     *     FEATURE_LEVEL = 0x0 - Basic cache
     *     UNCACHED = 0        - Does not include uncached regions
     *     CYCLES = 0          - Always 0 for VERSION=0x4
     */
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, VERSION, 0x4);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, WAYS, 0x1);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, SIZE, 0x7);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, BLOCK_SIZE, 0x2);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, FEATURE_LEVEL, 0);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, UNCACHED, 0);
    cpu->aux_d_cache_build = FIELD_DP32(cpu->aux_d_cache_build, AUX_D_CACHE_BUILD, CYCLES, 0);

    cpu_reset(cs);

    acc->parent_realize(dev, errp);
}

static void arc_cpu_disas_set_info(CPUState *cs, disassemble_info *info)
{
    ARCCPU *cpu = ARC_CPU(cs);

    info->endian = BFD_ENDIAN_LITTLE;

    if (arc_cpu_is_hs(cpu)) {
        info->arch = bfd_arch_arc;
        info->mach = bfd_mach_arc_arcv2hs;
    } else if (arc_cpu_is_em(cpu)) {
        info->arch = bfd_arch_arc;
        info->mach = bfd_mach_arc_arcv2em;
    } else if (arc_cpu_is_hs5x(cpu)) {
        info->arch = bfd_arch_arc64;
        info->mach = bfd_mach_arcv3_32;
    } else if (arc_cpu_is_hs6x(cpu)) {
        info->arch = bfd_arch_arc64;
        info->mach = bfd_mach_arcv3_64;
    } else {
        g_assert_not_reached();
    }

    info->print_insn = print_insn_arc;
}

static const gchar *arc_gdb_arch_name(CPUState *cs)
{
#ifdef TARGET_ARCV2
    return "arc:ARCv2";
#elif defined(TARGET_ARCV3_32)
    return "arc64:32";
#elif defined(TARGET_ARCV3_64)
    return "arc64:64";
#else
#error "Unsupported ARC target"
#endif
}

#ifdef CONFIG_USER_ONLY
static void arc_cpu_record_sigsegv(CPUState *cs, vaddr addr,
                                   MMUAccessType access_type,
                                   bool maperr, uintptr_t retaddr)
{
    CPUARCState *env = cpu_env(cs);

    if (maperr) {
        switch (access_type) {
        case MMU_INST_FETCH:
            cs->exception_index = ARC_EXCP_TLB_MISS_I;
            break;
        case MMU_DATA_LOAD:
            cs->exception_index = ARC_EXCP_TLB_MISS_D_LD;
            break;
        default:
            cs->exception_index = ARC_EXCP_TLB_MISS_D_ST;
            break;
        }
    } else {
        switch (access_type) {
        case MMU_INST_FETCH:
            cs->exception_index = ARC_EXCP_PROTV_EX;
            break;
        case MMU_DATA_LOAD:
            cs->exception_index = ARC_EXCP_PROTV_LD;
            break;
        default:
            cs->exception_index = ARC_EXCP_PROTV_ST;
            break;
        }
    }

    env->excp_mem_addr = addr;
    cpu_loop_exit_restore(cs, retaddr);
}

static void arc_cpu_record_sigbus(CPUState *cs, vaddr addr,
                                  MMUAccessType access_type,
                                  uintptr_t retaddr)
{
    CPUARCState *env = cpu_env(cs);

    env->excp_mem_addr = addr;
    cs->exception_index = ARC_EXCP_MISALIGNED_DATA;
    cpu_loop_exit_restore(cs, retaddr);
}
#else
#include "hw/core/sysemu-cpu-ops.h"

static const struct SysemuCPUOps arc_sysemu_ops = {
    .has_work = arc_cpu_has_work,
    .get_phys_page_debug = arc_cpu_get_phys_page_debug,
};
#endif

static const TCGCPUOps arc_tcg_ops = {
    .guest_default_memory_order = TCG_MO_ALL,
    .mttcg_supported = false,

    .initialize = arc_translate_init,
    .translate_code = arc_translate_code,
    .get_tb_cpu_state = arc_get_tb_cpu_state,
    .synchronize_from_tb = arc_cpu_synchronize_from_tb,
    .restore_state_to_opc = arc_restore_state_to_opc,
    .mmu_index = arc_cpu_mmu_index,
#ifndef CONFIG_USER_ONLY
    .pointer_wrap = arc_cpu_pointer_wrap,
#endif

#ifdef CONFIG_USER_ONLY
    .record_sigsegv = arc_cpu_record_sigsegv,
    .record_sigbus = arc_cpu_record_sigbus,
#else
    .tlb_fill = arc_mmu_tlb_fill,
    .cpu_exec_interrupt = arc_cpu_exec_interrupt,
    .cpu_exec_halt = arc_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
    .do_interrupt = arc_cpu_do_interrupt,
    .do_transaction_failed = arc_cpu_do_transaction_failed,
    .do_unaligned_access = arc_cpu_do_unaligned_access,
#endif
};

static const Property arc_properties[] = {
    DEFINE_PROP_BOOL("enable-exceptions", ArchCPU, cfg.enable_exceptions, true),
    DEFINE_PROP_BOOL("exit-on-halt", ArchCPU, cfg.exit_on_halt, true),
    DEFINE_PROP_UINT32("rf-banks", ArchCPU, cfg.rf_banks, 1),
    DEFINE_PROP_BOOL("firq", ArchCPU, cfg.firq, true),
    /* TODO: Implement using of has-interrupt option */
    DEFINE_PROP_BOOL("has-interrupts", ArchCPU, cfg.has_interrupts, true),
    DEFINE_PROP_BOOL("has-timer0", ArchCPU, cfg.has_timer0, true),
    DEFINE_PROP_BOOL("has-timer1", ArchCPU, cfg.has_timer1, true),
    DEFINE_PROP_UINT32("freq-hz", ArchCPU, cfg.freq_hz, 100000000),
#ifdef TARGET_ARCV3_64
    DEFINE_PROP_UINT32("mmu-type", ArchCPU, cfg.mmu_type, 1),
#endif
};

static void arc_cpu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    CPUClass *cc = CPU_CLASS(klass);
    ARCCPUClass *acc = ARC_CPU_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    device_class_set_parent_realize(dc, arc_cpu_realize,
                                    &acc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, arc_cpu_reset_hold, NULL,
                                       &acc->parent_phases);

    cc->class_by_name = arc_cpu_class_by_name;
    cc->dump_state = arc_cpu_dump_state;
    cc->set_pc = arc_cpu_set_pc;
    cc->get_pc = arc_cpu_get_pc;
#ifndef CONFIG_USER_ONLY
    cc->sysemu_ops = &arc_sysemu_ops;
#endif
    cc->disas_set_info = arc_cpu_disas_set_info;
    cc->gdb_read_register = arc_cpu_gdb_read_register;
    cc->gdb_write_register = arc_cpu_gdb_write_register;
    cc->gdb_stop_before_watchpoint = true;
    cc->gdb_arch_name = arc_gdb_arch_name;
#if defined(TARGET_ARCV2)
    cc->gdb_core_xml_file = GDB_ARCV2_REG_CORE_XML;
#elif defined(TARGET_ARCV3_32)
    cc->gdb_core_xml_file = GDB_ARCV3_32_REG_CORE_XML;
#elif defined(TARGET_ARCV3_64)
    cc->gdb_core_xml_file = GDB_ARCV3_64_REG_CORE_XML;
#else
#error "Unsupported target"
#endif
    cc->tcg_ops = &arc_tcg_ops;

    device_class_set_props(dc, arc_properties);
}

static void arc_cpu_init(Object *obj)
{
}

static const TypeInfo arc_cpu_info = {
    .name = TYPE_ARC_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(ARCCPU),
    .instance_align = __alignof(ARCCPU),
    .instance_init = arc_cpu_init,
    .abstract = true,
    .class_size = sizeof(ARCCPUClass),
    .class_init = arc_cpu_class_init,
};

#ifdef TARGET_ARCV2

static void arc_em_cpu_init(Object *obj)
{
}

static void arc_hs_cpu_init(Object *obj)
{
}

static const TypeInfo arc_em_cpu_info = {
    .name = TYPE_ARC_CPU_EM,
    .parent = TYPE_ARC_CPU,
    .instance_init = arc_em_cpu_init,
};

static const TypeInfo arc_hs4x_cpu_info = {
    .name = TYPE_ARC_CPU_HS,
    .parent = TYPE_ARC_CPU,
    .instance_init = arc_hs_cpu_init,
};

static void arc_cpu_register_types(void)
{
    type_register_static(&arc_cpu_info);
    type_register_static(&arc_hs4x_cpu_info);
    type_register_static(&arc_em_cpu_info);
}

#elif defined(TARGET_ARCV3_32)

static void arc_hs5x_cpu_init(Object *obj)
{
}

static const TypeInfo arc_hs5x_cpu_info = {
    .name = TYPE_ARC_CPU_HS5X,
    .parent = TYPE_ARC_CPU,
    .instance_init = arc_hs5x_cpu_init,
};

static void arc_cpu_register_types(void)
{
    type_register_static(&arc_cpu_info);
    type_register_static(&arc_hs5x_cpu_info);
}

#elif defined(TARGET_ARCV3_64)

static void arc_hs6x_cpu_init(Object *obj)
{
}

static const TypeInfo arc_hs6x_cpu_info = {
    .name = TYPE_ARC_CPU_HS6X,
    .parent = TYPE_ARC_CPU,
    .instance_init = arc_hs6x_cpu_init,
};

static void arc_cpu_register_types(void)
{
    type_register_static(&arc_cpu_info);
    type_register_static(&arc_hs6x_cpu_info);
}

#else
#error "Unsupported target"
#endif

type_init(arc_cpu_register_types)
